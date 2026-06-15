"""Tests for the periodic GDPR purge — closes the loop on Art. 17.

The DELETE /api/v1/user/account endpoint marks a soft-delete via
users.deletion_requested_at. The actual hard purge happens in this
module on a cron (hourly is fine since grace is 30 days). Tested:

  - cutoff is computed from `now() - 30d` (matches Privacy Policy)
  - candidates are queried with deletion_requested_at <= cutoff
  - hard DELETE issued with the same filter
  - returns the list of IDs deleted (audit trail)
  - no candidates → no-op (idempotent)
  - upstream failure → no rows claimed deleted, error surfaced
  - misconfigured Supabase → no-op + warning
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest


class _SupabaseStub:
    def __init__(self) -> None:
        self.list_response: List[Dict[str, Any]] = []
        self.list_status = 200
        self.delete_status = 204
        self.requests: List[Dict[str, Any]] = []
        # audit_log writes go through .post(); kept separate so existing
        # assertions on .requests (GET+DELETE only) stay correct after
        # the purge job started emitting audit rows.
        self.audit_posts: List[Dict[str, Any]] = []

    def build(self):
        stub = self

        class _Resp:
            def __init__(self, status: int, body: Any = None):
                self.status_code = status
                self._body = body if body is not None else []

            def json(self):
                return self._body

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None, **_kw):
                stub.requests.append(
                    {"method": "GET", "url": url, "params": dict(params or {})}
                )
                return _Resp(stub.list_status, stub.list_response)

            async def request(self, method, url, params=None, headers=None, **_kw):
                stub.requests.append(
                    {"method": method, "url": url, "params": dict(params or {})}
                )
                return _Resp(stub.delete_status)

            async def post(self, url, json=None, headers=None, **_kw):
                if "/rest/v1/audit_log" in url:
                    stub.audit_posts.append(json or {})
                return _Resp(201)

        return _Client


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def supabase_stub(monkeypatch):
    import httpx as _httpx

    stub = _SupabaseStub()
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())
    return stub


# ─── Happy path ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purges_expired_accounts(supabase_ok, supabase_stub):
    """Two candidates past the grace window → both hard-deleted, IDs
    returned in the summary.

    Method sequence is GET (list) → PATCH × N (anonymise audit_log per
    user, GDPR Art. 17) → DELETE (cascade through FKs).
    """
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-a"}, {"id": "user-b"}]

    result = await purge_expired_accounts()

    assert result["deleted"] == 2
    assert set(result["ids"]) == {"user-a", "user-b"}
    methods = [r["method"] for r in supabase_stub.requests]
    # GET, PATCH (user-a), PATCH (user-b), DELETE
    assert methods == ["GET", "PATCH", "PATCH", "DELETE"]


@pytest.mark.asyncio
async def test_anonymises_audit_log_before_user_delete(supabase_ok, supabase_stub):
    """Audit log rows where actor_user_id = deleted user must have the
    actor nulled BEFORE the user row is wiped. Otherwise the audit
    table would carry the deleted user's UUID indefinitely with no
    FK to enforce cascade. (Audit MEDIUM "audit_log table has no
    retention policy or row cap, and the GDPR purge cron is not
    wired to clean it".)"""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-x"}]
    await purge_expired_accounts()

    # The PATCH carries the right filter + body.
    patches = [r for r in supabase_stub.requests if r["method"] == "PATCH"]
    assert len(patches) == 1
    assert "/rest/v1/audit_log" in patches[0]["url"]
    assert patches[0]["params"]["actor_user_id"] == "eq.user-x"


@pytest.mark.asyncio
async def test_delete_filter_params_pin_grace_window(
    supabase_ok, supabase_stub
):
    """The DELETE call MUST carry the same deletion_requested_at <= cutoff
    filter as the listing GET — otherwise a misconfigured cron could
    wipe accounts that haven't yet finished the 30-day grace.

    (Audit MEDIUM "account_purge DELETE filter params never asserted:
    wrong-cutoff regression would go undetected".)"""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-c"}]
    await purge_expired_accounts()

    delete_call = next(
        r for r in supabase_stub.requests if r["method"] == "DELETE"
    )
    assert delete_call["url"].endswith("/rest/v1/users"), delete_call["url"]
    raw = delete_call["params"]["deletion_requested_at"]
    assert raw.startswith("lte."), raw
    # The exact cutoff value matches the GET's cutoff (computed once
    # at the top of purge_expired_accounts).
    list_cutoff = next(
        r for r in supabase_stub.requests if r["method"] == "GET"
    )["params"]["deletion_requested_at"]
    assert raw == list_cutoff, (
        "DELETE cutoff drifted from GET cutoff — a misconfigured cron "
        "could now wipe users still inside their grace window."
    )


@pytest.mark.asyncio
async def test_cutoff_is_30_days_ago(supabase_ok, supabase_stub):
    """Grace window matches the Privacy Policy commitment exactly."""
    from api.services.account_purge import GRACE_DAYS, purge_expired_accounts

    assert GRACE_DAYS == 30
    supabase_stub.list_response = []

    await purge_expired_accounts()

    list_params = supabase_stub.requests[0]["params"]
    raw = list_params["deletion_requested_at"]
    assert raw.startswith("lte."), raw
    cutoff_iso = raw[len("lte."):]
    cutoff = datetime.fromisoformat(cutoff_iso)
    age_days = (datetime.now(timezone.utc) - cutoff).total_seconds() / 86400
    # Should be ~30 days. Allow a few seconds of test runtime jitter.
    assert 29.99 < age_days < 30.01, f"cutoff {age_days} days ago"


# ─── No-op paths ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_candidates_no_op(supabase_ok, supabase_stub):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = []
    result = await purge_expired_accounts()

    assert result == {"deleted": 0}
    # No DELETE issued — only the listing GET fired.
    methods = [r["method"] for r in supabase_stub.requests]
    assert methods == ["GET"]


@pytest.mark.asyncio
async def test_supabase_unconfigured(monkeypatch):
    """If env vars are absent the script must NOT crash a cron — it
    should log + return a no-op summary."""
    from api import config
    from api.services.account_purge import purge_expired_accounts

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)

    result = await purge_expired_accounts()
    assert result == {"deleted": 0, "skipped": "supabase_not_configured"}


# ─── Failure paths ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_failure_returns_error(supabase_ok, supabase_stub):
    """Upstream returns 503 on the list query → no DELETE issued, error
    surfaced in the summary."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_status = 503

    result = await purge_expired_accounts()

    assert result["deleted"] == 0
    assert "error" in result
    # No DELETE was attempted.
    methods = [r["method"] for r in supabase_stub.requests]
    assert "DELETE" not in methods


@pytest.mark.asyncio
async def test_delete_failure_surfaces_candidate_ids(supabase_ok, supabase_stub):
    """List works (candidates known), DELETE fails → return the IDs
    that SHOULD have been deleted so the operator can investigate.
    Without this we'd lose the audit trail for the failed batch."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-x"}]
    supabase_stub.delete_status = 502

    result = await purge_expired_accounts()

    assert result["deleted"] == 0
    assert "error" in result
    assert result["candidates"] == ["user-x"]


@pytest.mark.asyncio
async def test_purge_writes_audit_row_per_deleted_user(supabase_ok, supabase_stub):
    """Compliance: every account.hard_deleted must leave an audit_log
    row. The user row is gone forever after the DELETE — the audit
    trail is what a reviewer reaches for to answer 'did we honour the
    SAR / deletion request?' post-fact."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "u1"}, {"id": "u2"}, {"id": "u3"}]

    result = await purge_expired_accounts()
    assert result["deleted"] == 3

    # One audit row per deleted user, all flagged as account.hard_deleted.
    actions = [row.get("action") for row in supabase_stub.audit_posts]
    assert actions == ["account.hard_deleted"] * 3
    target_ids = {row["target_id"] for row in supabase_stub.audit_posts}
    assert target_ids == {"u1", "u2", "u3"}
    # actor_user_id is NULL — this is a system-cron event, not a human.
    assert all(row.get("actor_user_id") is None for row in supabase_stub.audit_posts)
