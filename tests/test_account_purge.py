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
  - a user who restores mid-purge is never purged: each candidate is
    re-read right before anything irreversible, and only the rows the
    conditional DELETE actually removed count as deleted
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest


class _SupabaseStub:
    def __init__(self) -> None:
        self.list_response: List[Dict[str, Any]] = []
        self.list_status = 200
        # Users whose deletion was cleared after the listing (restore).
        self.restored: set = set()
        self.recheck_status = 200
        # DELETE users answers with the rows it removed (return=representation).
        self.delete_status = 200
        # Supabase Auth admin API (DELETE /auth/v1/admin/users/{id}).
        self.auth_delete_status = 200
        # subscriptions rows by user_id — the purge cancels live Stripe
        # billing before anything is deleted.
        self.subscription_rows: Dict[str, Dict[str, Any]] = {}
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

            def _live(self):
                return [r for r in stub.list_response if r["id"] not in stub.restored]

            async def get(self, url, params=None, headers=None, **_kw):
                stub.requests.append(
                    {"method": "GET", "url": url, "params": dict(params or {})}
                )
                if "/rest/v1/subscriptions" in url:
                    uid = dict(params or {}).get("user_id", "eq.")[3:]
                    row = stub.subscription_rows.get(uid)
                    return _Resp(200, [row] if row else [])
                uid = dict(params or {}).get("id", "")
                if uid.startswith("eq."):
                    rows = [r for r in self._live() if r["id"] == uid[3:]]
                    return _Resp(stub.recheck_status, rows)
                return _Resp(stub.list_status, stub.list_response)

            async def request(self, method, url, params=None, headers=None, **_kw):
                stub.requests.append(
                    {"method": method, "url": url, "params": dict(params or {}),
                     "headers": dict(headers or {})}
                )
                if "/auth/v1/admin/users/" in url:
                    return _Resp(stub.auth_delete_status, {})
                if method == "DELETE" and url.endswith("/rest/v1/users"):
                    wanted = dict(params or {}).get("id", "in.()")[4:-1].split(",")
                    return _Resp(stub.delete_status, [r for r in self._live() if r["id"] in wanted])
                return _Resp(204)

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

    Sequence: GET (list) → per user: GET subscriptions row (stop Stripe
    billing first), PATCH audit_log (anonymise, GDPR Art. 17), DELETE the
    Supabase Auth user → one DELETE on public.users (cascade through FKs).
    """
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-a"}, {"id": "user-b"}]

    result = await purge_expired_accounts()

    assert result["deleted"] == 2
    assert set(result["ids"]) == {"user-a", "user-b"}

    def kind(r):
        url = r["url"]
        if "/auth/v1/admin/users/" in url:
            return f"{r['method']} auth:{url.rsplit('/', 1)[1]}"
        return f"{r['method']} {url.split('/rest/v1/')[1]}"

    assert [kind(r) for r in supabase_stub.requests] == [
        "GET users",
        "GET users", "GET subscriptions", "PATCH audit_log", "DELETE auth:user-a",
        "GET users", "GET subscriptions", "PATCH audit_log", "DELETE auth:user-b",
        "DELETE users",
    ]


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
        r for r in supabase_stub.requests
        if r["method"] == "DELETE" and r["url"].endswith("/rest/v1/users")
    )
    # Only the users that cleared every pre-delete step are deleted…
    assert delete_call["params"]["id"] == "in.(user-c)"
    # …and still only while they're past the grace window.
    raw = delete_call["params"]["deletion_requested_at"]
    assert raw.startswith("lte."), raw
    # The exact cutoff value matches the GET's cutoff (computed once
    # at the top of purge_expired_accounts).
    list_cutoff = next(
        r for r in supabase_stub.requests if r["method"] == "GET"
    )["params"]["deletion_requested_at"]
    # The rows it removed come back, so only those are reported as purged.
    assert delete_call["headers"]["Prefer"] == "return=representation"
    assert delete_call["params"]["select"] == "id"
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


@pytest.mark.asyncio
async def test_purge_drops_the_users_redis_keys(supabase_ok, supabase_stub, monkeypatch):
    """The trusted-sites whitelist lives in Redis with a 1-year TTL; it must
    go with the account, not a year later."""
    from api.services import account_purge

    deleted: list = []

    class _R:
        async def delete(self, *keys):
            deleted.extend(keys)
            return len(keys)

    async def _get_redis():
        return _R()

    monkeypatch.setattr("api.services.cache.get_redis", _get_redis)
    supabase_stub.list_response = [{"id": "u1"}, {"id": "u2"}]

    result = await account_purge.purge_expired_accounts()

    assert result["deleted"] == 2
    for uid in ("u1", "u2"):
        assert f"whitelist:{uid}" in deleted
        assert f"percentile:{uid}" in deleted
        assert f"tier:{uid}" in deleted


@pytest.mark.asyncio
async def test_purge_survives_redis_outage(supabase_ok, supabase_stub, monkeypatch):
    from api.services import account_purge

    async def _down():
        raise ConnectionError("redis down")

    monkeypatch.setattr("api.services.cache.get_redis", _down)
    supabase_stub.list_response = [{"id": "u1"}]

    result = await account_purge.purge_expired_accounts()
    assert result["deleted"] == 1


# ─── auth.users + Stripe ──────────────────────────────────────
#
# public.users.id has no FK to auth.users, so deleting the app row left
# the Supabase Auth identity (email, provider ids, sessions) behind
# forever — and the person could still sign in. The purge now deletes
# the auth user through the Admin API, and refuses to delete anyone
# whose Stripe billing it could not stop.


@pytest.mark.asyncio
async def test_purge_deletes_the_supabase_auth_user(supabase_ok, supabase_stub):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-auth"}]
    result = await purge_expired_accounts()

    assert result["deleted"] == 1
    auth_deletes = [
        r for r in supabase_stub.requests
        if r["method"] == "DELETE" and "/auth/v1/admin/users/" in r["url"]
    ]
    assert [r["url"] for r in auth_deletes] == [
        "https://fake.supabase.co/auth/v1/admin/users/user-auth"
    ]


@pytest.mark.asyncio
async def test_auth_user_already_gone_counts_as_deleted(supabase_ok, supabase_stub):
    """A previous run deleted the auth user, then the public delete
    failed. The retry gets 404 from the Admin API — that's done, not an
    error."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-404"}]
    supabase_stub.auth_delete_status = 404
    result = await purge_expired_accounts()

    assert result["deleted"] == 1
    assert result["ids"] == ["user-404"]


@pytest.mark.asyncio
async def test_auth_delete_failure_keeps_user_for_next_run(supabase_ok, supabase_stub):
    """If the auth identity can't be deleted, keep the public row too —
    it's the only thing that makes the user a candidate again next run."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-stuck"}]
    supabase_stub.auth_delete_status = 500
    result = await purge_expired_accounts()

    assert result["deleted"] == 0
    assert result["skipped"] == ["user-stuck"]
    assert not any(
        r["method"] == "DELETE" and r["url"].endswith("/rest/v1/users")
        for r in supabase_stub.requests
    )


@pytest.mark.asyncio
async def test_purge_cancels_live_stripe_billing_first(supabase_ok, supabase_stub, fake_stripe):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-pay"}]
    supabase_stub.subscription_rows["user-pay"] = {
        "user_id": "user-pay", "tier": "personal", "status": "active",
        "provider": "stripe", "provider_subscription_id": "sub_pay",
        "stripe_customer_id": "cus_pay", "trial_used_at": None,
    }
    fake_stripe.add_subscription("sub_pay", "cus_pay", status="active")

    result = await purge_expired_accounts()

    assert result["deleted"] == 1
    assert [c[0] for c in fake_stripe.cancel_calls] == ["sub_pay"]


@pytest.mark.asyncio
async def test_purge_skips_user_when_stripe_cancel_fails(supabase_ok, supabase_stub, fake_stripe):
    """Deleting the row would lose the only link to the Stripe customer
    and the subscription would bill forever. Skip, retry next run."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-pay"}, {"id": "user-free"}]
    supabase_stub.subscription_rows["user-pay"] = {
        "user_id": "user-pay", "tier": "personal", "status": "active",
        "provider": "stripe", "provider_subscription_id": "sub_pay",
        "stripe_customer_id": "cus_pay", "trial_used_at": None,
    }
    fake_stripe.add_subscription("sub_pay", "cus_pay", status="active")
    fake_stripe.fail_cancel = True

    result = await purge_expired_accounts()

    assert result["ids"] == ["user-free"]
    assert result["skipped"] == ["user-pay"]
    assert not any(
        "/auth/v1/admin/users/user-pay" in r["url"] for r in supabase_stub.requests
    )
    users_delete = next(
        r for r in supabase_stub.requests
        if r["method"] == "DELETE" and r["url"].endswith("/rest/v1/users")
    )
    assert users_delete["params"]["id"] == "in.(user-free)"


# ─── Restored mid-purge ────────────────────────────────────────
#
# The listing and the final DELETE are seconds apart, and in between the
# purge does things that cannot be undone (cancel Stripe, anonymise the
# audit trail, delete the Supabase Auth identity). A user who restores in
# that window must come out of it with their account intact.


def _calls_for(stub, uid):
    return [r for r in stub.requests if uid in r["url"] or uid in str(r["params"])]


@pytest.mark.asyncio
async def test_a_user_restored_after_the_listing_is_not_touched(supabase_ok, supabase_stub, fake_stripe):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-gone"}, {"id": "user-back"}]
    supabase_stub.subscription_rows["user-back"] = {
        "user_id": "user-back", "tier": "personal", "status": "active",
        "provider": "stripe", "provider_subscription_id": "sub_back",
        "stripe_customer_id": "cus_back", "trial_used_at": None,
    }
    fake_stripe.add_subscription("sub_back", "cus_back", status="active")
    supabase_stub.restored.add("user-back")

    result = await purge_expired_accounts()

    assert result == {"deleted": 1, "ids": ["user-gone"], "restored": ["user-back"]}
    # Re-read only: no Stripe cancel, no audit anonymising, no auth delete.
    assert [(r["method"], r["url"].rsplit("/", 1)[1], r["params"].get("id"))
            for r in _calls_for(supabase_stub, "user-back")] == [("GET", "users", "eq.user-back")]
    assert fake_stripe.cancel_calls == []
    users_delete = next(r for r in supabase_stub.requests
                        if r["method"] == "DELETE" and r["url"].endswith("/rest/v1/users"))
    assert users_delete["params"]["id"] == "in.(user-gone)"
    assert [row["target_id"] for row in supabase_stub.audit_posts] == ["user-gone"]


@pytest.mark.asyncio
async def test_everyone_restored_means_no_delete_at_all(supabase_ok, supabase_stub):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-back"}]
    supabase_stub.restored.add("user-back")

    result = await purge_expired_accounts()

    assert result == {"deleted": 0, "ids": [], "restored": ["user-back"]}
    assert [r["method"] for r in supabase_stub.requests] == ["GET", "GET"]
    assert supabase_stub.audit_posts == []


@pytest.mark.asyncio
async def test_a_failed_recheck_keeps_the_user_for_the_next_run(supabase_ok, supabase_stub):
    """Can't confirm the deletion still stands → do nothing irreversible."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-x"}]
    supabase_stub.recheck_status = 503

    result = await purge_expired_accounts()

    assert result == {"deleted": 0, "ids": [], "skipped": ["user-x"]}
    assert [r["method"] for r in supabase_stub.requests] == ["GET", "GET"]


@pytest.mark.asyncio
async def test_the_recheck_is_pinned_to_the_same_cutoff(supabase_ok, supabase_stub):
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "user-c"}]
    await purge_expired_accounts()

    listing, recheck = [r for r in supabase_stub.requests if r["method"] == "GET" and r["url"].endswith("/users")]
    assert recheck["params"]["id"] == "eq.user-c"
    assert recheck["params"]["deletion_requested_at"] == listing["params"]["deletion_requested_at"]


@pytest.mark.asyncio
async def test_only_rows_the_delete_removed_count_as_purged(supabase_ok, supabase_stub, monkeypatch, caplog):
    """A restore that lands after the re-read but before the DELETE: the
    DELETE's own deletion_requested_at filter skips the row, and the purge
    reports (and audits, and clears Redis for) only what was removed."""
    import logging

    import httpx as _httpx

    from api.services import account_purge

    supabase_stub.list_response = [{"id": "u1"}, {"id": "u2"}]
    dropped: list = []

    class _R:
        async def delete(self, *keys):
            dropped.extend(keys)
            return len(keys)

    async def _get_redis():
        return _R()

    monkeypatch.setattr("api.services.cache.get_redis", _get_redis)
    client_cls = supabase_stub.build()
    real_request = client_cls.request

    async def request(self, method, url, params=None, headers=None, **kw):
        if method == "DELETE" and url.endswith("/rest/v1/users"):
            supabase_stub.restored.add("u2")
        return await real_request(self, method, url, params=params, headers=headers, **kw)

    client_cls.request = request
    monkeypatch.setattr(_httpx, "AsyncClient", client_cls)

    with caplog.at_level(logging.ERROR, logger="cleanway.account_purge"):
        result = await account_purge.purge_expired_accounts()

    assert result == {"deleted": 1, "ids": ["u1"], "restored": ["u2"]}
    assert [row["target_id"] for row in supabase_stub.audit_posts] == ["u1"]
    assert dropped and not any("u2" in k for k in dropped)
    (alert,) = [r for r in caplog.records if r.getMessage() == "account_purge.restored_during_delete"]
    assert alert.user_ids == ["u2"]


@pytest.mark.asyncio
async def test_a_delete_answer_without_rows_claims_nothing(supabase_ok, supabase_stub):
    """A 2xx that doesn't list the removed rows can't prove anything was purged."""
    from api.services.account_purge import purge_expired_accounts

    supabase_stub.list_response = [{"id": "u1"}]
    supabase_stub.delete_status = 204

    result = await purge_expired_accounts()

    assert result["deleted"] == 0 and result["error"] == "delete_failed_204"
    assert supabase_stub.audit_posts == []
