"""`python -m api.services.export --user <uuid|email>` — the operator's way to
answer an access request that arrives by email (docs/runbooks/data-requests.md).

Supabase is tests/supabase_rest_stub.FakeSupabase: the account lookup and
every table read are recorded, so the tests pin that the export is the same
one the person downloads, scoped to the one account found. Redis is the
shared FakeRedis (tests/conftest.py): the whitelist and the referral records
live there, not in a table.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from api.routers.referral import referral_code
from api.services import export
from tests.supabase_rest_stub import FakeSupabase

ACCOUNT = "55555555-5555-4555-8555-555555555555"
EMAIL = "person@example.com"

# What GET /auth/v1/admin/users/{id} answers, with the fields a GoTrue
# version may add that are secrets, not data about the person.
AUTH_RECORD = {
    "id": ACCOUNT,
    "aud": "authenticated",
    "role": "authenticated",
    "email": EMAIL,
    "phone": "",
    "email_confirmed_at": "2026-09-01T10:00:05Z",
    "confirmed_at": "2026-09-01T10:00:05Z",
    "last_sign_in_at": "2026-10-20T08:30:00Z",
    "created_at": "2026-09-01T10:00:00Z",
    "updated_at": "2026-10-20T08:30:00Z",
    "app_metadata": {"provider": "email", "providers": ["email"]},
    "user_metadata": {"locale": "ru"},
    "identities": [
        {
            "identity_id": "11111111-1111-4111-8111-111111111111",
            "id": ACCOUNT,
            "user_id": ACCOUNT,
            "identity_data": {"email": EMAIL, "sub": ACCOUNT, "email_verified": True},
            "provider": "email",
            "last_sign_in_at": "2026-10-20T08:30:00Z",
            "created_at": "2026-09-01T10:00:00Z",
            "updated_at": "2026-10-20T08:30:00Z",
            "access_token": "leak-me-not",
        }
    ],
    "factors": [{"id": "f-1", "factor_type": "totp", "secret": "JBSWY3DPEHPK3PXP"}],
    "encrypted_password": "$2a$10$abcdefghijklmnopqrstuv",
    "confirmation_token": "leak-me-not",
    "recovery_token": "leak-me-not",
}


@pytest.fixture
def sb(monkeypatch, fake_redis) -> FakeSupabase:
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


def _lookups(sb: FakeSupabase) -> list[dict]:
    return [c for c in sb.to("GET", "/rest/v1/users") if c["params"].get("select") == "id,email"]


def test_export_by_email_finds_the_account_and_prints_its_export(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])
    sb.on("GET", f"/auth/v1/admin/users/{ACCOUNT}", body=AUTH_RECORD)

    assert export.main(["--user", "  Person@Example.com "]) == 0

    (lookup,) = _lookups(sb)
    assert lookup["params"]["email"] == "eq.person@example.com"
    body = json.loads(capsys.readouterr().out)
    assert body["user_id"] == ACCOUNT and body["email"] == "person@example.com"
    assert set(body["tables"]) == {key for key, *_ in export.EXPORT_TABLES}
    reads = [c for c in sb.calls if c["params"].get("limit") == str(export.EXPORT_ROW_CAP)]
    assert len(reads) == len(export.EXPORT_TABLES)
    for c in reads:
        assert [v for v in c["params"].values() if v.startswith("eq.")] == [f"eq.{ACCOUNT}"]


def test_export_by_account_id_writes_a_file(sb, tmp_path, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])
    sb.on("GET", "/rest/v1/audit_log", status=500)
    out = tmp_path / "export.json"

    assert export.main(["--user", ACCOUNT.upper(), "--out", str(out)]) == 0

    (lookup,) = _lookups(sb)
    assert lookup["params"]["id"] == f"eq.{ACCOUNT}"
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["tables"]["audit_log"] == {"error": "upstream returned 500"}
    err = capsys.readouterr().err
    assert "audit_log" in err and str(out) in err


# ─── Outside the tables: Supabase Auth and Redis ─────────────────


def test_export_includes_the_auth_record_without_its_secrets(sb, capsys):
    """Sign-up and sign-in times and how the person signs in are data about
    them; password hashes, tokens and MFA secrets are not — an allow-list,
    so a field a later GoTrue adds stays out until someone looks at it."""
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])
    sb.on("GET", f"/auth/v1/admin/users/{ACCOUNT}", body=AUTH_RECORD)

    assert export.main(["--user", ACCOUNT]) == 0

    (read,) = sb.to("GET", "/auth/v1/admin/users/")
    assert read["url"].endswith(f"/auth/v1/admin/users/{ACCOUNT}")
    auth_user = json.loads(capsys.readouterr().out)["auth_user"]
    assert auth_user == {
        "email": EMAIL,
        "phone": "",
        "created_at": "2026-09-01T10:00:00Z",
        "confirmed_at": "2026-09-01T10:00:05Z",
        "email_confirmed_at": "2026-09-01T10:00:05Z",
        "phone_confirmed_at": None,
        "last_sign_in_at": "2026-10-20T08:30:00Z",
        "updated_at": "2026-10-20T08:30:00Z",
        "user_metadata": {"locale": "ru"},
        "identities": [
            {
                "provider": "email",
                "created_at": "2026-09-01T10:00:00Z",
                "last_sign_in_at": "2026-10-20T08:30:00Z",
                "updated_at": "2026-10-20T08:30:00Z",
            }
        ],
    }
    for secret in ("leak-me-not", "$2a$", "JBSWY3DPEHPK3PXP"):
        assert secret not in json.dumps(auth_user)


def test_export_includes_the_whitelist_and_referral_records_from_redis(sb, fake_redis, capsys):
    code = referral_code(ACCOUNT, EMAIL)
    asyncio.run(fake_redis.sadd(f"whitelist:{ACCOUNT}", "bank.example", "aunt-blog.example"))
    record = {"owner_id": ACCOUNT, "created": "2026-09-02T00:00:00+00:00", "redeemed_count": 2}
    asyncio.run(fake_redis.set(f"referral:{code}", json.dumps(record)))
    asyncio.run(fake_redis.set(f"redeemed:{ACCOUNT}", "FRIEND42"))
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])

    assert export.main(["--user", EMAIL]) == 0

    body = json.loads(capsys.readouterr().out)
    assert body["whitelist"] == ["aunt-blog.example", "bank.example"]
    assert body["referral"] == {"code": code, "record": record, "redeemed_code": "FRIEND42"}


def test_nothing_in_redis_is_an_empty_answer_not_an_error(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])

    assert export.main(["--user", ACCOUNT]) == 0

    body = json.loads(capsys.readouterr().out)
    assert body["whitelist"] == []
    assert body["referral"] == {"code": referral_code(ACCOUNT, EMAIL), "record": None, "redeemed_code": None}


def test_redis_and_auth_failures_are_flagged_never_shown_as_empty(sb, monkeypatch, tmp_path, capsys):
    async def _down():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr("api.services.cache.get_redis", _down)
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])
    sb.on("GET", "/auth/v1/admin/users/", status=500)
    out = tmp_path / "export.json"

    assert export.main(["--user", ACCOUNT, "--out", str(out)]) == 0

    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["whitelist"] == {"error": "ConnectionError"}
    assert body["referral"] == {"error": "ConnectionError"}
    assert body["auth_user"] == {"error": "upstream returned 500"}
    # The operator is told what to read again before answering the request.
    err = capsys.readouterr().err
    for part in ("whitelist", "referral", "auth_user"):
        assert part in err


def test_an_auth_record_that_is_gone_is_null_not_an_error(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT, "email": EMAIL}])
    sb.on("GET", "/auth/v1/admin/users/", status=404, body={"msg": "User not found"})

    assert export.main(["--user", ACCOUNT]) == 0

    assert json.loads(capsys.readouterr().out)["auth_user"] is None


def test_no_such_account_exits_1_and_reads_nothing_else(sb, capsys):
    sb.on("GET", "/rest/v1/users", body=[])
    assert export.main(["--user", "nobody@example.com"]) == 1
    assert "no account" in capsys.readouterr().err
    assert len(sb.calls) == 1


@pytest.mark.parametrize("identifier", ["not-an-id", "12345", ""])
def test_neither_an_id_nor_an_email_exits_2_without_a_query(sb, identifier, capsys):
    assert export.main(["--user", identifier]) == 2
    assert sb.calls == []
    assert "uuid" in capsys.readouterr().err


@pytest.mark.parametrize("failure", [{"status": 503}, {"exc": httpx.ConnectError("down")}])
def test_lookup_failure_exits_2(sb, failure, capsys):
    sb.on("GET", "/rest/v1/users", **failure)
    assert export.main(["--user", ACCOUNT]) == 2
    assert "lookup" in capsys.readouterr().err


def test_two_rows_for_one_lookup_is_no_answer(sb):
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT}, {"id": "other"}])
    assert export.main(["--user", ACCOUNT]) == 1


def test_without_a_database_exits_2(monkeypatch, capsys):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    assert export.main(["--user", ACCOUNT]) == 2
    assert "not configured" in capsys.readouterr().err
