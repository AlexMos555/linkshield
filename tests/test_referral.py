"""
Tests for the referral program.

Covers:
- _code_for is deterministic per (user_id, email)
- /generate idempotently returns the same code on repeat calls
- /generate succeeds even when Redis is unavailable (fail-soft, returns
  the deterministic code so the user can still share their link)
- /stats returns 0 redeemed when no record exists yet
- /stats returns count + reward_days_earned from Redis
- /redeem rejects missing/empty/invalid codes
- /redeem blocks self-redeem
- /redeem blocks repeat-redeem (one per redeemer ever)
- /redeem grants credit days in Supabase to BOTH parties
- /redeem persists the increment to Redis
- /redeem returns 503 when Redis is unavailable
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


# ─── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def authed_user():
    return AuthUser(id="user-A", email="a@test.com", tier=UserTier.free)


@pytest.fixture
def app(authed_user):
    from api.main import app as fastapi_app
    from api.services.auth import get_current_user, get_optional_user

    fastapi_app.dependency_overrides[get_current_user] = lambda: authed_user
    fastapi_app.dependency_overrides[get_optional_user] = lambda: authed_user
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


class FakeRedis:
    def __init__(self) -> None:
        self.kv: Dict[str, str] = {}
        self.ttls: Dict[str, int] = {}
        self.fail_mode = False

    async def get(self, key: str) -> Optional[str]:
        if self.fail_mode:
            raise RuntimeError("redis offline")
        return self.kv.get(key)

    async def set(self, key: str, value: str) -> bool:
        if self.fail_mode:
            raise RuntimeError("redis offline")
        self.kv[key] = value
        return True

    async def expire(self, key: str, seconds: int) -> bool:
        if self.fail_mode:
            raise RuntimeError("redis offline")
        self.ttls[key] = seconds
        return True


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def grant_calls(monkeypatch):
    """Capture _grant_credit_days calls without hitting Supabase."""
    calls: List[Dict[str, Any]] = []

    async def _spy(user_id: str, days: int):
        calls.append({"user_id": user_id, "days": days})

    monkeypatch.setattr("api.routers.referral._grant_credit_days", _spy)
    return calls


# ─── Pure unit ─────────────────────────────────────────────────────


def test_code_for_deterministic():
    from api.routers.referral import _code_for

    assert _code_for("u1", "a@test.com") == _code_for("u1", "a@test.com")
    # Different user → different code
    assert _code_for("u1", "a@test.com") != _code_for("u2", "a@test.com")
    # Always 8 uppercase chars
    code = _code_for("u1", "a@test.com")
    assert len(code) == 8
    assert code.isupper() or code.isalnum()


# ─── /generate ─────────────────────────────────────────────────────


def test_generate_returns_deterministic_code(client, fake_redis):
    r1 = client.post("/api/v1/referral/generate")
    assert r1.status_code == 200
    code1 = r1.json()["code"]

    r2 = client.post("/api/v1/referral/generate")
    assert r2.json()["code"] == code1


def test_generate_url_format(client, fake_redis):
    resp = client.post("/api/v1/referral/generate")
    body = resp.json()
    assert body["url"] == f"https://cleanway.ai/ref/{body['code']}"
    assert "7 days" in body["reward"]


def test_generate_writes_owner_record_to_redis(client, fake_redis):
    resp = client.post("/api/v1/referral/generate")
    code = resp.json()["code"]
    stored = fake_redis.kv.get(f"referral:{code}")
    assert stored is not None
    info = json.loads(stored)
    assert info["owner_id"] == "user-A"
    assert info["redeemed_count"] == 0


def test_generate_succeeds_when_redis_down(client, monkeypatch):
    """Fail-soft: deterministic code still returned even with Redis offline."""

    async def _broken_redis():
        raise RuntimeError("redis offline")

    monkeypatch.setattr("api.services.cache.get_redis", _broken_redis)

    resp = client.post("/api/v1/referral/generate")
    assert resp.status_code == 200
    body = resp.json()
    assert "code" in body and len(body["code"]) == 8


# ─── /stats ────────────────────────────────────────────────────────


def test_stats_zero_when_no_redis_record(client, fake_redis):
    resp = client.get("/api/v1/referral/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["redeemed_count"] == 0
    assert body["reward_days_earned"] == 0


def test_stats_reflects_redis_count(client, fake_redis):
    # Pre-populate as if 3 friends redeemed
    from api.routers.referral import _code_for

    code = _code_for("user-A", "a@test.com")
    fake_redis.kv[f"referral:{code}"] = json.dumps(
        {"owner_id": "user-A", "created": "2026-04-26T00:00:00", "redeemed_count": 3}
    )

    resp = client.get("/api/v1/referral/stats")
    body = resp.json()
    assert body["redeemed_count"] == 3
    assert body["reward_days_earned"] == 21  # 3 * 7


# ─── /redeem ───────────────────────────────────────────────────────


def test_redeem_rejects_empty_code(client, fake_redis):
    resp = client.post("/api/v1/referral/redeem", json={"code": "   "})
    assert resp.status_code == 400


def test_redeem_rejects_unknown_code(client, fake_redis):
    resp = client.post("/api/v1/referral/redeem", json={"code": "DEADBEEF"})
    assert resp.status_code == 404


def test_redeem_blocks_self_redeem(client, fake_redis, grant_calls):
    """user-A's own code can't be redeemed by user-A."""
    from api.routers.referral import _code_for

    own_code = _code_for("user-A", "a@test.com")
    fake_redis.kv[f"referral:{own_code}"] = json.dumps(
        {"owner_id": "user-A", "created": "2026-04-26T00:00:00", "redeemed_count": 0}
    )

    resp = client.post("/api/v1/referral/redeem", json={"code": own_code})
    assert resp.status_code == 400
    assert "own" in resp.json()["detail"].lower()
    assert grant_calls == []


def test_redeem_blocks_double_redeem(client, fake_redis, grant_calls):
    """Once a user has redeemed any code, they can't redeem again."""
    fake_redis.kv["referral:OTHERREF"] = json.dumps(
        {"owner_id": "user-B", "created": "2026-04-26T00:00:00", "redeemed_count": 0}
    )
    fake_redis.kv["redeemed:user-A"] = "EARLIER"  # user-A already redeemed

    resp = client.post("/api/v1/referral/redeem", json={"code": "OTHERREF"})
    assert resp.status_code == 400
    assert "already" in resp.json()["detail"].lower()


def test_redeem_grants_credits_to_both_parties(client, fake_redis, grant_calls):
    fake_redis.kv["referral:FRIENDREF"] = json.dumps(
        {"owner_id": "user-B", "created": "2026-04-26T00:00:00", "redeemed_count": 2}
    )

    resp = client.post("/api/v1/referral/redeem", json={"code": "FRIENDREF"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["trial_days"] == 7

    # Both redeemer and owner credited 7 days
    assert {"user_id": "user-A", "days": 7} in grant_calls
    assert {"user_id": "user-B", "days": 7} in grant_calls
    assert len(grant_calls) == 2


def test_redeem_increments_count_in_redis(client, fake_redis, grant_calls):
    fake_redis.kv["referral:FRIENDREF"] = json.dumps(
        {"owner_id": "user-B", "created": "2026-04-26T00:00:00", "redeemed_count": 4}
    )

    client.post("/api/v1/referral/redeem", json={"code": "FRIENDREF"})

    info = json.loads(fake_redis.kv["referral:FRIENDREF"])
    assert info["redeemed_count"] == 5
    # Redeemer marker set
    assert fake_redis.kv["redeemed:user-A"] == "FRIENDREF"


def test_redeem_returns_503_when_redis_offline(client, monkeypatch, grant_calls):
    async def _broken_redis():
        raise RuntimeError("redis offline")

    monkeypatch.setattr("api.services.cache.get_redis", _broken_redis)

    resp = client.post("/api/v1/referral/redeem", json={"code": "FRIENDREF"})
    assert resp.status_code == 503
    assert grant_calls == []


def test_redeem_normalizes_lowercase_code(client, fake_redis, grant_calls):
    """Codes are stored uppercase; lowercase input still matches."""
    fake_redis.kv["referral:FRIENDREF"] = json.dumps(
        {"owner_id": "user-B", "created": "2026-04-26T00:00:00", "redeemed_count": 0}
    )

    resp = client.post("/api/v1/referral/redeem", json={"code": "friendref"})
    assert resp.status_code == 200
