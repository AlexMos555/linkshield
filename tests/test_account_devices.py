"""Account devices + entitlement endpoints (api/routers/account.py).

Requests go through the REAL auth dependency with signed test JWTs, so the
"unlinked device is refused everywhere" gate in api/services/auth.py is
exercised end to end, not mocked away.
"""
from __future__ import annotations

import time
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient

ACCOUNT = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
PHONE = "phone-install-0001-aaaa"
TABLET = "tablet-install-0002-bbb"
LAPTOP = "laptop-install-0003-ccc"
FOURTH = "fourth-install-0004-ddd"


def _token(sub: str = ACCOUNT, session_id: str | None = None) -> str:
    from api.config import get_settings

    payload = {
        "sub": sub,
        "email": "person@example.com",
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
        "session_id": session_id or str(uuid.uuid4()),
    }
    return jwt.encode(payload, get_settings().supabase_jwt_secret, algorithm="HS256")


def _headers(device: str | None = None, sub: str = ACCOUNT, session_id: str | None = None) -> dict:
    h = {"Authorization": f"Bearer {_token(sub, session_id)}"}
    if device:
        h["X-Device-Id"] = device
    return h


@pytest.fixture
def client(fake_redis, account_store, monkeypatch):
    from api.main import app
    from api.services import rate_limiter

    # rate_limiter imported get_redis by name; point it at the same fake so
    # the per-user buckets are per test (and no real Redis is touched).
    async def _fake():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _fake)
    return TestClient(app)


def _register(client, device: str, platform: str = "android", name: str | None = "Pixel 8",
              sub: str = ACCOUNT, session_id: str | None = None):
    body = {"device_id": device, "platform": platform, "app_version": "1.0.4"}
    if name is not None:
        body["name"] = name
    return client.post("/api/v1/me/devices", json=body,
                       headers=_headers(device, sub, session_id))


# ─── register / heartbeat ─────────────────────────────────────────


def test_first_registration_creates_then_heartbeat_updates(client, account_store):
    session = str(uuid.uuid4())
    first = _register(client, PHONE, session_id=session)
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["status"] == "created"
    assert body["device"]["platform"] == "android"
    assert body["device"]["name"] == "Pixel 8"
    assert body["device"]["is_current"] is True
    assert body["entitlement"]["devices_used"] == 1
    # The Auth session is stored so unlinking can end it.
    assert account_store.devices[0]["session_id"] == session

    again = _register(client, PHONE, name="Something else")
    assert again.status_code == 200
    assert again.json()["status"] == "updated"
    # A heartbeat never overwrites the name (renames are explicit).
    assert again.json()["device"]["name"] == "Pixel 8"
    assert len(account_store.devices) == 1


def test_free_account_links_two_devices_then_gets_device_limit_reached(client, account_store):
    assert _register(client, PHONE).status_code == 201
    assert _register(client, TABLET, platform="ios", name="iPad").status_code == 201

    third = _register(client, LAPTOP, platform="extension", name="Chrome on Windows")
    assert third.status_code == 409
    detail = third.json()["detail"]
    assert detail["code"] == "device_limit_reached"
    assert detail["device_limit"] == 2 and detail["devices_used"] == 2
    assert detail["plan"] == "free"
    # The linked devices come along so the app can offer "unlink one".
    assert {d["name"] for d in detail["devices"]} == {"Pixel 8", "iPad"}
    assert all("device_hash" not in d for d in detail["devices"])
    assert len(account_store.devices) == 2


def test_paid_plan_covers_three_devices(client, account_store):
    account_store.add_entitlement(ACCOUNT, plan="personal", device_limit=3)
    for device in (PHONE, TABLET, LAPTOP):
        assert _register(client, device).status_code == 201
    fourth = _register(client, FOURTH)
    assert fourth.status_code == 409
    assert fourth.json()["detail"]["device_limit"] == 3


def test_bought_extras_raise_the_limit(client, account_store):
    account_store.add_entitlement(ACCOUNT, device_limit=4)
    for device in (PHONE, TABLET, LAPTOP, FOURTH):
        assert _register(client, device).status_code == 201


def test_registration_uses_the_entitlement_limit(client, account_store):
    account_store.add_entitlement(ACCOUNT, source="operator_ru", external_id="op-7", device_limit=3)
    _register(client, PHONE)
    assert account_store.register_calls[-1]["device_limit"] == 3


def test_linked_device_keeps_working_after_the_plan_lapses(client, account_store):
    row = account_store.add_entitlement(ACCOUNT, device_limit=3)
    for device in (PHONE, TABLET, LAPTOP):
        _register(client, device)
    row["status"] = "cancelled"  # back to free: limit 2, three linked

    assert _register(client, LAPTOP).status_code == 200  # heartbeat passes
    assert _register(client, FOURTH).status_code == 409  # but no new device


@pytest.mark.parametrize("body", [
    {"device_id": "short", "platform": "android"},
    {"device_id": "has spaces in it!!!!", "platform": "android"},
    {"device_id": PHONE, "platform": "toaster"},
    {"device_id": PHONE},
])
def test_register_validates_input(client, body):
    resp = client.post("/api/v1/me/devices", json=body, headers=_headers())
    assert resp.status_code == 422


def test_device_name_is_cleaned(client, account_store):
    _register(client, PHONE, name="  Pixel\n8\x00 Pro  ")
    assert account_store.devices[0]["name"] == "Pixel 8 Pro"


def test_register_requires_sign_in(client):
    resp = client.post("/api/v1/me/devices", json={"device_id": PHONE, "platform": "android"})
    assert resp.status_code == 401


# ─── entitlement view ─────────────────────────────────────────────


def test_entitlement_for_a_free_account(client):
    resp = client.get("/api/v1/me/entitlement", headers=_headers())
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "plan": "free",
        "status": "free",
        "source": None,
        "manage_url": None,
        "period_end": None,
        "device_limit": 2,
        "included_devices": 3,
        "devices_used": 0,
        "devices": [],
    }


def test_entitlement_for_a_paid_account_marks_this_device(client, account_store):
    account_store.add_entitlement(ACCOUNT, plan="family", status="trialing",
                                  period_end="2099-01-01T00:00:00+00:00")
    _register(client, PHONE)
    _register(client, LAPTOP, platform="extension", name="Firefox on Linux")

    resp = client.get("/api/v1/me/entitlement", headers=_headers(LAPTOP))
    body = resp.json()
    assert body["plan"] == "family" and body["status"] == "trialing"
    assert body["source"] == "stripe" and body["period_end"].startswith("2099-01-01")
    assert body["manage_url"] == "https://cleanway.ai/account"
    assert body["device_limit"] == 3 and body["devices_used"] == 2
    current = [d for d in body["devices"] if d["is_current"]]
    assert [d["name"] for d in current] == ["Firefox on Linux"]
    for d in body["devices"]:
        assert set(d) == {"id", "platform", "name", "app_version", "created_at",
                          "last_seen_at", "is_current"}


def test_list_devices(client):
    _register(client, PHONE)
    resp = client.get("/api/v1/me/devices", headers=_headers(PHONE))
    assert resp.status_code == 200
    assert [d["is_current"] for d in resp.json()] == [True]


def test_account_reads_do_not_spend_the_daily_check_quota(client, fake_redis):
    client.get("/api/v1/me/entitlement", headers=_headers())
    assert not [k for k in fake_redis._kv if k.startswith("rate:daily:")]
    assert [k for k in fake_redis._kv if k.startswith("rate:sensitive:account_read:")]


def test_store_outage_is_503_not_free(client, account_store):
    account_store.fail = True
    resp = client.get("/api/v1/me/entitlement", headers=_headers())
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "account_unavailable"
    assert _register(client, PHONE).status_code == 503


def test_unconfigured_database_is_503(client):
    from api.services import account_store as store_module

    store_module.set_account_store(None)  # back to "configured" — and it isn't
    resp = client.post(
        "/api/v1/me/devices", json={"device_id": PHONE, "platform": "android"}, headers=_headers()
    )
    assert resp.status_code == 503


# ─── unlink ───────────────────────────────────────────────────────


def _device_id(account_store, install: str) -> str:
    return next(d["id"] for d in account_store.devices if d["device_hash"] == install)


def test_unlink_frees_the_seat_and_refuses_the_device_everywhere(client, account_store):
    _register(client, PHONE)
    _register(client, TABLET)
    assert _register(client, LAPTOP).status_code == 409

    resp = client.delete(f"/api/v1/me/devices/{_device_id(account_store, TABLET)}",
                         headers=_headers(PHONE))
    assert resp.status_code == 200, resp.text
    assert resp.json()["devices_used"] == 1

    # The freed seat is usable at once.
    assert _register(client, LAPTOP).status_code == 201

    # The unlinked install is refused on ANY authenticated endpoint …
    refused = client.get("/api/v1/me/entitlement", headers=_headers(TABLET))
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "device_revoked"
    refused = client.get("/api/v1/user/settings", headers=_headers(TABLET))
    assert refused.status_code == 403
    # … and can't re-register under the same install id.
    again = _register(client, TABLET)
    assert again.status_code == 403
    assert again.json()["detail"]["code"] == "device_revoked"

    # Other devices of the account are untouched.
    assert client.get("/api/v1/me/entitlement", headers=_headers(PHONE)).status_code == 200


def test_revoked_device_is_refused_at_heartbeat_even_without_the_redis_marker(
    client, account_store, fake_redis
):
    _register(client, PHONE)
    client.delete(f"/api/v1/me/devices/{_device_id(account_store, PHONE)}", headers=_headers())
    fake_redis._kv.clear()  # Redis lost the marker
    resp = _register(client, PHONE)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "device_revoked"
    # … and the marker is written back.
    assert client.get("/api/v1/me/devices", headers=_headers(PHONE)).status_code == 403


def test_unlink_is_idempotent(client, account_store):
    _register(client, PHONE)
    target = _device_id(account_store, PHONE)
    assert client.delete(f"/api/v1/me/devices/{target}", headers=_headers()).status_code == 200
    assert client.delete(f"/api/v1/me/devices/{target}", headers=_headers()).status_code == 200


def test_cannot_unlink_someone_elses_device(client, account_store):
    _register(client, PHONE, sub=OTHER)
    target = _device_id(account_store, PHONE)
    resp = client.delete(f"/api/v1/me/devices/{target}", headers=_headers())
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "device_not_found"
    assert account_store.devices[0]["revoked_at"] is None


def test_unlink_with_a_malformed_id_is_404(client):
    resp = client.delete("/api/v1/me/devices/not-a-uuid", headers=_headers())
    assert resp.status_code == 404


def test_unlink_writes_an_audit_row(client, account_store, monkeypatch):
    calls = []

    async def _write(**kw):
        calls.append(kw)

    monkeypatch.setattr("api.services.audit_log.write", _write)
    _register(client, PHONE)
    client.delete(f"/api/v1/me/devices/{_device_id(account_store, PHONE)}", headers=_headers())
    assert calls and calls[0]["action"] == "device.unlinked"
    assert calls[0]["actor_user_id"] == ACCOUNT


# ─── rename ───────────────────────────────────────────────────────


def test_rename(client, account_store):
    _register(client, PHONE)
    target = _device_id(account_store, PHONE)
    resp = client.patch(f"/api/v1/me/devices/{target}", json={"name": "Mum's phone"},
                        headers=_headers(PHONE))
    assert resp.status_code == 200
    assert resp.json()["name"] == "Mum's phone" and resp.json()["is_current"] is True


def test_rename_rejects_blank_names_and_foreign_devices(client, account_store):
    _register(client, PHONE)
    target = _device_id(account_store, PHONE)
    blank = client.patch(f"/api/v1/me/devices/{target}", json={"name": " \n "}, headers=_headers())
    assert blank.status_code == 422
    foreign = client.patch(f"/api/v1/me/devices/{target}", json={"name": "x"},
                           headers=_headers(sub=OTHER))
    assert foreign.status_code == 404


# ─── legacy POST /api/v1/user/device ──────────────────────────────


def test_legacy_device_route_goes_through_the_limit(client, account_store):
    for i, platform in enumerate(("chrome", "android")):
        resp = client.post("/api/v1/user/device",
                           json={"device_hash": f"legacy-install-000{i}xx", "platform": platform},
                           headers=_headers())
        assert resp.status_code == 200, resp.text
    assert {d["platform"] for d in account_store.devices} == {"extension", "android"}
    resp = client.post("/api/v1/user/device",
                       json={"device_hash": "legacy-install-0009xx", "platform": "ios"},
                       headers=_headers())
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "device_limit_reached"


# ─── auth gate details ────────────────────────────────────────────


def test_revocation_check_fails_open_when_redis_is_down(redis_down):
    import asyncio

    from api.services.account_devices import is_revoked

    assert asyncio.run(is_revoked(ACCOUNT, PHONE)) is False


def test_session_id_claim_reaches_the_auth_user(fake_redis):
    import asyncio

    from api.services.auth import _decode_jwt_and_resolve

    session = str(uuid.uuid4())
    user = asyncio.run(_decode_jwt_and_resolve(f"Bearer {_token(session_id=session)}"))
    assert user.session_id == session
