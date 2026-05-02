"""
Tests for /api/v1/family — Family Hub E2E alert plumbing.

The server is BLIND to alert content. These tests assert:

  Auth boundaries:
    - Non-members can't read keys, list members, list alerts, submit alerts
    - Non-owners can't create invites
    - Self-redeeming your own invite is rejected
    - Wrong PIN returns the same 404 as wrong code (no enumeration)

  Happy path:
    - Create family → caller becomes owner
    - Register key persists 32-byte curve25519 pubkey, base64url encoded
    - List members surfaces public keys per user
    - Owner creates invite → returns code+PIN ONCE; only hashes persisted
    - Member redeems code+PIN → joins family
    - Submit alerts → ciphertext+nonce+sender_pubkey stored as raw bytes
    - List alerts returns only the recipient's own envelopes

  Validation:
    - Public key must decode to exactly 32 bytes
    - Nonce must decode to exactly 24 bytes (xchacha20-poly1305)
    - PIN must be exactly 4 digits
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, List, Optional
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


# ─── Common fixtures ───────────────────────────────────────────────


@pytest.fixture
def authed_user():
    return AuthUser(id="user-A", email="a@test.com", tier=UserTier.free)


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "service-key-test", raising=False)
    return settings


def _make_app(authed: AuthUser):
    from api.main import app as fastapi_app
    from api.services.auth import get_current_user, get_optional_user

    fastapi_app.dependency_overrides[get_current_user] = lambda: authed
    fastapi_app.dependency_overrides[get_optional_user] = lambda: authed
    return fastapi_app


@pytest.fixture
def client_factory():
    """Build a TestClient bound to a specific user identity."""
    from api.main import app as fastapi_app

    def _build(user: AuthUser) -> TestClient:
        _make_app(user)
        return TestClient(fastapi_app)

    yield _build
    fastapi_app.dependency_overrides.clear()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _hex_to_b64(hex_with_prefix: str) -> str:
    raw = bytes.fromhex(hex_with_prefix.removeprefix("\\x"))
    return _b64(raw)


# ─── In-memory FakeSupabase modelling all the tables we touch ──────


class FakeSupabase:
    def __init__(self) -> None:
        self.families: Dict[str, Dict[str, Any]] = {}
        self.members: List[Dict[str, Any]] = []
        self.keys: Dict[str, Dict[str, Any]] = {}  # key: f"{family_id}:{user_id}"
        self.invites: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []

    def build(self):
        fake = self

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        def _filter(rows: List[dict], params: Optional[dict]) -> List[dict]:
            if not params:
                return rows
            out = list(rows)
            for k, v in (params or {}).items():
                if not isinstance(v, str):
                    continue
                if v.startswith("eq."):
                    val = v[3:]
                    out = [r for r in out if str(r.get(k)) == val]
                elif v.startswith("in.("):
                    # PostgREST `in.(a,b,c)` — comma-separated list of values
                    inner = v[len("in."):].strip("()")
                    allowed = {item.strip() for item in inner.split(",") if item.strip()}
                    out = [r for r in out if str(r.get(k)) in allowed]
                elif v == "is.null":
                    out = [r for r in out if r.get(k) is None]
            return out

        class _MockClient:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def request(self, method, url, params=None, json=None, headers=None):
                # Route on URL suffix
                if url.endswith("/families"):
                    if method == "POST":
                        body = json if isinstance(json, dict) else (json[0] if json else {})
                        new_id = str(uuid4())
                        row = {"id": new_id, "owner_id": body["owner_id"], "name": body.get("name", "My Family")}
                        fake.families[new_id] = row
                        return _Resp(201, [row])
                    if method == "GET":
                        # /family/mine queries here with ?id=in.(...) — list lookup.
                        return _Resp(200, _filter(list(fake.families.values()), params))
                if url.endswith("/family_members"):
                    if method == "GET":
                        return _Resp(200, _filter(fake.members, params))
                    if method == "POST":
                        rows = json if isinstance(json, list) else [json]
                        for row in rows:
                            existing = [
                                m for m in fake.members
                                if m["family_id"] == row["family_id"] and m["user_id"] == row["user_id"]
                            ]
                            if not existing:
                                fake.members.append({**row, "joined_at": "2026-04-28T00:00:00+00:00"})
                        return _Resp(201, [])
                if url.endswith("/family_member_keys"):
                    if method == "GET":
                        rows = list(fake.keys.values())
                        return _Resp(200, _filter(rows, params))
                    if method == "POST":
                        body = json if isinstance(json, dict) else json[0]
                        key = f"{body['family_id']}:{body['user_id']}"
                        fake.keys[key] = {
                            "family_id": body["family_id"],
                            "user_id": body["user_id"],
                            "public_key": body["public_key"],
                            "key_version": body.get("key_version", 1),
                        }
                        return _Resp(201, [])
                if url.endswith("/family_invites"):
                    if method == "POST":
                        body = json if isinstance(json, dict) else json[0]
                        new_id = str(uuid4())
                        row = {**body, "id": new_id, "redeemed_at": None}
                        fake.invites[new_id] = row
                        return _Resp(201, [row])
                    if method == "GET":
                        rows = list(fake.invites.values())
                        return _Resp(200, _filter(rows, params))
                    if method == "PATCH":
                        target_id = (params or {}).get("id", "").removeprefix("eq.")
                        if target_id in fake.invites:
                            fake.invites[target_id].update(json or {})
                        return _Resp(204, "")
                if url.endswith("/family_alerts"):
                    if method == "POST":
                        rows = json if isinstance(json, list) else [json]
                        for r in rows:
                            stored = {**r, "id": str(uuid4()), "created_at": "2026-04-28T00:00:00+00:00"}
                            fake.alerts.append(stored)
                        return _Resp(201, [])
                    if method == "GET":
                        return _Resp(200, _filter(fake.alerts, params))
                return _Resp(404, [])

        return _MockClient


@pytest.fixture
def fake_sb(monkeypatch):
    import httpx as _httpx

    fake = FakeSupabase()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


# ─── /family/mine GET ─────────────────────────────────────────────


def test_mine_returns_empty_when_no_membership(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    resp = client.get("/api/v1/family/mine")
    assert resp.status_code == 200
    assert resp.json() == {"families": []}


def test_mine_returns_families_with_role_and_count(supabase_ok, fake_sb, client_factory):
    """user-A is owner of fam-1 (3 members) and member of fam-2 (2 members)."""
    fake_sb.families["fam-1"] = {"id": "fam-1", "owner_id": "user-A", "name": "Smiths"}
    fake_sb.families["fam-2"] = {"id": "fam-2", "owner_id": "user-X", "name": "Joneses"}
    fake_sb.members.append({"family_id": "fam-1", "user_id": "user-A", "role": "owner"})
    fake_sb.members.append({"family_id": "fam-1", "user_id": "user-B", "role": "member"})
    fake_sb.members.append({"family_id": "fam-1", "user_id": "user-C", "role": "member"})
    fake_sb.members.append({"family_id": "fam-2", "user_id": "user-X", "role": "owner"})
    fake_sb.members.append({"family_id": "fam-2", "user_id": "user-A", "role": "member"})

    a = AuthUser(id="user-A", email="a@t.com", tier=UserTier.free)
    resp = client_factory(a).get("/api/v1/family/mine")
    assert resp.status_code == 200
    body = resp.json()
    by_id = {f["family_id"]: f for f in body["families"]}
    assert len(by_id) == 2
    assert by_id["fam-1"]["role"] == "owner"
    assert by_id["fam-1"]["name"] == "Smiths"
    assert by_id["fam-1"]["member_count"] == 3
    assert by_id["fam-2"]["role"] == "member"
    assert by_id["fam-2"]["name"] == "Joneses"
    assert by_id["fam-2"]["member_count"] == 2


# ─── /family POST (create) ────────────────────────────────────────


def test_create_family_makes_caller_owner(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    resp = client.post("/api/v1/family", json={"name": "Smiths"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "Smiths"
    fid = body["family_id"]
    assert fid in fake_sb.families
    assert fake_sb.families[fid]["owner_id"] == "user-A"
    # Owner row created in family_members
    owners = [m for m in fake_sb.members if m["family_id"] == fid and m["role"] == "owner"]
    assert len(owners) == 1


def test_create_family_503_when_supabase_missing(authed_user, monkeypatch, client_factory):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    client = client_factory(authed_user)
    resp = client.post("/api/v1/family", json={})
    assert resp.status_code == 503


# ─── /family/{id}/keys (register pubkey) ──────────────────────────


def test_register_key_persists_curve25519(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]

    pub = bytes(range(32))  # 32-byte fixture
    resp = client.post(
        f"/api/v1/family/{fid}/keys",
        json={"public_key_b64": _b64(pub), "key_version": 1},
    )
    assert resp.status_code == 200, resp.text
    stored = fake_sb.keys[f"{fid}:user-A"]
    # Stored as \x-prefixed hex per Supabase BYTEA convention
    assert stored["public_key"] == "\\x" + pub.hex()
    assert stored["key_version"] == 1


def test_register_key_rejects_wrong_length(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]

    short = bytes(31)
    resp = client.post(
        f"/api/v1/family/{fid}/keys",
        json={"public_key_b64": _b64(short)},
    )
    assert resp.status_code == 422


def test_register_key_blocks_non_member(authed_user, supabase_ok, fake_sb, client_factory):
    """user-B can't register a key in user-A's family."""
    other = AuthUser(id="user-B", email="b@test.com", tier=UserTier.free)
    fake_sb.families["fam-foreign"] = {"id": "fam-foreign", "owner_id": "user-A", "name": "S"}
    fake_sb.members.append({"family_id": "fam-foreign", "user_id": "user-A", "role": "owner"})

    client = client_factory(other)
    resp = client.post(
        "/api/v1/family/fam-foreign/keys",
        json={"public_key_b64": _b64(bytes(32))},
    )
    assert resp.status_code == 403


# ─── /family/{id}/members ─────────────────────────────────────────


def test_list_members_returns_pubkeys(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]
    pub = bytes([42] * 32)
    client.post(
        f"/api/v1/family/{fid}/keys",
        json={"public_key_b64": _b64(pub)},
    )

    resp = client.get(f"/api/v1/family/{fid}/members")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["members"]) == 1
    m = body["members"][0]
    assert m["user_id"] == "user-A"
    assert m["role"] == "owner"
    assert m["public_key_b64"] == _b64(pub)


def test_list_members_blocks_non_member(authed_user, supabase_ok, fake_sb, client_factory):
    other = AuthUser(id="user-B", email="b@test.com", tier=UserTier.free)
    fake_sb.families["fam"] = {"id": "fam", "owner_id": "user-A", "name": "S"}
    fake_sb.members.append({"family_id": "fam", "user_id": "user-A", "role": "owner"})

    client = client_factory(other)
    resp = client.get("/api/v1/family/fam/members")
    assert resp.status_code == 403


# ─── /family/{id}/invite (owner-only) ─────────────────────────────


def test_owner_creates_invite_with_one_time_code_and_pin(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]

    resp = client.post(f"/api/v1/family/{fid}/invite")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["code"], str) and len(body["code"]) >= 6
    assert body["pin"].isdigit() and len(body["pin"]) == 4
    # Server only stored hashes, never the raw values
    invite = next(iter(fake_sb.invites.values()))
    assert invite["invite_code_hash"] == hashlib.sha256(body["code"].encode()).hexdigest()
    assert "pin" not in invite  # raw PIN never persisted
    assert invite["pin_hash"].startswith("$2b$")  # bcrypt prefix


def test_member_cannot_create_invite(authed_user, supabase_ok, fake_sb, client_factory):
    """Owner role required; plain members get 403."""
    fake_sb.families["fam"] = {"id": "fam", "owner_id": "user-X", "name": "S"}
    fake_sb.members.append({"family_id": "fam", "user_id": "user-A", "role": "member"})

    client = client_factory(authed_user)
    resp = client.post("/api/v1/family/fam/invite")
    assert resp.status_code == 403


# ─── /family/accept ───────────────────────────────────────────────


def test_accept_invite_joins_family(authed_user, supabase_ok, fake_sb, client_factory):
    # User-X creates family + invite
    inviter = AuthUser(id="user-X", email="x@t.com", tier=UserTier.free)
    inviter_client = client_factory(inviter)
    fid = inviter_client.post("/api/v1/family", json={"name": "F"}).json()["family_id"]
    invite_resp = inviter_client.post(f"/api/v1/family/{fid}/invite").json()

    # User-A accepts
    acceptor = client_factory(authed_user)
    resp = acceptor.post(
        "/api/v1/family/accept",
        json={"code": invite_resp["code"], "pin": invite_resp["pin"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["family_id"] == fid
    assert body["role"] == "member"
    # Joined
    members = [m for m in fake_sb.members if m["family_id"] == fid and m["user_id"] == "user-A"]
    assert len(members) == 1
    # Invite marked redeemed
    invite = next(iter(fake_sb.invites.values()))
    assert invite["redeemed_at"] is not None
    assert invite["redeemed_by_user_id"] == "user-A"


def test_accept_self_invite_blocked(supabase_ok, fake_sb, client_factory):
    inviter = AuthUser(id="user-X", email="x@t.com", tier=UserTier.free)
    client = client_factory(inviter)
    fid = client.post("/api/v1/family", json={"name": "F"}).json()["family_id"]
    invite = client.post(f"/api/v1/family/{fid}/invite").json()

    resp = client.post(
        "/api/v1/family/accept",
        json={"code": invite["code"], "pin": invite["pin"]},
    )
    assert resp.status_code == 400


def test_accept_wrong_pin_returns_404_not_403(authed_user, supabase_ok, fake_sb, client_factory):
    """Same error as wrong code — no enumeration of valid codes via PIN check."""
    inviter = AuthUser(id="user-X", email="x@t.com", tier=UserTier.free)
    client_factory(inviter).post("/api/v1/family", json={"name": "F"}).json()
    fid = list(fake_sb.families.keys())[0]
    invite = client_factory(inviter).post(f"/api/v1/family/{fid}/invite").json()

    resp = client_factory(authed_user).post(
        "/api/v1/family/accept",
        json={"code": invite["code"], "pin": "0000"},  # wrong
    )
    assert resp.status_code == 404


def test_accept_invalid_code_returns_404(authed_user, supabase_ok, fake_sb, client_factory):
    resp = client_factory(authed_user).post(
        "/api/v1/family/accept",
        json={"code": "DEADBEEFXYZ", "pin": "1234"},
    )
    assert resp.status_code == 404


# ─── /family/{id}/alerts (submit + list) ─────────────────────────


def test_submit_alerts_stores_ciphertext(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]

    ct = bytes([1, 2, 3, 4, 5])
    nonce = bytes(range(24))  # xchacha nonce length
    spk = bytes([7] * 32)

    resp = client.post(
        f"/api/v1/family/{fid}/alerts",
        json={
            "envelopes": [
                {
                    "recipient_user_id": "user-A",
                    "ciphertext_b64": _b64(ct),
                    "nonce_b64": _b64(nonce),
                    "sender_pubkey_b64": _b64(spk),
                    "alert_type": "block",
                }
            ]
        },
    )
    assert resp.status_code == 200
    assert resp.json()["accepted"] == 1
    stored = fake_sb.alerts[0]
    assert stored["sender_user_id"] == "user-A"
    assert stored["recipient_user_id"] == "user-A"
    assert stored["alert_type"] == "block"
    # Bytes round-trip exactly
    assert stored["encrypted_payload"] == "\\x" + ct.hex()
    assert stored["nonce"] == "\\x" + nonce.hex()


def test_submit_alerts_rejects_wrong_nonce_length(authed_user, supabase_ok, fake_sb, client_factory):
    client = client_factory(authed_user)
    fid = client.post("/api/v1/family", json={"name": "S"}).json()["family_id"]
    resp = client.post(
        f"/api/v1/family/{fid}/alerts",
        json={
            "envelopes": [
                {
                    "recipient_user_id": "user-A",
                    "ciphertext_b64": _b64(b"x"),
                    "nonce_b64": _b64(bytes(8)),  # too short
                    "sender_pubkey_b64": _b64(bytes(32)),
                }
            ]
        },
    )
    assert resp.status_code == 422


def test_submit_alerts_blocks_non_member(authed_user, supabase_ok, fake_sb, client_factory):
    other = AuthUser(id="user-B", email="b@t.com", tier=UserTier.free)
    fake_sb.families["fam"] = {"id": "fam", "owner_id": "user-X", "name": "F"}
    fake_sb.members.append({"family_id": "fam", "user_id": "user-X", "role": "owner"})

    resp = client_factory(other).post(
        "/api/v1/family/fam/alerts",
        json={
            "envelopes": [
                {
                    "recipient_user_id": "user-X",
                    "ciphertext_b64": _b64(b"x"),
                    "nonce_b64": _b64(bytes(24)),
                    "sender_pubkey_b64": _b64(bytes(32)),
                }
            ]
        },
    )
    assert resp.status_code == 403


def test_list_alerts_returns_only_caller_envelopes(supabase_ok, fake_sb, client_factory):
    """user-A and user-B both in family; user-A only sees alerts addressed to user-A."""
    fake_sb.families["fam"] = {"id": "fam", "owner_id": "user-A", "name": "F"}
    fake_sb.members.append({"family_id": "fam", "user_id": "user-A", "role": "owner"})
    fake_sb.members.append({"family_id": "fam", "user_id": "user-B", "role": "member"})

    # Pre-populate two alerts: one for A, one for B
    fake_sb.alerts.append(
        {
            "id": "alert-a",
            "family_id": "fam",
            "recipient_user_id": "user-A",
            "sender_user_id": "user-B",
            "encrypted_payload": "\\x" + b"hi-a".hex(),
            "nonce": "\\x" + bytes(24).hex(),
            "sender_pubkey": "\\x" + bytes(32).hex(),
            "alert_type": "block",
            "created_at": "2026-04-28T00:00:00+00:00",
        }
    )
    fake_sb.alerts.append(
        {
            "id": "alert-b",
            "family_id": "fam",
            "recipient_user_id": "user-B",
            "sender_user_id": "user-A",
            "encrypted_payload": "\\x" + b"hi-b".hex(),
            "nonce": "\\x" + bytes(24).hex(),
            "sender_pubkey": "\\x" + bytes(32).hex(),
            "alert_type": "block",
            "created_at": "2026-04-28T00:00:01+00:00",
        }
    )

    a = AuthUser(id="user-A", email="a@t.com", tier=UserTier.free)
    resp = client_factory(a).get("/api/v1/family/fam/alerts")
    assert resp.status_code == 200
    items = resp.json()["alerts"]
    assert len(items) == 1
    assert items[0]["id"] == "alert-a"
    assert items[0]["ciphertext_b64"] == _b64(b"hi-a")
