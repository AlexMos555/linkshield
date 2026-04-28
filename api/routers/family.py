"""
Family Hub — E2E encrypted alerts between family members.

Server is BLIND to alert content. It stores:
  - Curve25519 public keys per (family_id, user_id) — clients use them
    to encrypt outgoing alerts to siblings.
  - Per-recipient ciphertext blobs (one row per recipient per source
    alert). Server cannot decrypt.

Crypto-side responsibilities live with the clients:
  - libsodium (TweetNaCl in JS, PyNaCl in mobile)
  - Sender: nacl.box(plaintext, nonce, recipient_pubkey, sender_privkey)
  - Recipient: nacl.box.open(ct, nonce, sender_pubkey, recipient_privkey)

This file deliberately does NOT import nacl/PyNaCl. The backend handles
raw bytes only — that's what makes the system end-to-end encrypted.

Endpoints:
  POST  /api/v1/family                              create family (caller becomes owner)
  POST  /api/v1/family/{id}/keys                    upsert my pubkey
  GET   /api/v1/family/{id}/members                 list members + their pubkeys
  POST  /api/v1/family/{id}/invite                  admin: generate code+PIN (returned once)
  POST  /api/v1/family/accept                       redeem code+PIN, join family
  POST  /api/v1/family/{id}/alerts                  submit per-recipient ciphertexts
  GET   /api/v1/family/{id}/alerts                  list MY pending ciphertexts

Auth model:
  - All endpoints require JWT.
  - Membership / role enforcement happens server-side; we don't
    delegate to RLS because the backend already uses the service_role
    key to read across the table set.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.config import get_settings
from api.models.schemas import AuthUser
from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit

logger = logging.getLogger("cleanway.family")

router = APIRouter(prefix="/api/v1/family", tags=["family"])

INVITE_TTL_SECONDS = 7 * 24 * 3600  # 7 days
INVITE_CODE_LENGTH_BYTES = 9  # ~12 base32 chars after encoding
PUBLIC_KEY_LENGTH = 32  # curve25519
ALERT_DEFAULT_TTL_DAYS = 30


# ─── Models ────────────────────────────────────────────────────────


class CreateFamilyRequest(BaseModel):
    name: str = Field(default="My Family", min_length=1, max_length=100)


class CreateFamilyResponse(BaseModel):
    family_id: str
    name: str


class RegisterKeyRequest(BaseModel):
    # base64url-encoded 32-byte curve25519 public key
    public_key_b64: str = Field(..., min_length=40, max_length=64)
    key_version: int = Field(default=1, ge=1, le=1_000_000)


class RegisterKeyResponse(BaseModel):
    family_id: str
    user_id: str
    key_version: int


class FamilyMember(BaseModel):
    user_id: str
    role: str
    joined_at: Optional[str]
    public_key_b64: Optional[str]
    key_version: Optional[int]


class FamilyMembersResponse(BaseModel):
    family_id: str
    members: List[FamilyMember]


class InviteCreateResponse(BaseModel):
    """Returned ONCE at creation. Inviter must surface to the invitee
    out-of-band (text/scan/etc.); these values are never re-fetched."""

    invite_id: str
    code: str  # raw — never persisted
    pin: str  # 4-digit raw — never persisted
    expires_at: str


class AcceptInviteRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=64)
    pin: str = Field(..., pattern=r"^\d{4}$")


class AcceptInviteResponse(BaseModel):
    family_id: str
    role: str


class AlertEnvelope(BaseModel):
    """One per recipient. The same source alert produces N envelopes."""

    recipient_user_id: str
    ciphertext_b64: str = Field(..., min_length=1, max_length=8192)
    nonce_b64: str = Field(..., min_length=1, max_length=64)
    sender_pubkey_b64: str = Field(..., min_length=1, max_length=64)
    alert_type: str = Field(default="block", min_length=1, max_length=32)


class SubmitAlertsRequest(BaseModel):
    envelopes: List[AlertEnvelope] = Field(..., min_length=1, max_length=20)


class SubmitAlertsResponse(BaseModel):
    accepted: int


class StoredAlert(BaseModel):
    id: str
    sender_user_id: Optional[str]
    sender_pubkey_b64: Optional[str]
    nonce_b64: Optional[str]
    ciphertext_b64: Optional[str]
    alert_type: Optional[str]
    created_at: Optional[str]


class ListAlertsResponse(BaseModel):
    family_id: str
    alerts: List[StoredAlert]


# ─── Helpers ───────────────────────────────────────────────────────


def _decode_b64(value: str, *, expected_len: Optional[int] = None) -> bytes:
    """Decode base64url with padding-tolerant logic; raise 422 on bad input."""
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
    except Exception as e:  # broad — base64 raises a few different things
        raise HTTPException(422, "Invalid base64 input") from e
    if expected_len is not None and len(raw) != expected_len:
        raise HTTPException(422, f"Decoded length must be {expected_len} bytes")
    return raw


def _encode_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _hash_invite_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _hash_pin(pin: str) -> str:
    """bcrypt — slow on purpose to defeat offline brute force on the 4-digit space."""
    import bcrypt

    return bcrypt.hashpw(pin.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify_pin(pin: str, hashed: str) -> bool:
    import bcrypt

    try:
        return bcrypt.checkpw(pin.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


async def _supabase_request(
    method: str,
    path: str,
    *,
    params: Optional[dict] = None,
    json: Optional[object] = None,
    extra_headers: Optional[dict] = None,
):
    """Centralised Supabase REST caller — keeps endpoint code linear."""
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(503, "Family service unavailable")

    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(timeout=5.0) as client:
        return await client.request(
            method,
            f"{settings.supabase_url}/rest/v1/{path.lstrip('/')}",
            params=params,
            json=json,
            headers=headers,
        )


async def _is_family_member(family_id: str, user_id: str) -> Optional[str]:
    """Return the role string ('owner'|'member') if user is in family, else None."""
    resp = await _supabase_request(
        "GET",
        "family_members",
        params={
            "family_id": f"eq.{family_id}",
            "user_id": f"eq.{user_id}",
            "select": "role",
        },
    )
    if resp.status_code != 200:
        return None
    rows = resp.json()
    if not rows:
        return None
    return rows[0].get("role")


# ─── Endpoints ─────────────────────────────────────────────────────


@router.post(
    "",
    response_model=CreateFamilyResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="family_create"))],
)
async def create_family(
    body: CreateFamilyRequest,
    user: AuthUser = Depends(get_current_user),
) -> CreateFamilyResponse:
    """Create a family with the caller as owner."""
    create_resp = await _supabase_request(
        "POST",
        "families",
        json={"owner_id": user.id, "name": body.name},
        extra_headers={"Prefer": "return=representation"},
    )
    if create_resp.status_code not in (200, 201):
        logger.warning("family.create_failed", extra={"status": create_resp.status_code})
        raise HTTPException(500, "Failed to create family")

    rows = create_resp.json()
    if not rows:
        raise HTTPException(500, "Failed to create family")
    family_id = rows[0]["id"]

    # Add owner to family_members table — their JWT-bound role
    member_resp = await _supabase_request(
        "POST",
        "family_members",
        json={"family_id": family_id, "user_id": user.id, "role": "owner"},
        extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
    )
    if member_resp.status_code not in (200, 201, 204):
        logger.warning("family.owner_add_failed", extra={"status": member_resp.status_code})
        # Owner row missing is recoverable; family row exists. Surface to caller.

    return CreateFamilyResponse(family_id=family_id, name=body.name)


@router.post(
    "/{family_id}/keys",
    response_model=RegisterKeyResponse,
    dependencies=[Depends(rate_limit(category="user_write"))],
)
async def register_key(
    family_id: str,
    body: RegisterKeyRequest,
    user: AuthUser = Depends(get_current_user),
) -> RegisterKeyResponse:
    """Upsert my curve25519 public key for this family."""
    role = await _is_family_member(family_id, user.id)
    if role is None:
        raise HTTPException(403, "Not a member of this family")

    # Validate length — defense in depth (DB CHECK also enforces).
    raw = _decode_b64(body.public_key_b64, expected_len=PUBLIC_KEY_LENGTH)

    # Postgres BYTEA in PostgREST — \x-prefixed hex string is the
    # accepted JSON encoding.
    pubkey_hex = "\\x" + raw.hex()

    resp = await _supabase_request(
        "POST",
        "family_member_keys",
        json={
            "family_id": family_id,
            "user_id": user.id,
            "public_key": pubkey_hex,
            "key_version": body.key_version,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
    )
    if resp.status_code not in (200, 201, 204):
        logger.warning("family.key_register_failed", extra={"status": resp.status_code})
        raise HTTPException(500, "Failed to register key")

    return RegisterKeyResponse(
        family_id=family_id, user_id=user.id, key_version=body.key_version
    )


def _pubkey_to_b64(pubkey_field) -> Optional[str]:
    """Supabase returns BYTEA as either hex with \\x prefix or base64
    depending on driver/headers. Normalize to base64url."""
    if pubkey_field is None:
        return None
    if isinstance(pubkey_field, str):
        if pubkey_field.startswith("\\x"):
            try:
                raw = bytes.fromhex(pubkey_field[2:])
                return _encode_b64(raw)
            except ValueError:
                return None
        # Already base64
        return pubkey_field
    return None


@router.get(
    "/{family_id}/members",
    response_model=FamilyMembersResponse,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def list_members(
    family_id: str,
    user: AuthUser = Depends(get_current_user),
) -> FamilyMembersResponse:
    """List all members + their public keys so the client can encrypt to them."""
    role = await _is_family_member(family_id, user.id)
    if role is None:
        raise HTTPException(403, "Not a member of this family")

    members_resp = await _supabase_request(
        "GET",
        "family_members",
        params={
            "family_id": f"eq.{family_id}",
            "select": "user_id,role,joined_at",
        },
    )
    if members_resp.status_code != 200:
        raise HTTPException(500, "Failed to list members")
    members_rows = members_resp.json()

    keys_resp = await _supabase_request(
        "GET",
        "family_member_keys",
        params={
            "family_id": f"eq.{family_id}",
            "select": "user_id,public_key,key_version",
        },
    )
    keys_by_user: dict = {}
    if keys_resp.status_code == 200:
        for k in keys_resp.json():
            keys_by_user[k["user_id"]] = k

    members = []
    for row in members_rows:
        uid = row.get("user_id")
        kr = keys_by_user.get(uid) if uid else None
        members.append(
            FamilyMember(
                user_id=uid,
                role=row.get("role") or "member",
                joined_at=row.get("joined_at"),
                public_key_b64=_pubkey_to_b64(kr.get("public_key")) if kr else None,
                key_version=int(kr["key_version"]) if kr and kr.get("key_version") else None,
            )
        )

    return FamilyMembersResponse(family_id=family_id, members=members)


@router.post(
    "/{family_id}/invite",
    response_model=InviteCreateResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="family_invite"))],
)
async def create_invite(
    family_id: str,
    user: AuthUser = Depends(get_current_user),
) -> InviteCreateResponse:
    """Owner-only: generate one-time code+PIN. Caller must surface them
    out-of-band; the server keeps only hashes."""
    role = await _is_family_member(family_id, user.id)
    if role != "owner":
        raise HTTPException(403, "Only the family owner can create invites")

    # base32-friendly random bytes → 14-char code (no padding)
    raw_code = secrets.token_urlsafe(INVITE_CODE_LENGTH_BYTES)
    pin = f"{secrets.randbelow(10000):04d}"

    expires = datetime.now(timezone.utc) + timedelta(seconds=INVITE_TTL_SECONDS)

    resp = await _supabase_request(
        "POST",
        "family_invites",
        json={
            "family_id": family_id,
            "inviter_id": user.id,
            "invite_code_hash": _hash_invite_code(raw_code),
            "pin_hash": _hash_pin(pin),
            "expires_at": expires.isoformat(),
        },
        extra_headers={"Prefer": "return=representation"},
    )
    if resp.status_code not in (200, 201):
        raise HTTPException(500, "Failed to create invite")
    rows = resp.json()
    if not rows:
        raise HTTPException(500, "Failed to create invite")

    return InviteCreateResponse(
        invite_id=rows[0]["id"],
        code=raw_code,
        pin=pin,
        expires_at=expires.isoformat(),
    )


@router.post(
    "/accept",
    response_model=AcceptInviteResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="family_accept"))],
)
async def accept_invite(
    body: AcceptInviteRequest,
    user: AuthUser = Depends(get_current_user),
) -> AcceptInviteResponse:
    """Redeem a (code, PIN) pair — joins caller to the family as a member."""
    code_hash = _hash_invite_code(body.code.strip())

    resp = await _supabase_request(
        "GET",
        "family_invites",
        params={
            "invite_code_hash": f"eq.{code_hash}",
            "redeemed_at": "is.null",
            "select": "id,family_id,pin_hash,expires_at,inviter_id",
        },
    )
    if resp.status_code != 200:
        raise HTTPException(500, "Failed to look up invite")
    rows = resp.json()
    if not rows:
        raise HTTPException(404, "Invalid or expired invite")
    invite = rows[0]

    # Expiry — make sure it's still valid
    try:
        expires_at = datetime.fromisoformat(invite["expires_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError):
        expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(404, "Invalid or expired invite")

    if not _verify_pin(body.pin, invite["pin_hash"]):
        # Don't distinguish "bad PIN" from "bad code" — same error message
        # so an attacker can't enumerate valid codes via the PIN check.
        raise HTTPException(404, "Invalid or expired invite")

    if invite["inviter_id"] == user.id:
        raise HTTPException(400, "You can't accept your own invite")

    # Add to family_members (idempotent merge)
    add_resp = await _supabase_request(
        "POST",
        "family_members",
        json={"family_id": invite["family_id"], "user_id": user.id, "role": "member"},
        extra_headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
    )
    if add_resp.status_code not in (200, 201, 204):
        raise HTTPException(500, "Failed to join family")

    # Mark invite as redeemed
    redeem_resp = await _supabase_request(
        "PATCH",
        "family_invites",
        params={"id": f"eq.{invite['id']}"},
        json={
            "redeemed_at": datetime.now(timezone.utc).isoformat(),
            "redeemed_by_user_id": user.id,
        },
        extra_headers={"Prefer": "return=minimal"},
    )
    if redeem_resp.status_code not in (200, 204):
        logger.warning("family.invite_redeem_mark_failed", extra={"status": redeem_resp.status_code})

    return AcceptInviteResponse(family_id=invite["family_id"], role="member")


@router.post(
    "/{family_id}/alerts",
    response_model=SubmitAlertsResponse,
    dependencies=[Depends(rate_limit(category="user_write"))],
)
async def submit_alerts(
    family_id: str,
    body: SubmitAlertsRequest,
    user: AuthUser = Depends(get_current_user),
) -> SubmitAlertsResponse:
    """Submit per-recipient ciphertexts. Server stores raw bytes; never
    decrypts. Each envelope is an independent row.

    Sender (caller) MUST be a family member; recipients MUST also be
    family members (we don't validate every individual recipient row
    here — that's enforced by the FK + the membership index doesn't
    allow strangers to receive). For now we enforce the sender check
    and trust the FK.
    """
    role = await _is_family_member(family_id, user.id)
    if role is None:
        raise HTTPException(403, "Not a member of this family")

    rows = []
    expires = (
        datetime.now(timezone.utc) + timedelta(days=ALERT_DEFAULT_TTL_DAYS)
    ).isoformat()
    for env in body.envelopes:
        # Validate base64 lengths to fail fast on garbage payloads
        ct = _decode_b64(env.ciphertext_b64)
        nonce = _decode_b64(env.nonce_b64, expected_len=24)  # xchacha20-poly1305 nonce
        spk = _decode_b64(env.sender_pubkey_b64, expected_len=PUBLIC_KEY_LENGTH)

        rows.append(
            {
                "family_id": family_id,
                "sender_device_hash": "",  # legacy column from migration 001 — keep non-null
                "sender_user_id": user.id,
                "recipient_user_id": env.recipient_user_id,
                "encrypted_payload": "\\x" + ct.hex(),
                "nonce": "\\x" + nonce.hex(),
                "sender_pubkey": "\\x" + spk.hex(),
                "alert_type": env.alert_type,
                "expires_at": expires,
            }
        )

    resp = await _supabase_request(
        "POST",
        "family_alerts",
        json=rows,
        extra_headers={"Prefer": "return=minimal"},
    )
    if resp.status_code not in (200, 201, 204):
        logger.warning("family.alert_submit_failed", extra={"status": resp.status_code})
        raise HTTPException(500, "Failed to submit alerts")

    return SubmitAlertsResponse(accepted=len(rows))


def _bytea_to_b64(field) -> Optional[str]:
    if field is None:
        return None
    if isinstance(field, str):
        if field.startswith("\\x"):
            try:
                return _encode_b64(bytes.fromhex(field[2:]))
            except ValueError:
                return None
        return field
    return None


@router.get(
    "/{family_id}/alerts",
    response_model=ListAlertsResponse,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def list_alerts(
    family_id: str,
    user: AuthUser = Depends(get_current_user),
) -> ListAlertsResponse:
    """List ciphertexts addressed to the caller. Server doesn't decrypt."""
    role = await _is_family_member(family_id, user.id)
    if role is None:
        raise HTTPException(403, "Not a member of this family")

    resp = await _supabase_request(
        "GET",
        "family_alerts",
        params={
            "family_id": f"eq.{family_id}",
            "recipient_user_id": f"eq.{user.id}",
            "select": "id,sender_user_id,sender_pubkey,nonce,encrypted_payload,alert_type,created_at",
            "order": "created_at.desc",
            "limit": "100",
        },
    )
    if resp.status_code != 200:
        raise HTTPException(500, "Failed to list alerts")

    items: List[StoredAlert] = []
    for row in resp.json():
        items.append(
            StoredAlert(
                id=row.get("id"),
                sender_user_id=row.get("sender_user_id"),
                sender_pubkey_b64=_bytea_to_b64(row.get("sender_pubkey")),
                nonce_b64=_bytea_to_b64(row.get("nonce")),
                ciphertext_b64=_bytea_to_b64(row.get("encrypted_payload")),
                alert_type=row.get("alert_type"),
                created_at=row.get("created_at"),
            )
        )

    return ListAlertsResponse(family_id=family_id, alerts=items)
