"""Devices linked to an account: register / heartbeat, list, unlink, rename.

A device is one install (Android / iOS app, browser extension, a browser on
the website) that is signed in to the account. The client makes a random id
once per install, keeps it in secure storage and sends it as `X-Device-Id`;
on reinstall the app makes a new one (= a new device; the old one can be
unlinked from the device list).

The limit (docs/ACCOUNTS_BILLING_PLAN.md §5) is enforced when a NEW device
registers: the effective entitlement's device_limit (3 + extras paid, 2
free). An already-linked device always passes its heartbeat, even when the
account is over the limit after a plan lapsed — nobody is kicked off a phone
they already use; they just can't add another.

Unlinking marks the row revoked (migration 022), ends its Auth session, and
leaves a Redis marker so EVERY authenticated request from that install is
refused with 403 `device_revoked` (api/services/auth.py). The app then signs
out locally and makes a new install id; signing in again on that phone is a
new device that takes a seat like any other.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from typing import Optional

from api.services import account_store
from api.services.account_store import AccountStoreError
from api.services.entitlements import Entitlement, EntitlementError, get_effective_entitlement

logger = logging.getLogger("cleanway.account_devices")

PLATFORMS = ("android", "ios", "extension", "web")
DEVICE_ID_HEADER = "X-Device-Id"
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NAME_MAX = 80

# How long the "this install was unlinked" marker lives. The install's id is
# never reused, so it only has to outlive the app's local session — a year is
# far beyond any refresh token's life.
_REVOKED_TTL_SECONDS = 365 * 24 * 3600
_REVOKED_KEY = "revoked_device:{}:{}"


class DeviceError(Exception):
    """Base for refusals the router turns into HTTP answers."""


class StoreUnavailable(DeviceError):
    pass


class DeviceRevoked(DeviceError):
    pass


class DeviceNotFound(DeviceError):
    pass


class DeviceLimitReached(DeviceError):
    def __init__(self, entitlement: Entitlement, devices: list[dict]) -> None:
        super().__init__("device_limit_reached")
        self.entitlement = entitlement
        self.devices = devices


def valid_device_id(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(DEVICE_ID_RE.match(value))


def valid_row_id(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def clean_name(value: Optional[str]) -> Optional[str]:
    """Printable, single-line, at most NAME_MAX characters; empty → None."""
    if not value:
        return None
    text = "".join(
        " " if unicodedata.category(ch).startswith(("C", "Z")) else ch for ch in value
    )
    text = " ".join(text.split())[:NAME_MAX].strip()
    return text or None


def legacy_platform(value: str) -> str:
    """Platform strings the old POST /user/device accepted → today's set."""
    v = (value or "").strip().lower()
    if v in PLATFORMS:
        return v
    if v in ("chrome", "firefox", "safari", "edge", "chrome_ext", "firefox_ext", "safari_ext"):
        return "extension"
    return "web"


def device_view(row: dict, current_device_id: Optional[str]) -> dict:
    """What the API shows of a device. Never the install id itself."""
    return {
        "id": str(row.get("id")),
        "platform": row.get("platform"),
        "name": row.get("name"),
        "app_version": row.get("app_version"),
        "created_at": row.get("created_at"),
        "last_seen_at": row.get("last_seen"),
        "is_current": bool(current_device_id) and row.get("device_hash") == current_device_id,
    }


def _store():
    store = account_store.get_account_store()
    if store is None:
        raise StoreUnavailable("account store not configured")
    return store


async def _mark_revoked(account_id: str, device_hash: Optional[str]) -> None:
    if not device_hash:
        return
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        await r.setex(_REVOKED_KEY.format(account_id, device_hash), _REVOKED_TTL_SECONDS, "1")
    except Exception as e:
        # The DB row is revoked either way; the install is refused at its
        # next registration / heartbeat even without the marker.
        logger.warning("device_revoked_marker_failed", extra={"account_id": account_id, "error": str(e)})


async def is_revoked(account_id: str, device_id: Optional[str]) -> bool:
    """Fast per-request check (Redis). Fails open: Redis down → not revoked;
    the heartbeat still consults the database."""
    if not valid_device_id(device_id):
        return False
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        return bool(await r.get(_REVOKED_KEY.format(account_id, device_id)))
    except Exception:
        return False


async def load_entitlement(account_id: str) -> Entitlement:
    try:
        return await get_effective_entitlement(account_id)
    except EntitlementError as e:
        raise StoreUnavailable(str(e)) from e


async def list_devices(account_id: str) -> list[dict]:
    try:
        return await _store().list_devices(account_id)
    except AccountStoreError as e:
        raise StoreUnavailable(str(e)) from e


async def register(
    *,
    account_id: str,
    device_id: str,
    platform: str,
    name: Optional[str],
    app_version: Optional[str],
    session_id: Optional[str],
) -> tuple[str, dict, Entitlement]:
    """Register a new device or heartbeat a linked one.

    Returns (status, device_row, entitlement), status 'created' | 'updated'.
    Raises DeviceRevoked, DeviceLimitReached, StoreUnavailable."""
    entitlement = await load_entitlement(account_id)
    store = _store()
    try:
        result = await store.register_device(
            account_id=account_id,
            device_hash=device_id,
            platform=platform,
            name=clean_name(name),
            app_version=(app_version or None),
            session_id=session_id if valid_row_id(session_id) else None,
            device_limit=entitlement.device_limit,
        )
    except AccountStoreError as e:
        raise StoreUnavailable(str(e)) from e

    status = result.get("status")
    if status in ("created", "updated"):
        if status == "created":
            logger.info(
                "device_linked",
                extra={"account_id": account_id, "platform": platform, "plan": entitlement.plan},
            )
        return status, result.get("device") or {}, entitlement
    if status == "revoked":
        await _mark_revoked(account_id, device_id)
        raise DeviceRevoked()
    if status == "limit_reached":
        raise DeviceLimitReached(entitlement, await list_devices(account_id))
    raise StoreUnavailable(f"register_device returned {status!r}")


async def revoke(*, account_id: str, device_row_id: str) -> dict:
    """Unlink one device of this account. Idempotent. Raises DeviceNotFound."""
    if not valid_row_id(device_row_id):
        raise DeviceNotFound()
    try:
        result = await _store().revoke_device(account_id=account_id, device_id=device_row_id)
    except AccountStoreError as e:
        raise StoreUnavailable(str(e)) from e
    status = result.get("status")
    if status == "not_found":
        raise DeviceNotFound()
    device = result.get("device") or {}
    # Also for 'already_revoked': rewrites a marker Redis may have lost.
    await _mark_revoked(account_id, device.get("device_hash"))
    if status == "revoked":
        logger.info("device_unlinked", extra={"account_id": account_id, "platform": device.get("platform")})
    return device


async def rename(*, account_id: str, device_row_id: str, name: Optional[str]) -> dict:
    cleaned = clean_name(name)
    if cleaned is None:
        raise ValueError("name must contain visible characters")
    if not valid_row_id(device_row_id):
        raise DeviceNotFound()
    try:
        row = await _store().rename_device(account_id=account_id, device_id=device_row_id, name=cleaned)
    except AccountStoreError as e:
        raise StoreUnavailable(str(e)) from e
    if not row:
        raise DeviceNotFound()
    return row
