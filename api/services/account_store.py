"""Storage for accounts: linked devices and entitlements.

Two tables (supabase/migrations 022, 023) reached through PostgREST with
the service key, like the rest of the API — plus `revenuecat_events` (024),
the RevenueCat webhook's dedupe list. Device registration and unlinking
go through the SQL functions `register_device` / `revoke_device`: the device
limit has to be checked and written in ONE transaction (two new phones
racing for the last seat must not both get it), which a pair of REST calls
cannot do.

Everything raises `AccountStoreError` when Supabase can't be reached or
answers non-2xx. Callers decide: an account screen answers 503, a billing
webhook (Stripe, RevenueCat) answers 5xx so it is retried. Nothing here turns "database down"
into "no devices" or "free plan".

`get_account_store()` returns None when Supabase isn't configured (local
dev) — endpoints then answer 503 instead of pretending. Tests swap in an
in-memory store via `set_account_store()`.
"""
from __future__ import annotations

import logging
from typing import Any, Optional, Protocol

from api.config import get_settings

logger = logging.getLogger("cleanway.account_store")

# Columns a device is read with. device_hash (the client's install id) is
# read so the API can tell "this device" apart; it is never sent back out.
DEVICE_COLUMNS = "id,device_hash,platform,name,app_version,created_at,last_seen,revoked_at"
# Every column: product_id / source_event_at arrive with migration 024, and
# naming them here would turn every account screen into a 503 on a database
# where 024 hasn't been applied yet.
ENTITLEMENT_COLUMNS = "*"


class AccountStoreError(Exception):
    """Supabase failed on the account path. Never swallow."""


class AccountStore(Protocol):
    async def list_entitlements(self, account_id: str) -> list[dict]: ...

    async def upsert_entitlement(self, row: dict) -> None: ...

    async def set_entitlements_status(
        self, *, account_id: str, source: str, status: str
    ) -> None: ...

    async def get_entitlement(self, *, source: str, external_id: str) -> Optional[dict]: ...

    async def reassign_entitlements(
        self, *, from_account: str, to_account: str, sources: tuple[str, ...]
    ) -> int: ...

    async def is_event_processed(self, event_id: str) -> bool: ...

    async def mark_event_processed(self, event_id: str, event_type: str) -> None: ...

    async def list_devices(self, account_id: str) -> list[dict]: ...

    async def register_device(
        self,
        *,
        account_id: str,
        device_hash: str,
        platform: str,
        name: Optional[str],
        app_version: Optional[str],
        session_id: Optional[str],
        device_limit: int,
    ) -> dict: ...

    async def revoke_device(self, *, account_id: str, device_id: str) -> dict: ...

    async def rename_device(
        self, *, account_id: str, device_id: str, name: str
    ) -> Optional[dict]: ...


class PostgrestAccountStore:
    """The production store: Supabase PostgREST + two RPC functions."""

    def __init__(self, base_url: str, service_key: str, timeout: float = 5.0) -> None:
        self._base = base_url.rstrip("/")
        self._key = service_key
        self._timeout = timeout

    def _headers(self, **extra: str) -> dict[str, str]:
        return {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            **extra,
        }

    async def _call(self, method: str, path: str, *, ok=(200,), **kwargs: Any) -> Any:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await getattr(client, method)(f"{self._base}{path}", **kwargs)
        except Exception as e:
            raise AccountStoreError(f"{method.upper()} {path} failed: {e}") from e
        if resp.status_code not in ok:
            logger.error(
                "account_store_unexpected_status",
                extra={"path": path, "status": resp.status_code, "body": (resp.text or "")[:200]},
            )
            raise AccountStoreError(f"{method.upper()} {path} returned {resp.status_code}")
        if resp.status_code == 204:
            return None
        try:
            return resp.json()
        except Exception as e:
            raise AccountStoreError(f"{method.upper()} {path} returned invalid JSON") from e

    # ── entitlements ──

    async def list_entitlements(self, account_id: str) -> list[dict]:
        rows = await self._call(
            "get",
            "/rest/v1/entitlements",
            params={"account_id": f"eq.{account_id}", "select": ENTITLEMENT_COLUMNS},
            headers=self._headers(),
        )
        return list(rows or [])

    async def upsert_entitlement(self, row: dict) -> None:
        # merge-duplicates on (source, external_id): only the columns sent are
        # overwritten on conflict, so an update without `plan` keeps the plan.
        await self._call(
            "post",
            "/rest/v1/entitlements",
            ok=(200, 201, 204),
            params={"on_conflict": "source,external_id"},
            json=row,
            headers=self._headers(
                **{
                    "Content-Type": "application/json",
                    "Prefer": "resolution=merge-duplicates,return=minimal",
                }
            ),
        )

    async def set_entitlements_status(self, *, account_id: str, source: str, status: str) -> None:
        await self._call(
            "patch",
            "/rest/v1/entitlements",
            ok=(200, 204),
            params={"account_id": f"eq.{account_id}", "source": f"eq.{source}"},
            json={"status": status},
            headers=self._headers(
                **{"Content-Type": "application/json", "Prefer": "return=minimal"}
            ),
        )

    async def get_entitlement(self, *, source: str, external_id: str) -> Optional[dict]:
        rows = await self._call(
            "get",
            "/rest/v1/entitlements",
            params={
                "source": f"eq.{source}",
                "external_id": f"eq.{external_id}",
                "select": ENTITLEMENT_COLUMNS,
                "limit": "1",
            },
            headers=self._headers(),
        )
        rows = list(rows or [])
        return rows[0] if rows else None

    async def reassign_entitlements(
        self, *, from_account: str, to_account: str, sources: tuple[str, ...]
    ) -> int:
        rows = await self._call(
            "patch",
            "/rest/v1/entitlements",
            params={
                "account_id": f"eq.{from_account}",
                "source": f"in.({','.join(sources)})",
                "select": "id",
            },
            json={"account_id": to_account},
            headers=self._headers(
                **{"Content-Type": "application/json", "Prefer": "return=representation"}
            ),
        )
        return len(list(rows or []))

    # ── RevenueCat webhook dedupe (migration 024) ──

    async def is_event_processed(self, event_id: str) -> bool:
        rows = await self._call(
            "get",
            "/rest/v1/revenuecat_events",
            params={"event_id": f"eq.{event_id}", "select": "event_id", "limit": "1"},
            headers=self._headers(),
        )
        return bool(rows)

    async def mark_event_processed(self, event_id: str, event_type: str) -> None:
        await self._call(
            "post",
            "/rest/v1/revenuecat_events",
            ok=(200, 201, 204),
            params={"on_conflict": "event_id"},
            json={"event_id": event_id, "event_type": event_type},
            headers=self._headers(
                **{
                    "Content-Type": "application/json",
                    "Prefer": "resolution=ignore-duplicates,return=minimal",
                }
            ),
        )

    # ── devices ──

    async def list_devices(self, account_id: str) -> list[dict]:
        rows = await self._call(
            "get",
            "/rest/v1/devices",
            params={
                "user_id": f"eq.{account_id}",
                "revoked_at": "is.null",
                "select": DEVICE_COLUMNS,
                "order": "created_at.asc",
            },
            headers=self._headers(),
        )
        return list(rows or [])

    async def _rpc(self, fn: str, args: dict) -> dict:
        result = await self._call(
            "post",
            f"/rest/v1/rpc/{fn}",
            json=args,
            headers=self._headers(**{"Content-Type": "application/json"}),
        )
        if not isinstance(result, dict) or "status" not in result:
            raise AccountStoreError(f"rpc {fn} returned an unexpected body")
        return result

    async def register_device(
        self,
        *,
        account_id: str,
        device_hash: str,
        platform: str,
        name: Optional[str],
        app_version: Optional[str],
        session_id: Optional[str],
        device_limit: int,
    ) -> dict:
        return await self._rpc(
            "register_device",
            {
                "p_user_id": account_id,
                "p_device_hash": device_hash,
                "p_platform": platform,
                "p_name": name,
                "p_app_version": app_version,
                "p_session_id": session_id,
                "p_device_limit": device_limit,
            },
        )

    async def revoke_device(self, *, account_id: str, device_id: str) -> dict:
        return await self._rpc(
            "revoke_device", {"p_user_id": account_id, "p_device_id": device_id}
        )

    async def rename_device(self, *, account_id: str, device_id: str, name: str) -> Optional[dict]:
        rows = await self._call(
            "patch",
            "/rest/v1/devices",
            params={
                "id": f"eq.{device_id}",
                "user_id": f"eq.{account_id}",
                "revoked_at": "is.null",
                "select": DEVICE_COLUMNS,
            },
            json={"name": name},
            headers=self._headers(
                **{"Content-Type": "application/json", "Prefer": "return=representation"}
            ),
        )
        rows = list(rows or [])
        return rows[0] if rows else None


_override: Optional[AccountStore] = None


def set_account_store(store: Optional[AccountStore]) -> None:
    """Install a store (tests); None goes back to the configured one."""
    global _override
    _override = store


def get_account_store() -> Optional[AccountStore]:
    if _override is not None:
        return _override
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return None
    return PostgrestAccountStore(settings.supabase_url, settings.supabase_service_key)
