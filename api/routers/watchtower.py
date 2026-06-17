"""Typosquat Watchtower API — Strategy doc Top-20 #17.

CRUD over the user's brand watchlist + read access to the
typosquat_alerts emitted by the daily scan job. The scan itself
is a background script (scripts/refresh_watchtower.py) triggered
by GH Actions cron. Users can also force an on-demand scan via
POST /scan, rate-limited to 1 per hour per user.

Endpoints:
  GET    /api/v1/watchtower/brands               — list user's brands
  POST   /api/v1/watchtower/brands               — add brand
  DELETE /api/v1/watchtower/brands/{id}          — remove brand
  GET    /api/v1/watchtower/alerts               — alerts for user's brands
  PATCH  /api/v1/watchtower/alerts/{id}          — toggle auto_block
  POST   /api/v1/watchtower/scan                 — force scan now

Quotas (free vs paid):
  free tier   — 1 brand watched, 1 manual scan per day
  personal    — 5 brands, 4 scans/day
  family      — 25 brands across the group
  business    — unlimited

The quotas are enforced at INSERT/POST time, not as RLS — keeping
the DB simple. The cron scans every distinct brand once per day
regardless of who owns it.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.services.watchtower import eTLD1, scan_brand

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/watchtower", tags=["watchtower"])

BRAND_QUOTA_BY_TIER: dict[UserTier, int] = {
    UserTier.free: 1,
    UserTier.personal: 5,
    UserTier.family: 25,
    UserTier.business: 1_000,  # effectively unlimited
}


# ─────────────────────────────────────────────────────────────────
# Request / response models
# ─────────────────────────────────────────────────────────────────

class BrandCreate(BaseModel):
    brand_name: str = Field(..., min_length=1, max_length=80)
    brand_root_domain: str = Field(..., min_length=3, max_length=253)

    @field_validator("brand_name")
    @classmethod
    def _strip_brand_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("brand_name cannot be blank")
        return v

    @field_validator("brand_root_domain")
    @classmethod
    def _canonicalize_root(cls, v: str) -> str:
        root = eTLD1(v)
        if not root or "." not in root:
            raise ValueError("must be a valid registrable domain")
        return root


class BrandResponse(BaseModel):
    id: str
    brand_name: str
    brand_root_domain: str
    created_at: str
    last_scanned_at: Optional[str] = None


class AlertResponse(BaseModel):
    id: str
    brand_root_domain: str
    suspect_domain: str
    edit_distance: int
    variant_kind: str
    first_seen_at: str
    issuer: Optional[str] = None
    auto_block: bool
    created_at: str


class AlertPatch(BaseModel):
    auto_block: bool


class ScanResponse(BaseModel):
    scanned_brands: int
    new_alerts: int
    candidates_found: int


# ─────────────────────────────────────────────────────────────────
# Supabase helpers — same pattern as routers/family.py
# ─────────────────────────────────────────────────────────────────

async def _supabase(method: str, path: str, *, params=None, json=None, extra_headers=None):
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(503, "Watchtower service unavailable")

    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.request(
            method,
            f"{settings.supabase_url}/rest/v1/{path.lstrip('/')}",
            params=params,
            json=json,
            headers=headers,
        )


# ─────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────

@router.get(
    "/brands",
    response_model=list[BrandResponse],
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_list"))],
)
async def list_brands(user: AuthUser = Depends(get_current_user)):
    resp = await _supabase(
        "GET",
        "brand_watchlist",
        params={
            "user_id": f"eq.{user.id}",
            "select": "id,brand_name,brand_root_domain,created_at,last_scanned_at",
            "order": "created_at.desc",
        },
    )
    if resp.status_code != 200:
        logger.warning("watchtower list failed: %s %s", resp.status_code, resp.text[:200])
        raise HTTPException(502, "Failed to load watchlist")
    return resp.json()


@router.post(
    "/brands",
    response_model=BrandResponse,
    status_code=201,
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_add"))],
)
async def add_brand(
    body: BrandCreate,
    user: AuthUser = Depends(get_current_user),
):
    # Quota — fail closed. A previous version defaulted current=0 on
    # any count error, which meant a transient Supabase 502 or a
    # PostgREST timeout silently bypassed every user's quota
    # (adversarial-review #4).
    quota = BRAND_QUOTA_BY_TIER.get(user.tier, 1)
    count_resp = await _supabase(
        "GET",
        "brand_watchlist",
        params={"user_id": f"eq.{user.id}", "select": "id"},
        extra_headers={"Prefer": "count=exact", "Range": "0-0"},
    )
    if count_resp.status_code != 200:
        logger.warning(
            "watchtower quota check failed status=%s — failing closed",
            count_resp.status_code,
        )
        raise HTTPException(503, "Watchtower temporarily unavailable, please retry")
    cr = count_resp.headers.get("Content-Range") or ""
    try:
        current = int(cr.split("/")[-1])
    except (ValueError, IndexError):
        logger.warning("watchtower count header malformed: %r — failing closed", cr)
        raise HTTPException(503, "Watchtower temporarily unavailable, please retry")
    if current >= quota:
        raise HTTPException(
            403,
            f"Watchtower quota reached for tier {user.tier.value} ({quota} brand"
            f"{'s' if quota != 1 else ''}). Upgrade to add more.",
        )

    # Insert. RLS allows the user to insert their own row; service_role
    # bypasses RLS anyway and we set user_id explicitly.
    create_resp = await _supabase(
        "POST",
        "brand_watchlist",
        json={
            "user_id": user.id,
            "brand_name": body.brand_name,
            "brand_root_domain": body.brand_root_domain,
        },
        extra_headers={"Prefer": "return=representation"},
    )
    if create_resp.status_code == 409:
        # UNIQUE(user_id, brand_root_domain) — user already watches this brand.
        raise HTTPException(409, "Brand already in your watchlist")
    if create_resp.status_code not in (200, 201):
        logger.warning("watchtower create failed: %s %s", create_resp.status_code, create_resp.text[:300])
        raise HTTPException(502, "Failed to add brand")
    rows = create_resp.json()
    if not rows:
        raise HTTPException(502, "Brand created but empty response")
    return rows[0]


@router.delete(
    "/brands/{brand_id}",
    status_code=204,
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_delete"))],
)
async def remove_brand(
    brand_id: str,
    user: AuthUser = Depends(get_current_user),
):
    # Use both filters so a leaked brand_id (UUID) from one user
    # can't delete another user's row even via service_role.
    resp = await _supabase(
        "DELETE",
        "brand_watchlist",
        params={"id": f"eq.{brand_id}", "user_id": f"eq.{user.id}"},
    )
    if resp.status_code not in (200, 204):
        logger.warning("watchtower delete failed: %s %s", resp.status_code, resp.text[:300])
        raise HTTPException(502, "Failed to remove brand")
    return None


@router.get(
    "/alerts",
    response_model=list[AlertResponse],
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_alerts"))],
)
async def list_alerts(user: AuthUser = Depends(get_current_user)):
    # Fetch user's brand roots, then alerts for those roots. Two
    # round-trips but avoids needing a JOIN in the Supabase REST
    # query language (PostgREST supports embedded resources but
    # the embedded variant doesn't surface the RLS error path well).
    brands_resp = await _supabase(
        "GET",
        "brand_watchlist",
        params={
            "user_id": f"eq.{user.id}",
            "select": "brand_root_domain",
        },
    )
    if brands_resp.status_code != 200:
        raise HTTPException(502, "Failed to load brands for alerts")
    roots = [r["brand_root_domain"] for r in brands_resp.json()]
    if not roots:
        return []
    in_clause = "(" + ",".join(f'"{r}"' for r in roots) + ")"
    alerts_resp = await _supabase(
        "GET",
        "typosquat_alerts",
        params={
            "brand_root_domain": f"in.{in_clause}",
            "select": "id,brand_root_domain,suspect_domain,edit_distance,variant_kind,first_seen_at,issuer,auto_block,created_at",
            "order": "first_seen_at.desc",
            "limit": "200",
        },
    )
    if alerts_resp.status_code != 200:
        raise HTTPException(502, "Failed to load alerts")
    return alerts_resp.json()


@router.patch(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_patch"))],
    deprecated=True,
)
async def toggle_alert(
    alert_id: str,
    body: AlertPatch,
    user: AuthUser = Depends(get_current_user),
):
    """DEPRECATED — toggling auto_block is currently disabled while
    we move from shared-row alerts to per-user dismissals.

    Migration 020 dropped the RLS UPDATE policy because the original
    model let any user watching a brand demote a threat for ALL
    other watchers of the same brand (adversarial-review #5). The
    feature returns once we ship a dismissed_alerts table.
    """
    raise HTTPException(
        410,
        "Per-alert auto_block toggling is temporarily disabled; "
        "remove the brand from your watchlist to mute alerts.",
    )


@router.post(
    "/scan",
    response_model=ScanResponse,
    dependencies=[Depends(rate_limit(mode="user", category="watchtower_scan"))],
)
async def scan_now(user: AuthUser = Depends(get_current_user)):
    """On-demand scan of EVERY brand in the caller's watchlist.

    Rate-limit category 'watchtower_scan' caps this per user (the
    cron does the heavy lifting on a daily schedule; this is for
    impatient users who just added a brand and want their first
    batch of alerts immediately).
    """
    brands_resp = await _supabase(
        "GET",
        "brand_watchlist",
        params={
            "user_id": f"eq.{user.id}",
            "select": "id,brand_root_domain",
        },
    )
    if brands_resp.status_code != 200:
        raise HTTPException(502, "Failed to load brands")
    brands = brands_resp.json()
    if not brands:
        return ScanResponse(scanned_brands=0, new_alerts=0, candidates_found=0)

    total_candidates = 0
    new_alerts = 0
    for b in brands:
        candidates = await scan_brand(b["brand_root_domain"])
        total_candidates += len(candidates)
        if candidates:
            payload = [c.as_dict() for c in candidates]
            ins = await _supabase(
                "POST",
                "typosquat_alerts",
                json=payload,
                extra_headers={
                    # PostgREST UPSERT on the dedup key.
                    "Prefer": "resolution=ignore-duplicates,return=representation",
                },
            )
            if ins.status_code in (200, 201):
                created = ins.json()
                if isinstance(created, list):
                    new_alerts += len(created)
        # Stamp last_scanned_at regardless (so we don't re-scan
        # quiet brands at every manual click).
        from datetime import datetime, timezone
        await _supabase(
            "PATCH",
            "brand_watchlist",
            params={"id": f"eq.{b['id']}"},
            json={"last_scanned_at": datetime.now(timezone.utc).isoformat()},
        )

    return ScanResponse(
        scanned_brands=len(brands),
        new_alerts=new_alerts,
        candidates_found=total_candidates,
    )
