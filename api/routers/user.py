"""
User-facing API endpoints.

  POST /api/v1/user/aggregates — submit weekly aggregate from device
  GET  /api/v1/user/percentile — get percentile ranking
  POST /api/v1/user/score — sync security score number
  GET  /api/v1/user/profile — get user profile + subscription info
  POST /api/v1/user/device — register/update device
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.models.schemas import (
    AuthUser,
    SkillLevel,
    UserSettings,
    UserSettingsUpdate,
)
from api.config import get_settings

logger = logging.getLogger("cleanway.user")

router = APIRouter(prefix="/api/v1/user", tags=["user"])


# ── Models ──

class WeeklyAggregateSubmit(BaseModel):
    total_checks: int = Field(..., ge=0)
    total_blocks: int = Field(..., ge=0)
    total_warnings: int = Field(0, ge=0)
    total_trackers: int = Field(0, ge=0)
    score: Optional[int] = Field(None, ge=0, le=100)


class PercentileResponse(BaseModel):
    percentile: int = Field(..., ge=0, le=100)  # "safer than X% of users"
    total_blocks: int
    bracket: str  # "top 10%", "top 25%", etc.


class ScoreSync(BaseModel):
    score: int = Field(..., ge=0, le=100)


class DeviceRegister(BaseModel):
    device_hash: str
    platform: str  # chrome, firefox, safari, ios, android
    app_version: str = "0.1.0"


class DeviceOverrideUpdate(BaseModel):
    """Per-device overrides — used by Family Hub to set Granny Mode on
    grandmother's phone without changing her account-level default.

    All fields optional so PATCH semantics work; setting any to None
    explicitly clears the override and falls back to the user-level value.
    """

    skill_level_override: Optional[SkillLevel] = None
    voice_alerts_enabled: Optional[bool] = None
    font_scale: Optional[float] = None
    clear_overrides: bool = False  # if True, wipe all overrides (back to user defaults)


class EffectiveSkillResponse(BaseModel):
    """Resolved skill + accessibility for a specific device.

    Resolution rule: device override (if set) wins over user default.
    Returned to extension/mobile so the UI can render with the right
    density, fonts, voice alerts, etc.
    """

    device_hash: str
    skill_level: SkillLevel
    voice_alerts_enabled: bool
    font_scale: float
    # Provenance — useful for the client UI to show "Set by family admin"
    skill_source: Literal["device_override", "user_default"]
    voice_source: Literal["device_override", "user_default"]
    font_source: Literal["device_override", "user_default"]


class ProfileResponse(BaseModel):
    id: str
    email: Optional[str]
    tier: str
    devices: int
    member_since: Optional[str]


# Pricing v2: free users see full threat detail for the first N dangerous
# blocks, then detail-only is gated (block itself ALWAYS works — ethical
# baseline). Tunable via env if conversion data shows we set this wrong.
FREEMIUM_DETAIL_GATING_THRESHOLD: int = 50


class ThreatStatus(BaseModel):
    """Cumulative blocked-threats counter + freemium detail gating state."""

    threats_blocked_lifetime: int = 0
    threshold: int = FREEMIUM_DETAIL_GATING_THRESHOLD
    # `gated` is true when this user should see the upsell nudge instead of
    # full threat detail. Block UI itself never depends on this flag.
    gated: bool = False
    tier: str = "free"
    nudge_shown_at: Optional[str] = None  # ISO 8601
    nudge_count: int = 0


class IncrementThreatsRequest(BaseModel):
    """Extension/mobile reports N newly-blocked threats since last sync."""

    count: int = Field(default=1, ge=1, le=1000)


def _is_gated(tier: str, counter: int) -> bool:
    """Detail gating only applies to free tier past the threshold."""
    return tier == "free" and counter >= FREEMIUM_DETAIL_GATING_THRESHOLD


# ── Endpoints ──

@router.post("/aggregates", dependencies=[Depends(rate_limit(category="user_write"))])
async def submit_weekly_aggregate(
    data: WeeklyAggregateSubmit,
    user: AuthUser = Depends(get_current_user),
):
    """
    Submit weekly aggregate numbers from device.
    Called once per week by the extension/app.
    Server stores ONLY numbers — no URLs, no details.
    """
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(503, "Database not configured")

    # Calculate current week (Monday)
    today = datetime.now(timezone.utc).date()
    week_start = today - timedelta(days=today.weekday())

    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }

        body = {
            "user_id": user.id,
            "week": week_start.isoformat(),
            "total_checks": data.total_checks,
            "total_blocks": data.total_blocks,
            "total_warnings": data.total_warnings,
            "total_trackers": data.total_trackers,
            "score": data.score,
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{settings.supabase_url}/rest/v1/weekly_aggregates",
                headers=headers,
                json=body,
            )
            if resp.status_code not in (200, 201):
                logger.warning("aggregate_submit_error", extra={"status": resp.status_code})

        logger.info("aggregate_submitted", extra={
            "user_id": user.id, "checks": data.total_checks, "blocks": data.total_blocks,
        })

        return {"status": "ok", "week": week_start.isoformat()}

    except Exception as e:
        logger.error("aggregate_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to submit aggregate")


@router.get(
    "/percentile",
    response_model=PercentileResponse,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def get_percentile(user: AuthUser = Depends(get_current_user)):
    """
    Get user's percentile ranking based on weekly blocks.
    "Safer than X% of users" — computed from all users' aggregates.
    """
    import httpx
    from api.services.cache import get_redis

    settings = get_settings()

    # Try cache first
    try:
        r = await get_redis()
        cached = await r.get(f"percentile:{user.id}")
        if cached:
            import json
            return PercentileResponse(**json.loads(cached))
    except Exception:
        pass

    if not settings.supabase_url or not settings.supabase_service_key:
        # Fallback: return estimate
        return PercentileResponse(percentile=75, total_blocks=0, bracket="top 25%")

    today = datetime.now(timezone.utc).date()
    week_start = today - timedelta(days=today.weekday())

    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            # Get user's blocks this week
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/weekly_aggregates"
                f"?user_id=eq.{user.id}&week=eq.{week_start.isoformat()}&select=total_blocks",
                headers=headers,
            )
            user_data = resp.json()
            user_blocks = user_data[0]["total_blocks"] if user_data else 0

            # Get all users' blocks this week for percentile
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/weekly_aggregates"
                f"?week=eq.{week_start.isoformat()}&select=total_blocks&order=total_blocks.asc",
                headers=headers,
            )
            all_blocks = [row["total_blocks"] for row in resp.json()]

        if not all_blocks:
            percentile = 50
        else:
            below = sum(1 for b in all_blocks if b >= user_blocks)
            percentile = min(99, int((below / len(all_blocks)) * 100))

        bracket = (
            "top 1%" if percentile >= 99
            else "top 5%" if percentile >= 95
            else "top 10%" if percentile >= 90
            else "top 25%" if percentile >= 75
            else "top 50%" if percentile >= 50
            else "bottom 50%"
        )

        result = PercentileResponse(
            percentile=percentile,
            total_blocks=user_blocks,
            bracket=bracket,
        )

        # Cache for 1 hour
        try:
            r = await get_redis()
            import json
            await r.setex(f"percentile:{user.id}", 3600, json.dumps(result.model_dump()))
        except Exception:
            pass

        return result

    except Exception as e:
        logger.error("percentile_error", extra={"error": str(e)})
        return PercentileResponse(percentile=50, total_blocks=0, bracket="calculating...")


@router.post("/score", dependencies=[Depends(rate_limit(category="user_write"))])
async def sync_score(
    data: ScoreSync,
    user: AuthUser = Depends(get_current_user),
):
    """
    Sync security score NUMBER from device.
    Score is CALCULATED on device. Server stores the number only.
    Details/breakdown stay on device.
    """
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return {"status": "ok", "note": "Database not configured, score not persisted"}

    today = datetime.now(timezone.utc).date()
    week_start = today - timedelta(days=today.weekday())

    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{settings.supabase_url}/rest/v1/weekly_aggregates",
                headers=headers,
                json={
                    "user_id": user.id,
                    "week": week_start.isoformat(),
                    "score": data.score,
                },
            )

        return {"status": "ok", "score": data.score}

    except Exception as e:
        logger.error("score_sync_error", extra={"error": str(e)})
        return {"status": "ok", "note": "Score sync failed, will retry"}


@router.post("/device", dependencies=[Depends(rate_limit(category="user_write"))])
async def register_device(
    data: DeviceRegister,
    user: AuthUser = Depends(get_current_user),
):
    """Register or update device for multi-device sync."""
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return {"status": "ok"}

    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{settings.supabase_url}/rest/v1/devices",
                headers=headers,
                json={
                    "user_id": user.id,
                    "device_hash": data.device_hash,
                    "platform": data.platform,
                    "app_version": data.app_version,
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                },
            )

        return {"status": "ok"}

    except Exception as e:
        logger.error("device_register_error", extra={"error": str(e)})
        return {"status": "ok"}


_ALLOWED_LOCALES = frozenset(
    {"en", "es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id"}
)


def _hash_pin(pin: str) -> str:
    """
    Hash a 4-digit PIN with bcrypt.

    We deliberately do NOT log the plaintext PIN anywhere. Callers must validate
    format (4 digits) before invoking.
    """
    import bcrypt

    # bcrypt is slow on purpose — 4-digit space is tiny, slow hash is the
    # only defense against offline brute force once the hash is stolen.
    return bcrypt.hashpw(pin.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


@router.get(
    "/settings",
    response_model=UserSettings,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def get_user_settings(user: AuthUser = Depends(get_current_user)) -> UserSettings:
    """
    Return the current user's cross-device preferences (skill level, locale,
    accessibility defaults). PIN is never returned — only the `parental_pin_set`
    flag.
    """
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Degraded mode — return defaults so UI still renders
        return UserSettings()

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"{settings.supabase_url}/rest/v1/users",
            params={
                "id": f"eq.{user.id}",
                "select": "skill_level,preferred_locale,voice_alerts_enabled,font_scale,parental_pin_hash",
            },
            headers={
                "apikey": settings.supabase_service_key,
                "Authorization": f"Bearer {settings.supabase_service_key}",
            },
        )
        if resp.status_code != 200:
            logger.warning("settings_fetch_failed", extra={"status": resp.status_code})
            return UserSettings()
        rows = resp.json()
        if not rows:
            return UserSettings()
        row = rows[0]
        try:
            return UserSettings(
                skill_level=SkillLevel(row.get("skill_level") or "regular"),
                preferred_locale=row.get("preferred_locale") or "en",
                voice_alerts_enabled=bool(row.get("voice_alerts_enabled", False)),
                font_scale=float(row.get("font_scale") or 1.0),
                parental_pin_set=bool(row.get("parental_pin_hash")),
            )
        except (ValueError, TypeError) as e:
            logger.warning("settings_decode_failed", extra={"error": str(e)})
            return UserSettings()


@router.put(
    "/settings",
    response_model=UserSettings,
    dependencies=[Depends(rate_limit(category="user_write"))],
)
async def update_user_settings(
    update: UserSettingsUpdate,
    user: AuthUser = Depends(get_current_user),
) -> UserSettings:
    """
    Partial update of user settings. All fields optional.

    Parental PIN behavior:
    - Providing a non-empty `parental_pin` hashes and stores it.
    - Providing `parental_pin=""` clears the PIN.
    - Omitting `parental_pin` leaves the existing hash untouched.
    """
    # ── Validation ──
    if update.font_scale is not None and not 0.8 <= update.font_scale <= 2.5:
        raise HTTPException(
            status_code=422,
            detail="font_scale must be between 0.8 and 2.5",
        )
    if update.preferred_locale is not None and update.preferred_locale not in _ALLOWED_LOCALES:
        raise HTTPException(
            status_code=422,
            detail=f"preferred_locale must be one of: {sorted(_ALLOWED_LOCALES)}",
        )
    if update.parental_pin is not None and update.parental_pin != "":
        pin = update.parental_pin
        if not (pin.isdigit() and len(pin) == 4):
            raise HTTPException(
                status_code=422,
                detail="parental_pin must be exactly 4 digits",
            )

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(
            status_code=503,
            detail="User settings storage unavailable",
        )

    # Build update payload from non-None fields
    payload: dict = {}
    if update.skill_level is not None:
        payload["skill_level"] = update.skill_level.value
    if update.preferred_locale is not None:
        payload["preferred_locale"] = update.preferred_locale
    if update.voice_alerts_enabled is not None:
        payload["voice_alerts_enabled"] = update.voice_alerts_enabled
    if update.font_scale is not None:
        payload["font_scale"] = update.font_scale
    if update.parental_pin is not None:
        if update.parental_pin == "":
            payload["parental_pin_hash"] = None
        else:
            payload["parental_pin_hash"] = _hash_pin(update.parental_pin)

    # Nothing to update — return current state
    if not payload:
        return await get_user_settings(user)

    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.patch(
            f"{settings.supabase_url}/rest/v1/users",
            params={"id": f"eq.{user.id}"},
            json=payload,
            headers={
                "apikey": settings.supabase_service_key,
                "Authorization": f"Bearer {settings.supabase_service_key}",
                "Content-Type": "application/json",
                "Prefer": "return=representation",
            },
        )
        if resp.status_code not in (200, 204):
            logger.warning(
                "settings_update_failed",
                extra={"status": resp.status_code, "user_id": user.id},
            )
            raise HTTPException(
                status_code=500,
                detail="Failed to persist user settings",
            )

    # Re-fetch to return canonical state (with parental_pin_set derived flag)
    return await get_user_settings(user)


@router.get(
    "/profile",
    response_model=ProfileResponse,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def get_profile(user: AuthUser = Depends(get_current_user)):
    """Get user profile info."""
    import httpx

    settings = get_settings()
    devices_count = 0
    member_since: Optional[str] = None

    if settings.supabase_url and settings.supabase_service_key:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Prefer": "count=exact",
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                devices_resp, user_resp = await asyncio.gather(
                    client.get(
                        f"{settings.supabase_url}/rest/v1/devices",
                        params={"user_id": f"eq.{user.id}", "select": "id"},
                        headers={**headers, "Range-Unit": "items", "Range": "0-0"},
                    ),
                    client.get(
                        f"{settings.supabase_url}/rest/v1/users",
                        params={"id": f"eq.{user.id}", "select": "created_at"},
                        headers=headers,
                    ),
                    return_exceptions=True,
                )

            if isinstance(devices_resp, httpx.Response) and devices_resp.status_code in (200, 206):
                content_range = devices_resp.headers.get("content-range", "")
                if "/" in content_range:
                    total = content_range.rsplit("/", 1)[-1]
                    if total.isdigit():
                        devices_count = int(total)

            if isinstance(user_resp, httpx.Response) and user_resp.status_code == 200:
                rows = user_resp.json()
                if rows and rows[0].get("created_at"):
                    member_since = rows[0]["created_at"]
        except Exception as e:
            logger.warning("profile_fetch_error", extra={"error": str(e)})

    return ProfileResponse(
        id=user.id,
        email=user.email,
        tier=user.tier.value,
        devices=devices_count,
        member_since=member_since,
    )


# ═══════════════════════════════════════════════════════════════════
# Pricing v2: 50-threat freemium counter + detail gating
# ═══════════════════════════════════════════════════════════════════
#
# Block UI is FREE FOREVER. Every blocked threat protects the user
# regardless of subscription state — that is the ethical baseline.
#
# What's gated for free users past the threshold:
#   - "Why this is dangerous" detail panel
#   - Domain history / scheme breakdown
#   - Annotated page screenshot
#
# Server tracks the lifetime counter so the gating decision survives
# extension reinstalls and works across devices for the same account.

async def _fetch_threat_row(
    user_id: str,
    *,
    base_url: str,
    service_key: str,
) -> dict:
    """Read threats_blocked_lifetime + nudge fields. Empty dict if none."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"{base_url}/rest/v1/user_settings",
            params={
                "user_id": f"eq.{user_id}",
                "select": "threats_blocked_lifetime,threshold_nudge_shown_at,threshold_nudge_count",
            },
            headers={
                "apikey": service_key,
                "Authorization": f"Bearer {service_key}",
            },
        )
    if resp.status_code != 200:
        logger.warning("threat_row_fetch_failed", extra={"status": resp.status_code})
        return {}
    rows = resp.json()
    return rows[0] if rows else {}


@router.get(
    "/threats/status",
    response_model=ThreatStatus,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def get_threat_status(user: AuthUser = Depends(get_current_user)) -> ThreatStatus:
    """Return blocked-threats counter + freemium gating decision."""
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Degraded mode — return zeroed counter; gating disabled until DB recovers.
        return ThreatStatus(tier=user.tier.value)

    row = await _fetch_threat_row(
        user.id,
        base_url=settings.supabase_url,
        service_key=settings.supabase_service_key,
    )
    counter = int(row.get("threats_blocked_lifetime") or 0)
    return ThreatStatus(
        threats_blocked_lifetime=counter,
        gated=_is_gated(user.tier.value, counter),
        tier=user.tier.value,
        nudge_shown_at=row.get("threshold_nudge_shown_at"),
        nudge_count=int(row.get("threshold_nudge_count") or 0),
    )


@router.post(
    "/threats/increment",
    response_model=ThreatStatus,
    dependencies=[Depends(rate_limit(category="user_write"))],
)
async def increment_threats(
    body: IncrementThreatsRequest,
    user: AuthUser = Depends(get_current_user),
) -> ThreatStatus:
    """
    Add `body.count` to the lifetime threat counter and return new state.

    On the FIRST crossing of the gating threshold for a free user, set
    `threshold_nudge_shown_at` so the client can decide cadence for showing
    the upsell nudge. We do not bump nudge_count here — that's the client's
    responsibility once it actually renders the nudge UI.
    """
    import httpx

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(503, "User settings storage unavailable")

    # Read current state to compute first-crossing transition
    row = await _fetch_threat_row(
        user.id,
        base_url=settings.supabase_url,
        service_key=settings.supabase_service_key,
    )
    prev_counter = int(row.get("threats_blocked_lifetime") or 0)
    new_counter = prev_counter + body.count
    nudge_shown_at = row.get("threshold_nudge_shown_at")
    crossed_now = (
        prev_counter < FREEMIUM_DETAIL_GATING_THRESHOLD
        and new_counter >= FREEMIUM_DETAIL_GATING_THRESHOLD
        and user.tier.value == "free"
    )
    if crossed_now and not nudge_shown_at:
        nudge_shown_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "user_id": user.id,
        "threats_blocked_lifetime": new_counter,
        "threshold_nudge_shown_at": nudge_shown_at,
        "threshold_nudge_count": int(row.get("threshold_nudge_count") or 0),
    }
    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=minimal",
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{settings.supabase_url}/rest/v1/user_settings",
            headers=headers,
            json=payload,
        )

    if resp.status_code not in (200, 201, 204):
        logger.warning(
            "threat_counter_persist_failed",
            extra={"status": resp.status_code, "user_id": user.id},
        )
        raise HTTPException(500, "Failed to persist threat counter")

    return ThreatStatus(
        threats_blocked_lifetime=new_counter,
        gated=_is_gated(user.tier.value, new_counter),
        tier=user.tier.value,
        nudge_shown_at=nudge_shown_at,
        nudge_count=int(row.get("threshold_nudge_count") or 0),
    )


# ═══════════════════════════════════════════════════════════════════
# Skill Levels — device override + effective resolution
# ═══════════════════════════════════════════════════════════════════
#
# Two layers in the schema (migration 003 + 004):
#   users.skill_level / .voice_alerts_enabled / .font_scale  ← user default
#   devices.skill_level_override / .voice_alerts_enabled / .font_scale  ← per-device override
#
# Family Hub use case: an admin enables Granny Mode on grandmother's
# specific phone without changing her own account-level default. The
# extension/mobile client reads /effective to know which mode to render.


async def _fetch_user_skill_defaults(
    user_id: str,
    *,
    base_url: str,
    service_key: str,
) -> dict:
    """Read user-level skill + accessibility defaults from `users` table."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"{base_url}/rest/v1/users",
            params={
                "id": f"eq.{user_id}",
                "select": "skill_level,voice_alerts_enabled,font_scale",
            },
            headers={
                "apikey": service_key,
                "Authorization": f"Bearer {service_key}",
            },
        )
    if resp.status_code != 200:
        return {}
    rows = resp.json()
    return rows[0] if rows else {}


async def _fetch_device_overrides(
    user_id: str,
    device_hash: str,
    *,
    base_url: str,
    service_key: str,
) -> dict:
    """Read device-level overrides from `devices` table.

    Filters on (user_id, device_hash) so a stolen device hash from another
    account can't be used to read a foreign user's overrides.
    """
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"{base_url}/rest/v1/devices",
            params={
                "user_id": f"eq.{user_id}",
                "device_hash": f"eq.{device_hash}",
                "select": "skill_level_override,voice_alerts_enabled,font_scale",
            },
            headers={
                "apikey": service_key,
                "Authorization": f"Bearer {service_key}",
            },
        )
    if resp.status_code != 200:
        return {}
    rows = resp.json()
    return rows[0] if rows else {}


@router.get(
    "/device/{device_hash}/effective",
    response_model=EffectiveSkillResponse,
    dependencies=[Depends(rate_limit(category="user_read"))],
)
async def get_effective_skill(
    device_hash: str,
    user: AuthUser = Depends(get_current_user),
) -> EffectiveSkillResponse:
    """Resolve effective skill level + accessibility for this device.

    Device-level override wins; falls back to user-level default. Used by
    extension and mobile clients to know which UX mode to render.
    """
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Degraded — return safe defaults
        return EffectiveSkillResponse(
            device_hash=device_hash,
            skill_level=SkillLevel.regular,
            voice_alerts_enabled=False,
            font_scale=1.0,
            skill_source="user_default",
            voice_source="user_default",
            font_source="user_default",
        )

    user_row = await _fetch_user_skill_defaults(
        user.id,
        base_url=settings.supabase_url,
        service_key=settings.supabase_service_key,
    )
    device_row = await _fetch_device_overrides(
        user.id,
        device_hash,
        base_url=settings.supabase_url,
        service_key=settings.supabase_service_key,
    )

    user_skill = SkillLevel(user_row.get("skill_level") or "regular")
    user_voice = bool(user_row.get("voice_alerts_enabled", False))
    user_font = float(user_row.get("font_scale") or 1.0)

    skill_override = device_row.get("skill_level_override")
    voice_override = device_row.get("voice_alerts_enabled")
    font_override = device_row.get("font_scale")

    skill = SkillLevel(skill_override) if skill_override else user_skill
    skill_source: Literal["device_override", "user_default"] = (
        "device_override" if skill_override else "user_default"
    )
    voice = bool(voice_override) if voice_override is not None else user_voice
    voice_source: Literal["device_override", "user_default"] = (
        "device_override" if voice_override is not None else "user_default"
    )
    font = float(font_override) if font_override is not None else user_font
    font_source: Literal["device_override", "user_default"] = (
        "device_override" if font_override is not None else "user_default"
    )

    return EffectiveSkillResponse(
        device_hash=device_hash,
        skill_level=skill,
        voice_alerts_enabled=voice,
        font_scale=font,
        skill_source=skill_source,
        voice_source=voice_source,
        font_source=font_source,
    )


@router.patch(
    "/device/{device_hash}/overrides",
    response_model=EffectiveSkillResponse,
    dependencies=[Depends(rate_limit(category="user_write"))],
)
async def update_device_overrides(
    device_hash: str,
    body: DeviceOverrideUpdate,
    user: AuthUser = Depends(get_current_user),
) -> EffectiveSkillResponse:
    """Set or clear device-level overrides for this user's device.

    Validates font_scale 0.8..2.5 (matches DB CHECK constraint). Authorization
    is implicit: we filter on (user_id=user.id, device_hash) so a user can
    only change their own devices' overrides. Family Hub admin operations
    on a family member's device go through the family router (TODO).
    """
    if body.font_scale is not None and not 0.8 <= body.font_scale <= 2.5:
        raise HTTPException(422, "font_scale must be between 0.8 and 2.5")

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(503, "Device storage unavailable")

    payload: dict = {}
    if body.clear_overrides:
        payload = {
            "skill_level_override": None,
            "voice_alerts_enabled": False,
            "font_scale": 1.0,
        }
    else:
        if body.skill_level_override is not None:
            payload["skill_level_override"] = body.skill_level_override.value
        if body.voice_alerts_enabled is not None:
            payload["voice_alerts_enabled"] = body.voice_alerts_enabled
        if body.font_scale is not None:
            payload["font_scale"] = body.font_scale

    if not payload:
        # Nothing to write — return current effective state
        return await get_effective_skill(device_hash, user)

    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.patch(
            f"{settings.supabase_url}/rest/v1/devices",
            params={
                "user_id": f"eq.{user.id}",
                "device_hash": f"eq.{device_hash}",
            },
            json=payload,
            headers={
                "apikey": settings.supabase_service_key,
                "Authorization": f"Bearer {settings.supabase_service_key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
        )
    if resp.status_code not in (200, 204):
        logger.warning(
            "device_overrides_update_failed",
            extra={"status": resp.status_code, "user_id": user.id},
        )
        raise HTTPException(500, "Failed to persist device overrides")

    # Re-resolve to return canonical effective state
    return await get_effective_skill(device_hash, user)
