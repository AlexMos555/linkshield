"""
User-facing API endpoints.

  POST /api/v1/user/aggregates — submit weekly aggregate from device
  GET  /api/v1/user/percentile — get percentile ranking
  POST /api/v1/user/score — sync security score number
  GET  /api/v1/user/profile — get user profile + subscription info
  POST /api/v1/user/device — register/update device
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.services.auth import get_current_user
from api.models.schemas import AuthUser
from api.config import get_settings

logger = logging.getLogger("linkshield.user")

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


class ProfileResponse(BaseModel):
    id: str
    email: Optional[str]
    tier: str
    devices: int
    member_since: Optional[str]


# ── Endpoints ──

@router.post("/aggregates")
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


@router.get("/percentile", response_model=PercentileResponse)
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


@router.post("/score")
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


@router.post("/device")
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


@router.get("/profile", response_model=ProfileResponse)
async def get_profile(user: AuthUser = Depends(get_current_user)):
    """Get user profile info."""
    return ProfileResponse(
        id=user.id,
        email=user.email,
        tier=user.tier.value,
        devices=0,  # TODO: count from DB
        member_since=None,
    )
