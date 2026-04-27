"""
Referral System.

  POST /api/v1/referral/generate — generate unique referral code (idempotent)
  GET  /api/v1/referral/stats    — get referral stats for current user
  POST /api/v1/referral/redeem   — redeem a referral code (7-day Personal credit)

Flow:
  1. User A generates referral link: cleanway.ai/ref/ABC123
  2. User B clicks link and installs extension
  3. User B redeems code → gets 7 days credit toward Personal plan
  4. User A also gets 7 days credit added to their balance

Where credits live:
  - Redis stores the code → owner mapping + redeemed_count for fast reads
  - Supabase user_settings.settings.referral_credit_days holds the actual
    grant per user. When Stripe checkout is wired, the checkout flow
    reads + decrements this balance toward the trial extension.

Self-redeem and double-redeem are blocked. Code generation is deterministic
from user_id, so the same user always gets the same 8-char code.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.models.schemas import AuthUser
from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit

logger = logging.getLogger("cleanway.referral")

router = APIRouter(prefix="/api/v1/referral", tags=["referral"])

REFERRAL_TRIAL_DAYS = 7
REFERRAL_CODE_TTL_SECONDS = 86400 * 365  # 1 year


class RedeemRequest(BaseModel):
    code: str


def _code_for(user_id: str, email: Optional[str]) -> str:
    """Derive a deterministic 8-char referral code for a user.

    Same user_id+email always maps to the same code, so /generate is
    naturally idempotent and clients can show the same link across
    sessions without us persisting it anywhere.
    """
    raw = f"ls-ref-{user_id}-{email or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


async def _grant_credit_days(user_id: str, days: int) -> None:
    """Add `days` to user_settings.settings.referral_credit_days in Supabase.

    Read-then-merge upsert preserves any other settings keys (theme,
    weekly_report, email_optout, etc.). Best-effort: a Supabase outage
    logs a warning but never raises — the redeem flow still succeeds
    in Redis, and operators can reconcile from logs.
    """
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    service_key = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
    if not supabase_url or not service_key:
        logger.warning(
            "referral.grant_skipped_no_supabase",
            extra={"user_id": user_id, "days": days},
        )
        return

    import httpx

    headers = {
        "apikey": service_key,
        "Authorization": f"Bearer {service_key}",
    }
    timeout = httpx.Timeout(5.0)

    current_settings: dict = {}
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{supabase_url}/rest/v1/user_settings",
                params={"user_id": f"eq.{user_id}", "select": "settings"},
                headers=headers,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if rows and isinstance(rows[0].get("settings"), dict):
                    current_settings = rows[0]["settings"]
    except Exception as e:  # pragma: no cover — network failure path
        logger.warning(
            "referral.grant_read_failed",
            extra={"user_id": user_id, "error": str(e)},
        )

    existing_days = int(current_settings.get("referral_credit_days") or 0)
    merged = {**current_settings, "referral_credit_days": existing_days + days}

    write_headers = {
        **headers,
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=minimal",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{supabase_url}/rest/v1/user_settings",
                json={"user_id": user_id, "settings": merged},
                headers=write_headers,
            )
        if resp.status_code not in (200, 201, 204):
            logger.warning(
                "referral.grant_persist_failed",
                extra={
                    "user_id": user_id,
                    "days": days,
                    "status": resp.status_code,
                },
            )
    except Exception as e:  # pragma: no cover — network failure path
        logger.warning(
            "referral.grant_persist_exception",
            extra={"user_id": user_id, "days": days, "error": str(e)},
        )


@router.post("/generate", dependencies=[Depends(rate_limit(category="user_write"))])
async def generate_referral(user: AuthUser = Depends(get_current_user)):
    """Generate (or fetch existing) referral code for the user.

    Idempotent: same user → same code. We upsert the Redis mapping so the
    code → owner record exists for redeem-time lookups.
    """
    code = _code_for(user.id, user.email)

    # Best-effort Redis upsert — a Redis outage shouldn't block the user
    # from seeing their referral link (it's deterministic, derives from id).
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        if r is not None:
            key = f"referral:{code}"
            existing = await r.get(key)
            if not existing:
                await r.set(
                    key,
                    json.dumps(
                        {
                            "owner_id": user.id,
                            "created": datetime.now(timezone.utc).isoformat(),
                            "redeemed_count": 0,
                        }
                    ),
                )
                await r.expire(key, REFERRAL_CODE_TTL_SECONDS)
    except Exception as e:
        logger.warning("referral.generate_redis_failed", extra={"error": str(e)})

    return {
        "code": code,
        "url": f"https://cleanway.ai/ref/{code}",
        "reward": (
            f"Both you and your friend get {REFERRAL_TRIAL_DAYS} days "
            "of Personal plan free"
        ),
    }


@router.get("/stats", dependencies=[Depends(rate_limit(category="user_read"))])
async def referral_stats(user: AuthUser = Depends(get_current_user)):
    """Return the user's referral code, share URL, and redemption count."""
    code = _code_for(user.id, user.email)

    try:
        from api.services.cache import get_redis

        r = await get_redis()
        if r is not None:
            data = await r.get(f"referral:{code}")
            if data:
                info = json.loads(data)
                count = int(info.get("redeemed_count", 0))
                return {
                    "code": code,
                    "url": f"https://cleanway.ai/ref/{code}",
                    "redeemed_count": count,
                    "reward_days_earned": count * REFERRAL_TRIAL_DAYS,
                }
    except Exception as e:
        logger.warning("referral.stats_redis_failed", extra={"error": str(e)})

    return {
        "code": code,
        "url": f"https://cleanway.ai/ref/{code}",
        "redeemed_count": 0,
        "reward_days_earned": 0,
    }


@router.post(
    "/redeem",
    dependencies=[Depends(rate_limit(mode="sensitive", category="referral_redeem"))],
)
async def redeem_referral(
    request: RedeemRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Redeem a referral code. Grants 7 days credit to redeemer and referrer."""
    code = request.code.upper().strip()
    if not code:
        raise HTTPException(400, "Referral code required")

    from api.services.cache import get_redis

    try:
        r = await get_redis()
    except Exception as e:
        logger.error("referral.redeem_redis_unavailable", extra={"error": str(e)})
        raise HTTPException(503, "Referral service temporarily unavailable") from e

    if r is None:
        raise HTTPException(503, "Referral service temporarily unavailable")

    key = f"referral:{code}"
    try:
        data = await r.get(key)
    except Exception as e:
        logger.error("referral.redeem_lookup_failed", extra={"error": str(e)})
        raise HTTPException(503, "Referral service temporarily unavailable") from e

    if not data:
        raise HTTPException(404, "Invalid referral code")

    try:
        info = json.loads(data)
    except (TypeError, ValueError):
        logger.error("referral.redeem_corrupt_record", extra={"code": code})
        raise HTTPException(500, "Failed to redeem code")

    owner_id = info.get("owner_id")
    if not owner_id:
        raise HTTPException(500, "Failed to redeem code")

    if owner_id == user.id:
        raise HTTPException(400, "Cannot redeem your own referral code")

    # One-shot per redeemer — prevent farming
    redeemer_marker = f"redeemed:{user.id}"
    try:
        already = await r.get(redeemer_marker)
    except Exception as e:
        logger.error("referral.redeem_dedup_check_failed", extra={"error": str(e)})
        raise HTTPException(503, "Referral service temporarily unavailable") from e

    if already:
        raise HTTPException(400, "You have already redeemed a referral code")

    # Increment redemption count + mark redeemer
    info["redeemed_count"] = int(info.get("redeemed_count", 0)) + 1
    try:
        await r.set(key, json.dumps(info))
        await r.set(redeemer_marker, code)
        await r.expire(redeemer_marker, REFERRAL_CODE_TTL_SECONDS)
    except Exception as e:
        logger.error("referral.redeem_persist_failed", extra={"error": str(e)})
        raise HTTPException(500, "Failed to redeem code") from e

    # Grant credit to BOTH parties — best-effort, no rollback if one fails.
    # The Redis bookkeeping is the source of truth for "this redeem happened";
    # Supabase reflects it for the future Stripe checkout to consume.
    await _grant_credit_days(user.id, REFERRAL_TRIAL_DAYS)
    await _grant_credit_days(owner_id, REFERRAL_TRIAL_DAYS)

    logger.info(
        "referral_redeemed",
        extra={"code": code, "redeemer": user.id, "owner": owner_id},
    )

    return {
        "status": "ok",
        "message": (
            f"Referral code redeemed! You got {REFERRAL_TRIAL_DAYS} days "
            "of Personal plan."
        ),
        "trial_days": REFERRAL_TRIAL_DAYS,
    }
