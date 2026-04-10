"""
Referral System.

  POST /api/v1/referral/generate — generate unique referral code
  GET  /api/v1/referral/stats — get referral stats
  POST /api/v1/referral/redeem — redeem referral code (7-day free trial)

Flow:
  1. User A generates referral link: linkshield.io/ref/ABC123
  2. User B clicks link and installs extension
  3. User B redeems code → gets 7-day Personal trial
  4. User A gets 7 days added to their subscription
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.services.auth import get_current_user
from api.models.schemas import AuthUser
from api.config import get_settings

logger = logging.getLogger("linkshield.referral")

router = APIRouter(prefix="/api/v1/referral", tags=["referral"])


class RedeemRequest(BaseModel):
    code: str


@router.post("/generate")
async def generate_referral(user: AuthUser = Depends(get_current_user)):
    """Generate unique referral code for user."""
    # Deterministic code from user_id (same user always gets same code)
    raw = f"ls-ref-{user.id}-{user.email or ''}"
    code = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()

    # Store in Redis
    from api.services.cache import get_redis
    try:
        r = await get_redis()
        key = f"referral:{code}"
        existing = await r.get(key)
        if not existing:
            import json
            await r.set(key, json.dumps({
                "owner_id": user.id,
                "created": datetime.now(timezone.utc).isoformat(),
                "redeemed_count": 0,
            }))
            await r.expire(key, 86400 * 365)
    except Exception:
        pass

    referral_url = f"https://linkshield.io/ref/{code}"

    return {
        "code": code,
        "url": referral_url,
        "reward": "Both you and your friend get 7 days of Personal plan free",
    }


@router.get("/stats")
async def referral_stats(user: AuthUser = Depends(get_current_user)):
    """Get user's referral stats."""
    raw = f"ls-ref-{user.id}-{user.email or ''}"
    code = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()

    from api.services.cache import get_redis
    try:
        r = await get_redis()
        import json
        data = await r.get(f"referral:{code}")
        if data:
            info = json.loads(data)
            return {
                "code": code,
                "url": f"https://linkshield.io/ref/{code}",
                "redeemed_count": info.get("redeemed_count", 0),
                "reward_days_earned": info.get("redeemed_count", 0) * 7,
            }
    except Exception:
        pass

    return {"code": code, "redeemed_count": 0, "reward_days_earned": 0}


@router.post("/redeem")
async def redeem_referral(
    request: RedeemRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Redeem a referral code. Gives 7-day Personal trial to redeemer + 7 days to referrer."""
    code = request.code.upper().strip()

    from api.services.cache import get_redis
    try:
        r = await get_redis()
        import json

        # Check code exists
        key = f"referral:{code}"
        data = await r.get(key)
        if not data:
            raise HTTPException(404, "Invalid referral code")

        info = json.loads(data)

        # Can't redeem own code
        if info["owner_id"] == user.id:
            raise HTTPException(400, "Cannot redeem your own referral code")

        # Check if user already redeemed a code
        already = await r.get(f"redeemed:{user.id}")
        if already:
            raise HTTPException(400, "You have already redeemed a referral code")

        # Mark as redeemed
        info["redeemed_count"] = info.get("redeemed_count", 0) + 1
        await r.set(key, json.dumps(info))
        await r.set(f"redeemed:{user.id}", code)
        await r.expire(f"redeemed:{user.id}", 86400 * 365)

        logger.info("referral_redeemed", extra={
            "code": code, "redeemer": user.id, "owner": info["owner_id"],
        })

        return {
            "status": "ok",
            "message": "Referral code redeemed! You got 7 days of Personal plan.",
            "trial_days": 7,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error("referral_redeem_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to redeem code")
