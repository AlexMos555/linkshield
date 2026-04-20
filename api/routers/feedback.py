"""
User feedback endpoints.

  POST /api/v1/feedback/report — report false positive/negative
  POST /api/v1/feedback/whitelist — add domain to personal whitelist
  DELETE /api/v1/feedback/whitelist — remove domain from whitelist
  GET /api/v1/feedback/whitelist — get user's whitelist
"""

from __future__ import annotations

import logging
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.models.schemas import AuthUser
from api.config import get_settings

logger = logging.getLogger("linkshield.feedback")

router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])


class ReportRequest(BaseModel):
    domain: str
    report_type: str = Field(..., description="false_positive or false_negative")
    current_score: Optional[int] = None
    comment: Optional[str] = Field(None, max_length=500)


class WhitelistRequest(BaseModel):
    domain: str


@router.post("/report", dependencies=[Depends(rate_limit(category="feedback_report"))])
async def report_domain(
    request: ReportRequest,
    user: AuthUser = Depends(get_current_user),
):
    """
    Report a false positive (safe site flagged) or false negative (phishing not caught).
    Stored for ML model retraining and manual review.
    """
    if request.report_type not in ("false_positive", "false_negative"):
        raise HTTPException(400, "report_type must be 'false_positive' or 'false_negative'")

    # Store in Supabase (if configured) or log
    import httpx
    settings = get_settings()

    logger.info("domain_reported", extra={
        "domain": request.domain,
        "type": request.report_type,
        "score": request.current_score,
        "user_id": user.id,
    })

    if settings.supabase_url and settings.supabase_service_key:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{settings.supabase_url}/rest/v1/feedback_reports",
                    headers={
                        "apikey": settings.supabase_service_key,
                        "Authorization": f"Bearer {settings.supabase_service_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "user_id": user.id,
                        "domain": request.domain,
                        "report_type": request.report_type,
                        "score_at_report": request.current_score,
                        "comment": request.comment,
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
        except Exception as e:
            logger.warning("feedback_store_error", extra={"error": str(e)})

    return {"status": "ok", "message": "Thank you for your report. We review all submissions."}


@router.post("/whitelist", dependencies=[Depends(rate_limit(category="feedback_write"))])
async def add_to_whitelist(
    request: WhitelistRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Add a domain to user's personal whitelist (always marked safe)."""
    from api.services.cache import get_redis

    domain = request.domain.lower().strip()

    try:
        r = await get_redis()
        key = f"whitelist:{user.id}"
        await r.sadd(key, domain)
        await r.expire(key, 86400 * 365)  # 1 year TTL
    except Exception:
        pass  # Store in extension storage as fallback

    logger.info("whitelist_add", extra={"user_id": user.id, "domain": domain})
    return {"status": "ok", "domain": domain}


@router.delete("/whitelist", dependencies=[Depends(rate_limit(category="feedback_write"))])
async def remove_from_whitelist(
    request: WhitelistRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Remove domain from personal whitelist."""
    from api.services.cache import get_redis

    domain = request.domain.lower().strip()

    try:
        r = await get_redis()
        await r.srem(f"whitelist:{user.id}", domain)
    except Exception:
        pass

    return {"status": "ok", "domain": domain}


@router.get("/whitelist", dependencies=[Depends(rate_limit(category="user_read"))])
async def get_whitelist(user: AuthUser = Depends(get_current_user)):
    """Get user's personal whitelist."""
    from api.services.cache import get_redis

    try:
        r = await get_redis()
        domains = await r.smembers(f"whitelist:{user.id}")
        return {"domains": list(domains)}
    except Exception:
        return {"domains": []}
