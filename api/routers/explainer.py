"""Cultural explainer endpoint — Strategy doc Top-20 #15.

  POST /api/v1/explain
    Body: { signals: [str], locale: str }
    Response: { category, locale, explanation, source }

Anonymous + IP rate-limited. Privacy: the signal LIST is what
gets sent; no domain, no URL, no user identity ever leaves the
caller's request scope.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.services.rate_limiter import rate_limit
from api.services.scam_explainer import LOCALES, explain_scam

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["explainer"])


class ExplainRequest(BaseModel):
    # Cap the signal list so a malicious client can't fan us out
    # to a massive cache-key explosion. Real DomainResult tops out
    # at ~10 reasons.
    signals: list[str] = Field(default_factory=list, max_length=30)
    locale: str = Field("en", min_length=2, max_length=5)


class ExplainResponse(BaseModel):
    category: str
    locale: str
    explanation: str
    source: str  # "llm" | "template" | "cache"


@router.post(
    "/explain",
    response_model=ExplainResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="explainer"))],
)
async def explain_endpoint(body: ExplainRequest) -> ExplainResponse:
    # Validation at perimeter: locale must be one we support.
    locale = (body.locale or "en").lower()
    if locale not in LOCALES:
        # Don't reject — fall back to English. UX > strict contract.
        locale = "en"

    # Filter out empty / weird signals — keep what's actionable.
    clean_signals: list[str] = []
    for s in body.signals or []:
        if not isinstance(s, str):
            continue
        v = s.strip().lower()
        if not v or len(v) > 64:
            continue
        clean_signals.append(v)

    result = await explain_scam(clean_signals, locale)
    return ExplainResponse(**result)
