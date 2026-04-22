"""
/api/v1/email/* — inbound email phishing analysis.

Used by:
- Outlook Add-in (Office.js taskpane)
- Gmail content script (`packages/extension-core/src/content/gmail.js`)
- Future: Apple Mail extension, Thunderbird add-on, Maestro CLI

The endpoint is per-user rate-limited (same `rate_limit(category="user_write")`
used by other write-heavy actions). The response exposes the full structured
verdict so clients can render highlighted spans + per-finding explanations.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.models.schemas import AuthUser
from api.services.auth import get_current_user, get_optional_user  # noqa: F401
from api.services.email_analyzer import (
    AnalysisResult,
    EmailBody,
    EmailHeaders,
    analyze_email,
)
from api.services.rate_limiter import rate_limit
from api.services.safe_browsing import get_client as get_safe_browsing
from api.services.circuit_breaker import safe_browsing_breaker

logger = logging.getLogger("cleanway.email.analyze")

router = APIRouter(prefix="/api/v1/email", tags=["email"])


# ─── Schemas ──────────────────────────────────────────────────────────────────


class AnalyzeEmailRequest(BaseModel):
    from_address: str = Field("", description="RFC-5322 from address, e.g. security@chase.com")
    from_display: str = Field("", description="Display name, e.g. 'Chase Security'")
    reply_to: str = Field("", description="Reply-To address, if different from From")
    subject: str = Field("", description="Email subject line")
    return_path: str = Field("", description="Return-Path header value")
    spf: Optional[str] = Field(None, description="SPF result from Authentication-Results")
    dkim: Optional[str] = Field(None, description="DKIM result from Authentication-Results")
    dmarc: Optional[str] = Field(None, description="DMARC result from Authentication-Results")
    body_text: str = Field("", description="Plain-text body")
    body_html: str = Field("", description="HTML body (if available)")


class AnalyzeEmailResponse(BaseModel):
    level: str
    score: int
    findings: list[dict]
    links: list[dict]


# ─── Handler ──────────────────────────────────────────────────────────────────


@router.post(
    "/analyze",
    response_model=AnalyzeEmailResponse,
    # IP-rate-limited regardless of auth state so anonymous webmail banners
    # work on first page-load (before sign-in). Authenticated users are
    # additionally tallied against their daily quota via `rate_limit` below.
    dependencies=[
        Depends(rate_limit(mode="ip", category="email_analyze_public")),
    ],
)
async def analyze(
    payload: AnalyzeEmailRequest,
    user: Optional[AuthUser] = Depends(get_optional_user),
) -> AnalyzeEmailResponse:
    """
    Analyze a single inbound email for phishing markers. The client passes
    already-parsed header fields + body — we never ask for the raw MIME
    stream because
    (a) Outlook/Gmail clients already parse it for us, and
    (b) sending the full raw email would leak PII / internal headers into
        our logs.

    Both authenticated and anonymous callers are accepted. Anonymous calls
    are capped by per-IP rate limits; authenticated calls are additionally
    charged against the user's daily quota so abuse attribution stays
    possible.
    """
    headers = EmailHeaders(
        from_address=payload.from_address,
        from_display=payload.from_display,
        reply_to=payload.reply_to,
        subject=payload.subject,
        return_path=payload.return_path,
        spf=payload.spf,
        dkim=payload.dkim,
        dmarc=payload.dmarc,
    )
    body = EmailBody(text=payload.body_text, html=payload.body_html)

    gsb = get_safe_browsing()

    async def check_domain(domain: str) -> bool:
        """
        Thin adapter: delegate to the Safe Browsing client through the
        existing circuit breaker so repeated failures cool off without
        blocking the rest of the analysis.
        """
        result, _used_fallback = await safe_browsing_breaker.call(
            lambda d: _safe_browsing_is_threat(gsb, d), domain
        )
        return bool(result)

    result: AnalysisResult = await analyze_email(headers, body, check_domain)

    logger.info(
        "email_analyzed",
        extra={
            "user_id": user.id if user else "anon",
            "level": result.level.value,
            "score": result.score,
            "findings": len(result.findings),
            "links": len(result.links),
        },
    )

    # Authenticated users also consume a slot from their daily quota so
    # abusive flooders can be rate-shaped per account. Fail-open on
    # Redis/JWT hiccups.
    if user is not None:
        try:
            from api.services.rate_limiter import check_rate_limit

            await check_rate_limit(user, num_domains=1)
        except Exception as e:
            logger.debug("email_quota_charge_failed", extra={"error": str(e)})

    payload_out = result.to_dict()
    return AnalyzeEmailResponse(**payload_out)


async def _safe_browsing_is_threat(client, domain: str) -> bool:
    r = await client.check(domain)
    return r.is_threat
