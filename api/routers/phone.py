"""
/api/v1/phone/* — caller ID and crowd-sourced scam reporting (Phase H₁ / H₂).

The client computes `SHA-256(normalizeE164(number, country))` and submits
only the hash. We never see the plaintext number, and we never return one
for reports — but we DO return plaintext numbers for verified-legitimate
entries since those are publicly known (bank "contact us" pages, etc.).

Endpoints:
- ``POST /phone/report``  — user-initiated scam/spam/legit report
- ``GET  /phone/lookup/{hash}``  — caller-ID pre-answer check
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.config import get_settings
from api.models.schemas import AuthUser
from api.services.auth import get_current_user, get_optional_user
from api.services.rate_limiter import rate_limit

logger = logging.getLogger("linkshield.phone")

router = APIRouter(prefix="/api/v1/phone", tags=["phone"])

# Fixed enum of report tags so the client UI + backend agree on vocabulary.
ALLOWED_TAGS = frozenset(
    {
        "bank_fraud",
        "investment_scam",
        "government_impersonation",
        "tech_support_scam",
        "romance_scam",
        "delivery_scam",
        "job_scam",
        "lottery_scam",
        "tax_scam",
        "robocall_spam",
        "telemarketer",
        "other",
    }
)

_HASH_RE_LEN = 64  # SHA-256 hex length


# ─── Schemas ──────────────────────────────────────────────────────────────────


class PhoneReport(BaseModel):
    phone_hash: str = Field(..., min_length=_HASH_RE_LEN, max_length=_HASH_RE_LEN)
    country_code: str = Field(..., min_length=2, max_length=2)
    kind: str = Field(..., description="scam | spam | legit")
    tag: Optional[str] = None


class PhoneLookupTag(BaseModel):
    name: str
    count: int


class PhoneLookupResponse(BaseModel):
    known: bool
    verdict: str = Field(
        ...,
        description=(
            "'verified_legit' | 'scam' | 'spam' | 'legit' | 'unknown' — "
            "the strongest signal we have."
        ),
    )
    # For verified numbers only: full org metadata.
    org_name: Optional[str] = None
    org_category: Optional[str] = None
    # For crowd-sourced entries: report counts + top tags.
    scam_count: int = 0
    spam_count: int = 0
    legit_count: int = 0
    top_tags: list[PhoneLookupTag] = []


# ─── Handlers ────────────────────────────────────────────────────────────────


@router.post(
    "/report",
    dependencies=[Depends(rate_limit(category="phone_report"))],
)
async def report_phone(
    payload: PhoneReport,
    user: AuthUser = Depends(get_current_user),
) -> dict:
    """
    Record a scam/spam/legit report against a hashed phone number.

    Auth required — we throttle per user, which prevents the most common
    mass-poisoning attack on crowd-sourced number databases.
    """
    if payload.kind not in ("scam", "spam", "legit"):
        raise HTTPException(status_code=422, detail="kind must be scam|spam|legit")
    if payload.tag is not None and payload.tag not in ALLOWED_TAGS:
        raise HTTPException(status_code=422, detail=f"Unknown tag. Allowed: {sorted(ALLOWED_TAGS)}")

    _, _ = user, _validate_hash(payload.phone_hash)  # typing assertions

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Degraded mode — accept silently so the client doesn't crash, but log.
        logger.warning(
            "phone_report_degraded", extra={"user_id": user.id, "kind": payload.kind}
        )
        return {"accepted": False, "reason": "storage_unavailable"}

    import httpx

    body = {
        "p_hash": payload.phone_hash.lower(),
        "p_country": payload.country_code.upper(),
        "p_kind": payload.kind,
        "p_tag": payload.tag,
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            f"{settings.supabase_url}/rest/v1/rpc/report_phone",
            json=body,
            headers={
                "apikey": settings.supabase_service_key,
                "Authorization": f"Bearer {settings.supabase_service_key}",
                "Content-Type": "application/json",
            },
        )
    if resp.status_code not in (200, 204):
        logger.warning(
            "phone_report_rpc_failed",
            extra={"status": resp.status_code, "user_id": user.id},
        )
        raise HTTPException(status_code=502, detail="Upstream storage rejected the report")

    return {"accepted": True}


@router.get(
    "/lookup/{phone_hash}",
    response_model=PhoneLookupResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="phone_lookup"))],
)
async def lookup_phone(
    phone_hash: str,
    cc: str = "",
    _user: Optional[AuthUser] = Depends(get_optional_user),
) -> PhoneLookupResponse:
    """
    Caller-ID pre-answer check. Public — IP-rate-limited. Returns the
    strongest signal we have:

    - `verified_legit` — this hash is in `verified_numbers` for `cc`.
      The response carries the org name + category so the native phone UI
      can show "📞 Sberbank (bank)".
    - `scam` / `spam` — 3+ reports of that kind dominate the counts.
    - `legit` — opposite: legitimate reports outweigh.
    - `unknown` — no data; native UI shows no badge.
    """
    _validate_hash(phone_hash)
    country = cc.upper() if cc else ""
    if country and (len(country) != 2 or not country.isalpha()):
        raise HTTPException(status_code=422, detail="cc must be a 2-letter ISO code")

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return PhoneLookupResponse(known=False, verdict="unknown")

    import httpx

    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
    }

    async with httpx.AsyncClient(timeout=5.0) as client:
        # 1. Verified legit — highest priority; short-circuits.
        if country:
            vr = await client.get(
                f"{settings.supabase_url}/rest/v1/verified_numbers",
                params={
                    "phone_hash": f"eq.{phone_hash.lower()}",
                    "country_code": f"eq.{country}",
                    "active": "eq.true",
                    "select": "org_name,org_category,display_number",
                },
                headers=headers,
            )
            if vr.status_code == 200 and (rows := vr.json()):
                row = rows[0]
                return PhoneLookupResponse(
                    known=True,
                    verdict="verified_legit",
                    org_name=row.get("org_name"),
                    org_category=row.get("org_category"),
                )

        # 2. Crowd-sourced report counts.
        params = {
            "phone_hash": f"eq.{phone_hash.lower()}",
            "select": "scam_count,spam_count,legit_count,tags",
        }
        if country:
            params["country_code"] = f"eq.{country}"
        pr = await client.get(
            f"{settings.supabase_url}/rest/v1/phone_reports",
            params=params,
            headers=headers,
        )
        if pr.status_code != 200 or not (rows := pr.json()):
            return PhoneLookupResponse(known=False, verdict="unknown")

        row = rows[0]
        scam = int(row.get("scam_count") or 0)
        spam = int(row.get("spam_count") or 0)
        legit = int(row.get("legit_count") or 0)
        tags_dict = row.get("tags") or {}

        verdict = _verdict_for_counts(scam, spam, legit)
        top_tags = [
            PhoneLookupTag(name=name, count=int(count))
            for name, count in sorted(
                tags_dict.items(), key=lambda kv: int(kv[1]), reverse=True
            )[:3]
        ]
        return PhoneLookupResponse(
            known=True,
            verdict=verdict,
            scam_count=scam,
            spam_count=spam,
            legit_count=legit,
            top_tags=top_tags,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _validate_hash(h: str) -> None:
    if len(h) != _HASH_RE_LEN or not all(c in "0123456789abcdefABCDEF" for c in h):
        raise HTTPException(status_code=422, detail="phone_hash must be SHA-256 hex")


def _verdict_for_counts(scam: int, spam: int, legit: int) -> str:
    """
    Return the strongest verdict for a hash given its raw report counts.

    Weighting:
    - A scam report is worth more than spam (they're qualitatively different —
      spam is annoying, scam is dangerous).
    - 3 reports is our minimum-confidence threshold; below that we return
      "unknown" so the client UI doesn't show alarming badges based on a
      single angry user.
    """
    total = scam + spam + legit
    if total < 3:
        return "unknown"
    if scam * 2 >= spam + legit:
        return "scam"
    if spam >= scam + legit:
        return "spam"
    if legit >= scam + spam:
        return "legit"
    return "unknown"
