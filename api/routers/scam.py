"""
/api/v1/scam/* — LLM-assisted scam pattern detection (Phase H₄).

Three input surfaces, one verdict format:
- ``POST /scam/analyze_text`` — pasted text (SMS/DM/email/transcript)
- ``POST /scam/analyze_voice`` — audio file (< 10 min, < 25 MB)
- ``POST /scam/analyze_image`` — screenshot (OCR then analyze)

The LLM integration is behind a thin ``ScamClassifier`` interface so the
route handler stays testable. The default implementation is a **stub** —
it uses the same body-pattern regex as the email analyzer — until we wire
an Anthropic API key + audio STT. Ship the API surface now, swap the
impl later without changing clients.

See ``docs/runbooks/phase-h-scam-protection.md`` for the full pipeline.
"""
from __future__ import annotations

import logging
import re
from typing import Optional, Protocol

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, Field

from api.models.schemas import AuthUser
from api.services.auth import get_current_user
from api.services.email_analyzer import ALL_BODY_PATTERNS, _aggregate_score, _level_for_score, Finding
from api.services.rate_limiter import rate_limit

logger = logging.getLogger("cleanway.scam")

router = APIRouter(prefix="/api/v1/scam", tags=["scam"])


# ─── Types ────────────────────────────────────────────────────────────────────


# Fixed enum — UI maps each code to a localized string so adding a
# language doesn't require a backend change.
REASON_CODES = frozenset(
    {
        "urgency",
        "credential_request",
        "money_request",
        "account_lock_threat",
        "impersonation_government",
        "impersonation_bank",
        "impersonation_delivery",
        "impersonation_tech_support",
        "romance_pattern",
        "investment_pattern",
        "job_pattern",
        "lottery_pattern",
        "crypto_pattern",
        "inheritance_pattern",
        "fake_link",
        "fake_invoice",
        "other",
    }
)

MAX_TEXT_CHARS = 10_000
MAX_VOICE_BYTES = 25 * 1024 * 1024  # 25 MB — matches Whisper's limit
ALLOWED_AUDIO_MIMES = frozenset(
    {
        "audio/mpeg",
        "audio/mp4",
        "audio/m4a",
        "audio/wav",
        "audio/x-wav",
        "audio/ogg",
        "audio/aac",
        "audio/3gpp",
        "audio/amr",
    }
)


class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., max_length=MAX_TEXT_CHARS)
    # Hint for the classifier — if omitted, auto-detected.
    language: Optional[str] = Field(None, min_length=2, max_length=2)
    # Where did the user paste this from? Tunes patterns (sms vs dm vs email).
    source: str = Field(
        "text_paste",
        description="text_paste | sms | email | screenshot | voice_file",
    )
    country_code: Optional[str] = Field(None, min_length=2, max_length=2)


class ScamVerdict(BaseModel):
    verdict: str  # safe | suspicious | scam
    risk_score: int  # 0–100
    reason_codes: list[str]
    language: Optional[str] = None
    summary: str = Field(
        "",
        description=(
            "One-sentence human-readable summary of why the classifier flagged it. "
            "Empty when verdict == safe."
        ),
    )


# ─── Classifier interface ────────────────────────────────────────────────────


class ScamClassifier(Protocol):
    async def classify(
        self,
        text: str,
        *,
        language: Optional[str],
        source: str,
        country: Optional[str],
    ) -> ScamVerdict: ...


class HeuristicClassifier:
    """
    MVP classifier — regex-only. Uses the same body pattern library as the
    email analyzer so the two surfaces stay consistent. Will be replaced
    by an LLM call once `ANTHROPIC_API_KEY` is provisioned, without
    changing the public interface.
    """

    _PATTERN_TO_REASON = {
        "Urgency language": "urgency",
        "Countdown pressure": "urgency",
        "Urgency (RU)": "urgency",
        "Requests credential verification": "credential_request",
        "Asks to confirm credentials": "credential_request",
        "Asks for credential entry": "credential_request",
        "Click-to-verify pattern": "fake_link",
        "Credential entry (RU)": "credential_request",
        "Money-transfer request": "money_request",
        "Advance-fee scam marker": "lottery_pattern",
        "Money request (RU)": "money_request",
        "Account-lock threat": "account_lock_threat",
        "Fake security alert": "account_lock_threat",
        "Account lock (RU)": "account_lock_threat",
    }

    # Additional scam patterns beyond the email/body set —
    # tuned for SMS / messenger text.
    _EXTRA_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
        (re.compile(r"\b(investment opportunity|guaranteed returns?|\d+% (daily|weekly) return)\b", re.I), 45, "investment_pattern"),
        (re.compile(r"\b(crypto|bitcoin|eth) (?:investment|trading|signals?)\b", re.I), 40, "crypto_pattern"),
        (re.compile(r"\b(work from home|earn \$?\d+ per (day|week)|no experience needed)\b", re.I), 30, "job_pattern"),
        (re.compile(r"\b(dear beloved|inheritance of|next of kin|million (dollars|usd|euros))\b", re.I), 45, "inheritance_pattern"),
        (re.compile(r"\b(package (cannot be|couldn't be) delivered|customs fee|redelivery)\b", re.I), 35, "impersonation_delivery"),
        (re.compile(r"\b(irs|internal revenue|hmrc|фнс|налогов)\b.*\b(debt|owe|pay)\b", re.I), 45, "impersonation_government"),
        (re.compile(r"\b(apple support|microsoft support|your (mac|pc|windows) is infected)\b", re.I), 45, "impersonation_tech_support"),
    ]

    async def classify(
        self,
        text: str,
        *,
        language: Optional[str],
        source: str,
        country: Optional[str],
    ) -> ScamVerdict:
        findings: list[Finding] = []
        reasons: set[str] = set()

        for pattern, severity, message in ALL_BODY_PATTERNS:
            if pattern.search(text):
                findings.append(Finding(category="body_pattern", severity=severity, message=message))
                reason = self._PATTERN_TO_REASON.get(message)
                if reason:
                    reasons.add(reason)

        for pattern, severity, reason_code in self._EXTRA_PATTERNS:
            if pattern.search(text):
                findings.append(Finding(category="scam_pattern", severity=severity, message=reason_code))
                reasons.add(reason_code)

        score = _aggregate_score(findings)
        level = _level_for_score(score)

        # `RiskLevel.dangerous` maps to "scam" on this surface — see
        # migration 005 where `scam_analyses.verdict` uses (safe|suspicious|scam).
        level_val = level.value if hasattr(level, "value") else str(level)
        verdict_str = "scam" if level_val == "dangerous" else level_val

        summary = ""
        if reasons and verdict_str != "safe":
            ordered = sorted(reasons)
            summary = (
                f"Matched {len(ordered)} scam pattern(s): {', '.join(ordered[:3])}."
            )

        return ScamVerdict(
            verdict=verdict_str,
            risk_score=score,
            reason_codes=sorted(reasons),
            language=language,
            summary=summary,
        )


# Default singleton — swap via FastAPI Depends override in tests.
_classifier: ScamClassifier = HeuristicClassifier()


def get_classifier() -> ScamClassifier:
    return _classifier


# ─── Handlers ────────────────────────────────────────────────────────────────


@router.post(
    "/analyze_text",
    response_model=ScamVerdict,
    dependencies=[Depends(rate_limit(category="scam_analyze_text"))],
)
async def analyze_text(
    payload: AnalyzeTextRequest,
    user: AuthUser = Depends(get_current_user),
    classifier: ScamClassifier = Depends(get_classifier),
) -> ScamVerdict:
    """
    Classify pasted text (SMS / DM / email / transcript) as scam or not.

    The user's raw text is NEVER persisted. Only the structured verdict
    + reason codes are written to `scam_analyses`.
    """
    if not payload.text.strip():
        raise HTTPException(status_code=422, detail="text must not be empty")

    verdict = await classifier.classify(
        payload.text,
        language=payload.language,
        source=payload.source,
        country=payload.country_code,
    )
    await _persist_analysis(user, payload.source, payload.country_code, verdict, size=len(payload.text.split()))
    return verdict


@router.post(
    "/analyze_voice",
    response_model=ScamVerdict,
    dependencies=[Depends(rate_limit(mode="sensitive", category="scam_analyze_voice"))],
)
async def analyze_voice(
    file: UploadFile = File(..., description="Audio file, ≤25MB, ≤10min"),
    language: Optional[str] = Form(None),
    country_code: Optional[str] = Form(None),
    user: AuthUser = Depends(get_current_user),
    classifier: ScamClassifier = Depends(get_classifier),
) -> ScamVerdict:
    """
    Transcribe a voice recording and classify the transcript.

    Current implementation is a **stub** until the Whisper integration
    lands (ANTHROPIC_API_KEY / OPENAI_API_KEY). Returns an explicit
    "transcription_pending" status so clients can render the right UX.
    """
    if file.content_type and file.content_type not in ALLOWED_AUDIO_MIMES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported audio type {file.content_type}. Accepted: {sorted(ALLOWED_AUDIO_MIMES)}",
        )

    # Enforce size at read time rather than trusting Content-Length
    blob = await file.read(MAX_VOICE_BYTES + 1)
    if len(blob) > MAX_VOICE_BYTES:
        raise HTTPException(status_code=413, detail=f"File too large (>{MAX_VOICE_BYTES} bytes)")
    if not blob:
        raise HTTPException(status_code=422, detail="Empty audio upload")

    # TODO(H₄): run Whisper on `blob` → transcript, then pass to classifier.
    # Until then, return an honest "pending" state so UIs can queue/retry.
    logger.info(
        "scam_voice_pending",
        extra={"user_id": user.id, "bytes": len(blob), "mime": file.content_type},
    )
    return ScamVerdict(
        verdict="suspicious",
        risk_score=50,
        reason_codes=["other"],
        language=language,
        summary="Voice transcription is pending — external STT service not yet configured.",
    )


# ─── Persistence ─────────────────────────────────────────────────────────────


async def _persist_analysis(
    user: AuthUser,
    source: str,
    country_code: Optional[str],
    verdict: ScamVerdict,
    size: int,
) -> None:
    """Best-effort write to `scam_analyses`. Never raises to the caller."""
    from api.config import get_settings

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return  # Degraded mode — accept classification but skip history write

    import httpx

    body = {
        "user_id": user.id,
        "source": source,
        "verdict": verdict.verdict,
        "risk_score": verdict.risk_score,
        "reason_codes": verdict.reason_codes,
        "language": verdict.language,
        "country_code": country_code,
        "input_size": size,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(
                f"{settings.supabase_url}/rest/v1/scam_analyses",
                json=body,
                headers={
                    "apikey": settings.supabase_service_key,
                    "Authorization": f"Bearer {settings.supabase_service_key}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
            )
    except Exception as e:
        logger.warning("scam_analysis_persist_failed", extra={"error": str(e)})
