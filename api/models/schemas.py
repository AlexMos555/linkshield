from pydantic import BaseModel, Field, StringConstraints
from enum import Enum
from typing import Annotated, Optional


class RiskLevel(str, Enum):
    safe = "safe"
    caution = "caution"
    dangerous = "dangerous"


class ConfidenceLevel(str, Enum):
    high = "high"      # All external APIs responded + domain age known
    medium = "medium"  # 3-4 APIs responded
    low = "low"        # <3 APIs or very limited data


# Per-element string cap: RFC 1035 limits a full DNS name to 253 chars.
# Anything longer is invalid by spec, but without this cap the outer
# list cap (max 50 entries) alone allows ~10 MB total payload by
# stuffing one 10 MB string in. validate_domain() would later reject
# it, but Pydantic deserialization + a downstream `set()`/normalize
# pass already burn worker CPU before we get there.
DomainStr = Annotated[str, StringConstraints(max_length=253)]


class CheckRequest(BaseModel):
    domains: list[DomainStr] = Field(..., min_length=1, max_length=50, description="Domains to check")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"domains": ["google.com", "paypa1-verify.tk"]},
            ]
        }
    }


class DomainReason(BaseModel):
    signal: str
    detail: str
    weight: int


class DomainResult(BaseModel):
    domain: str
    score: int = Field(..., ge=0, le=100)
    level: RiskLevel
    confidence: ConfidenceLevel = ConfidenceLevel.medium
    # Strategy doc Top-20 #12 — conformal-style confidence band.
    # 50-99 integer; never 100 (we never claim absolute certainty)
    # and never below 50 (any verdict we return has at least basic
    # signal). Display verbatim in UI ("Confidence: 92%"). The
    # categorical `confidence` field above is derived from this.
    confidence_pct: int = Field(75, ge=50, le=99)
    reasons: list[DomainReason]
    domain_age_days: Optional[int] = None
    has_ssl: Optional[bool] = None
    ssl_issuer: Optional[str] = None
    cached: bool = False


class CheckResponse(BaseModel):
    results: list[DomainResult]
    checked_at: str
    api_calls_remaining: Optional[int] = None


class HealthResponse(BaseModel):
    status: str = "ok"  # "ok" or "degraded"
    # The /health handler overrides this with api.__version__. Default
    # is just for OpenAPI examples and Pydantic instantiation.
    version: str = "0.1.0"


class UserTier(str, Enum):
    free = "free"
    personal = "personal"
    family = "family"
    business = "business"


class SkillLevel(str, Enum):
    """
    Skill levels segment UX — one app, four very different presentations.

    - `kids`   — simplified, parental-controlled, stricter blocking
    - `regular` — default adult UX
    - `granny` — accessibility focus (large fonts, voice alerts, red/green only)
    - `pro`    — technical details (raw scores, threat types, headers)
    """

    kids = "kids"
    regular = "regular"
    granny = "granny"
    pro = "pro"


class UserSettings(BaseModel):
    """User-scoped preferences that sync across devices."""

    skill_level: SkillLevel = SkillLevel.regular
    preferred_locale: str = "en"
    voice_alerts_enabled: bool = False
    font_scale: float = 1.0
    parental_pin_set: bool = False  # read-only flag; PIN itself never returned

    class Config:
        json_schema_extra = {
            "example": {
                "skill_level": "regular",
                "preferred_locale": "en",
                "voice_alerts_enabled": False,
                "font_scale": 1.0,
                "parental_pin_set": False,
            }
        }


class UserSettingsUpdate(BaseModel):
    """Partial update — all fields optional so clients can PATCH individually."""

    skill_level: Optional[SkillLevel] = None
    preferred_locale: Optional[str] = None
    voice_alerts_enabled: Optional[bool] = None
    font_scale: Optional[float] = None
    # When present, a new 4-digit PIN for Kids Mode (hashed server-side).
    # Set to empty string "" to clear.
    parental_pin: Optional[str] = None


class AuthUser(BaseModel):
    id: str
    email: Optional[str] = None
    tier: UserTier = UserTier.free
