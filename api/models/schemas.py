from pydantic import BaseModel, Field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    safe = "safe"
    caution = "caution"
    dangerous = "dangerous"


class ConfidenceLevel(str, Enum):
    high = "high"      # All external APIs responded + domain age known
    medium = "medium"  # 3-4 APIs responded
    low = "low"        # <3 APIs or very limited data


class CheckRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=50, description="Domains to check")

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
    version: str = "0.1.0"


class UserTier(str, Enum):
    free = "free"
    personal = "personal"
    family = "family"
    business = "business"


class AuthUser(BaseModel):
    id: str
    email: Optional[str] = None
    tier: UserTier = UserTier.free
