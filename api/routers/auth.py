"""Public auth helpers — runs BEFORE the user has a session.

Right now this surface holds one endpoint: a pre-signup check that
flags disposable email domains so the landing form can refuse the
submission before calling Supabase Auth. The Supabase Auth API itself
is reachable directly with our public anon key, so this is
defense-in-depth — it catches the noisy 90% of bot signups that go
through our normal UI without changing the actual auth flow.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator

from api.services.email_validator import is_disposable_email
from api.services.rate_limiter import rate_limit

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Lightweight RFC-5322-flavoured shape check. We deliberately don't
# reach for pydantic.EmailStr (would force `email-validator` as a
# dependency for a 5-line check) — full RFC parsing is overkill for a
# pre-signup gate; Supabase Auth will do the authoritative check at
# magic-link time. This regex catches the "user typed garbage" case.
_EMAIL_SHAPE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")


class CheckEmailRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _looks_like_email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_SHAPE.match(v):
            raise ValueError("malformed email address")
        if len(v) > 320:  # RFC 5321 max
            raise ValueError("email too long")
        return v


class CheckEmailResponse(BaseModel):
    disposable: bool
    # Echoed back so the client UI can show "<domain>.com isn't allowed"
    # without re-parsing the email itself. Lower-cased to match the
    # blocklist's normalised form.
    domain: str


@router.post(
    "/check-email",
    response_model=CheckEmailResponse,
    # IP rate limit — this endpoint is unauthenticated by design (it
    # runs pre-signup). public_check category: 60/hr/IP. A bot could
    # theoretically iterate over a list of throwaway domains to find
    # one we don't block, but at 60/hr that's a non-starter.
    dependencies=[Depends(rate_limit(mode="ip", category="public_check"))],
)
async def check_email(body: CheckEmailRequest) -> CheckEmailResponse:
    domain = body.email.rsplit("@", 1)[1].lower()
    return CheckEmailResponse(
        disposable=is_disposable_email(body.email),
        domain=domain,
    )
