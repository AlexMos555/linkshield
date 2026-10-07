"""Auth helpers around Supabase Auth.

- ``POST /check-email`` runs BEFORE the user has a session: a pre-signup
  check that flags disposable email domains so the landing form can refuse
  the submission before calling Supabase Auth. The Supabase Auth API itself
  is reachable directly with our public anon key, so this is
  defense-in-depth — it catches the noisy 90% of bot signups that go
  through our normal UI without changing the actual auth flow.
- ``POST /extension-session`` runs for a signed-in user on
  cleanway.ai/extension/connect: it opens a SECOND, independent Supabase
  session for the browser extension (see the endpoint's docstring for why
  the website's own session cannot simply be copied).
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, field_validator

from api.config import get_settings
from api.models.schemas import AuthUser
from api.services.auth import get_current_user
from api.services.email_validator import is_disposable_email
from api.services.rate_limiter import check_sensitive_action_limit, rate_limit

logger = logging.getLogger("cleanway.auth_router")

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


# ─── Extension sign-in: an independent session for the browser extension ───


class ExtensionSessionResponse(BaseModel):
    access_token: str
    refresh_token: str
    # Unix seconds, as Supabase reports it — the extension refreshes before it.
    expires_at: int


_SUPABASE_TIMEOUT_S = 5.0


def _hashed_token(link: dict[str, Any]) -> tuple[Optional[str], str]:
    """GoTrue's generate_link answer → (hashed_token, verification type).

    GoTrue returns the link properties at the top level next to the user's
    fields; supabase-js regroups them under ``properties``. Accept both.
    """
    props = link.get("properties") if isinstance(link.get("properties"), dict) else link
    token = props.get("hashed_token")
    vtype = props.get("verification_type") or "magiclink"
    return (token if isinstance(token, str) and token else None), str(vtype)


@router.post("/extension-session", response_model=ExtensionSessionResponse)
async def extension_session(
    response: Response,
    user: AuthUser = Depends(get_current_user),
) -> ExtensionSessionResponse:
    """Open a new Supabase session for the signed-in user's browser extension.

    Why not hand the extension the website's own tokens: Supabase rotates
    refresh tokens and treats the reuse of an already-rotated one as theft —
    it revokes the WHOLE session. The website and the extension would refresh
    the same session independently, so within a couple of hours one of them
    would present a rotated token and both would be signed out. A session of
    its own (its own refresh-token family, its own row in auth.sessions) lets
    each side refresh, and sign out, without touching the other.

    How: the service key asks GoTrue for a one-time magic-link token for the
    caller's own address (``admin/generate_link`` — no email is sent), and the
    token is exchanged at ``/verify`` right here, so it never leaves the
    server. The address comes from the verified JWT, never from the request,
    so a caller can only ever open a session for themselves. The soft-delete
    gate in ``get_current_user`` applies (410 while the account is on hold),
    and the per-user sensitive-action limit (10 an hour) caps how many
    sessions a token can open.

    Tokens are never logged; failures log the upstream status code only.
    """
    await check_sensitive_action_limit(user, "extension_session")

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise HTTPException(status_code=503, detail="Sign-in is not configured")
    if not user.email:
        # Phone-only accounts have no magic link to mint.
        raise HTTPException(status_code=409, detail="This account has no email address")

    base = settings.supabase_url.rstrip("/")
    service = settings.supabase_service_key
    admin_headers = {
        "apikey": service,
        "Authorization": f"Bearer {service}",
        "Content-Type": "application/json",
    }
    # /verify is a public endpoint: the anon key is the right apikey when the
    # API has it; the service key is accepted too.
    public_headers = {
        "apikey": settings.supabase_anon_key or service,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=_SUPABASE_TIMEOUT_S) as client:
            link_resp = await client.post(
                f"{base}/auth/v1/admin/generate_link",
                headers=admin_headers,
                json={"type": "magiclink", "email": user.email},
            )
            if link_resp.status_code != 200:
                logger.warning(
                    "extension_session_link_failed",
                    extra={"user_id": user.id, "status": link_resp.status_code},
                )
                raise HTTPException(status_code=502, detail="Could not open a session")
            hashed, vtype = _hashed_token(link_resp.json())
            if not hashed:
                logger.warning("extension_session_link_malformed", extra={"user_id": user.id})
                raise HTTPException(status_code=502, detail="Could not open a session")

            verify_resp = await client.post(
                f"{base}/auth/v1/verify",
                headers=public_headers,
                json={"type": vtype, "token_hash": hashed},
            )
            if verify_resp.status_code != 200:
                logger.warning(
                    "extension_session_verify_failed",
                    extra={"user_id": user.id, "status": verify_resp.status_code},
                )
                raise HTTPException(status_code=502, detail="Could not open a session")
            session = verify_resp.json()
    except httpx.HTTPError as e:
        logger.warning(
            "extension_session_upstream_error",
            extra={"user_id": user.id, "error": type(e).__name__},
        )
        raise HTTPException(status_code=502, detail="Could not open a session")

    access = session.get("access_token")
    refresh = session.get("refresh_token")
    expires_at = session.get("expires_at")
    session_user = session.get("user") if isinstance(session.get("user"), dict) else {}
    if not (isinstance(access, str) and access and isinstance(refresh, str) and refresh):
        logger.warning("extension_session_malformed", extra={"user_id": user.id})
        raise HTTPException(status_code=502, detail="Could not open a session")
    # The address must resolve to the caller. A mismatch would mean the email
    # in the JWT now belongs to someone else (changed since the token was
    # issued) — never hand out another person's session.
    if session_user.get("id") != user.id:
        logger.error("extension_session_user_mismatch", extra={"user_id": user.id})
        raise HTTPException(status_code=409, detail="Account changed, sign in again")
    if not isinstance(expires_at, int):
        expires_in = session.get("expires_in")
        if not isinstance(expires_in, int):
            raise HTTPException(status_code=502, detail="Could not open a session")
        expires_at = int(time.time()) + expires_in

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    logger.info("extension_session_opened", extra={"user_id": user.id})
    return ExtensionSessionResponse(access_token=access, refresh_token=refresh, expires_at=expires_at)
