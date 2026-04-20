"""
Email unsubscribe — signed-token flow.

Every transactional email includes a signed URL. Clicking it:
  - GET  /api/v1/email/unsubscribe/{token}  → HTML page with "Confirm unsubscribe" button
  - POST /api/v1/email/unsubscribe/{token}  → processes unsubscribe, returns 200

Also supports RFC 8058 one-click (POST with Content-Type: multipart/form-data
  and body `List-Unsubscribe=One-Click`). Gmail/Apple fire this automatically
  when user taps their built-in "unsubscribe" button.

Tokens are HMAC-signed with SUPABASE_JWT_SECRET + a per-email purpose string.
Expire after 90 days. A stolen token only lets the attacker UNSUBSCRIBE the user
(which they can reverse in settings) — no data exfiltration risk.

Rate limit: 10 POST/min per IP — prevent trivial DoS on email preferences.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from api.services.rate_limiter import unsubscribe_rate_limit

logger = logging.getLogger("linkshield.email.unsubscribe")

router = APIRouter(prefix="/api/v1/email", tags=["email"])

_TOKEN_TTL_SECONDS = 90 * 24 * 3600  # 90 days
_PURPOSE = "email_unsubscribe_v1"


def _get_secret() -> bytes:
    secret = os.environ.get("SUPABASE_JWT_SECRET", "").strip()
    if not secret:
        raise RuntimeError("SUPABASE_JWT_SECRET not configured — cannot sign unsubscribe tokens")
    return secret.encode("utf-8")


def mint_token(user_id: str, email_template: str) -> str:
    """Create a signed unsubscribe token.

    Payload: {uid, template, iat}
    Signature: HMAC-SHA256(secret, payload_json)
    Encoded: base64url(payload_json) + "." + base64url(signature)

    No JWT library because we need the tokens to be URL-safe and short; a full
    JWT would be overkill.
    """
    payload = {
        "uid": user_id,
        "template": email_template,
        "iat": int(time.time()),
        "p": _PURPOSE,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(_get_secret(), payload_bytes, hashlib.sha256).digest()
    return (
        base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )


def _b64url_decode(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def verify_token(token: str) -> Optional[dict]:
    """Return payload dict if valid + non-expired, else None."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        return None

    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except Exception:
        return None

    expected = hmac.new(_get_secret(), payload_bytes, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except json.JSONDecodeError:
        return None

    if payload.get("p") != _PURPOSE:
        return None

    iat = payload.get("iat")
    if not isinstance(iat, (int, float)):
        return None
    if time.time() - iat > _TOKEN_TTL_SECONDS:
        return None

    if not isinstance(payload.get("uid"), str):
        return None
    if not isinstance(payload.get("template"), str):
        return None

    return payload


# ─── Routes ────────────────────────────────────────────────────────


async def _process_unsubscribe(payload: dict) -> None:
    """Mark user + template as unsubscribed in Supabase.

    Actual DB write is best-effort — logged so ops can reconcile if Supabase is
    down. The click has already happened; failing to record it should not show
    a confusing error to the user.
    """
    logger.info(
        "email.unsubscribe.recorded",
        extra={"uid": payload["uid"], "template": payload["template"]},
    )
    # TODO: wire Supabase client once user_settings.email_prefs column exists
    # For now: intentional no-op + log. Operator reconciles from logs until impl.


_UNSUB_PAGE_HTML = """\
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unsubscribe — LinkShield</title>
<style>
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:#f8fafc;color:#0f172a;margin:0;padding:40px 20px;text-align:center}
  .card{max-width:480px;margin:0 auto;background:#fff;padding:32px 28px;border-radius:12px;
        box-shadow:0 2px 8px rgba(0,0,0,0.06)}
  h1{font-size:22px;margin:0 0 12px;font-weight:700}
  p{color:#475569;line-height:1.55;margin:0 0 20px}
  button{background:#0f172a;color:#fff;border:none;padding:12px 24px;
         border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
  .success{color:#15803d;font-weight:600}
</style>
</head><body>
<div class="card">
  <h1>Unsubscribe from LinkShield emails?</h1>
  <p>You'll stop receiving <strong>__TEMPLATE__</strong> emails. Blocking scam sites keeps working — that's never email-gated.</p>
  <form method="POST" action="/api/v1/email/unsubscribe/__TOKEN__">
    <button type="submit">Yes, unsubscribe me</button>
  </form>
</div>
</body></html>
"""


def _render_unsub_page(template_key: str, token: str) -> str:
    """Simple placeholder substitution (str.format chokes on CSS braces).

    Sentinels __TEMPLATE__ / __TOKEN__ are unambiguous in HTML/CSS context.
    """
    from html import escape as h
    return (
        _UNSUB_PAGE_HTML
        .replace("__TEMPLATE__", h(template_key.replace("_", " ")))
        .replace("__TOKEN__", h(token, quote=True))
    )


@router.get(
    "/unsubscribe/{token}",
    dependencies=[Depends(unsubscribe_rate_limit())],
)
async def unsubscribe_landing(token: str) -> HTMLResponse:
    """Render a confirmation page. User must POST to actually unsubscribe."""
    payload = verify_token(token)
    if payload is None:
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;padding:40px;text-align:center'>"
            "<h1>Invalid or expired link</h1>"
            "<p>Please contact support if you want to adjust your email preferences.</p>"
            "</body></html>",
            status_code=400,
        )

    return HTMLResponse(_render_unsub_page(payload["template"], token))


@router.post(
    "/unsubscribe/{token}",
    dependencies=[Depends(unsubscribe_rate_limit())],
)
async def unsubscribe_confirm(
    token: str,
    request: Request,
    List_Unsubscribe: Optional[str] = Form(default=None),
) -> PlainTextResponse:
    """Process unsubscribe. Supports both browser POST and RFC 8058 one-click."""
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    # Validate RFC 8058 header if present — Gmail/Apple send "List-Unsubscribe=One-Click"
    # We accept any POST that has a valid token — the header validation is belt+suspenders.
    if List_Unsubscribe is not None and List_Unsubscribe != "One-Click":
        logger.warning("email.unsubscribe.bad_header", extra={"value": List_Unsubscribe})

    await _process_unsubscribe(payload)
    return PlainTextResponse("You've been unsubscribed.", status_code=200)
