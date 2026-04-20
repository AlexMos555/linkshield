"""
Email service — provider-agnostic transactional email sender.

Responsibilities:
  1. Pick a provider at runtime (Resend / SES / noop-dev) based on env var
  2. Load pre-rendered templates from packages/email-templates/out/{template}/{locale}.html
  3. Substitute runtime props (user name, URLs) into the static HTML via simple placeholders
  4. Send HTML + plaintext + subject with proper headers:
       List-Unsubscribe, List-Unsubscribe-Post (RFC 8058 one-click)
       Auto-Submitted: auto-generated
       Precedence: bulk
  5. Emit structured log events, never logging full email addresses

Design choices:
  - Templates are PRE-RENDERED at build time by scripts/build-emails.mjs
    → Python never runs React, no JS runtime in prod container
  - Provider selection via env: EMAIL_PROVIDER = "resend" | "ses" | "noop"
  - "noop" is the default for dev/staging — logs what would be sent, sends nothing

Privacy:
  - We log email_id (UUID) and template_key, never the recipient address
  - PII in rendered HTML is user-provided (name/links), kept only in-memory for the send call

Unsubscribe:
  - Every email includes a signed token URL — see api/routers/email_unsubscribe.py
  - List-Unsubscribe-Post enables Gmail/Apple "unsubscribe" button (RFC 8058)
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

logger = logging.getLogger("linkshield.email")

# ─── Template manifest (built by scripts/build-emails.mjs) ──────
_ROOT = Path(__file__).resolve().parent.parent.parent
_EMAIL_OUT = _ROOT / "packages" / "email-templates" / "out"

TemplateKey = Literal[
    "welcome",
    "receipt",
    "weekly_report",
    "family_invite",
    "breach_alert",
    "subscription_cancel",
    "granny_mode_invite",
]

SUPPORTED_LOCALES = ("en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar")


@dataclass(frozen=True)
class RenderedEmail:
    subject: str
    html: str
    text: str
    template_key: TemplateKey
    locale: str


def _load_manifest() -> dict:
    """Load {template: {subjects: {locale: ...}, fixture_props: {...}}}.

    Raises if the build hasn't run — explicit failure is better than silent skip.
    """
    manifest_path = _EMAIL_OUT / "manifest.json"
    if not manifest_path.exists():
        raise RuntimeError(
            f"Email templates not built. Run: node scripts/build-emails.mjs "
            f"(looked at {manifest_path})"
        )
    with open(manifest_path) as f:
        return json.load(f)


def _load_template_file(template: TemplateKey, locale: str, ext: Literal["html", "txt"]) -> str:
    """Load rendered template. Falls back to English if locale missing."""
    candidate = _EMAIL_OUT / template / f"{locale}.{ext}"
    if not candidate.exists():
        logger.warning(
            "email.template.locale_missing",
            extra={"template": template, "locale": locale, "fallback": "en"},
        )
        candidate = _EMAIL_OUT / template / f"en.{ext}"
    return candidate.read_text(encoding="utf-8")


def _substitute(raw: str, props: dict[str, Any]) -> str:
    """Replace {{key}} placeholders with runtime values.

    NOTE: since React Email pre-renders with the fixture values, the "placeholders"
    in production are actually the fixture URLs/names. We substitute by REPLACING
    those fixture strings with the real runtime values.

    This is intentional — it keeps the Python side dead simple (just string.replace)
    while guaranteeing the pre-rendered HTML is byte-identical in CI snapshots.

    Convention: each template documents which fixture strings get replaced per real props.
    """
    out = raw
    for old, new in props.items():
        # Props dict maps fixture_value → real_value
        out = out.replace(old, str(new))
    return out


def render_template(
    template: TemplateKey,
    locale: str,
    fixture_overrides: dict[str, Any],
) -> RenderedEmail:
    """Load pre-rendered HTML+text, substitute runtime values, return RenderedEmail.

    Args:
        template: key from the registry
        locale: target language; falls back to English if not rendered
        fixture_overrides: {fixture_value: real_value} pairs, e.g.
            {"Alex": user.first_name, "https://linkshield.example/scan": scan_link}
    """
    if locale not in SUPPORTED_LOCALES:
        logger.warning("email.locale.unknown", extra={"locale": locale, "fallback": "en"})
        locale = "en"

    manifest = _load_manifest()
    subject_raw = manifest[template]["subjects"].get(locale) or manifest[template]["subjects"]["en"]
    html_raw = _load_template_file(template, locale, "html")
    text_raw = _load_template_file(template, locale, "txt")

    return RenderedEmail(
        subject=_substitute(subject_raw, fixture_overrides),
        html=_substitute(html_raw, fixture_overrides),
        text=_substitute(text_raw, fixture_overrides),
        template_key=template,
        locale=locale,
    )


# ─── Provider abstraction ─────────────────────────────────────────


@dataclass
class SendResult:
    ok: bool
    provider_message_id: Optional[str]
    error: Optional[str]
    send_id: str  # our internal UUID for correlation


class EmailProvider:
    """Base class — implementations raise NotImplementedError."""

    name: str = "base"

    async def send(
        self,
        *,
        to: str,
        from_addr: str,
        from_name: str,
        subject: str,
        html: str,
        text: str,
        headers: dict[str, str],
    ) -> SendResult:
        raise NotImplementedError


class NoopProvider(EmailProvider):
    """Dev / staging default: logs the full envelope, sends nothing.

    Intentionally does NOT log `to` at INFO level — only at DEBUG — so we don't
    leak emails into production-shipped logs. In dev, DEBUG is on; in prod, never.
    """

    name = "noop"

    async def send(self, *, to, from_addr, from_name, subject, html, text, headers) -> SendResult:
        send_id = str(uuid.uuid4())
        logger.info(
            "email.send.noop",
            extra={
                "send_id": send_id,
                "from": f"{from_name} <{from_addr}>",
                "subject": subject,
                "html_len": len(html),
                "text_len": len(text),
                "headers": list(headers.keys()),
            },
        )
        logger.debug("email.send.noop.recipient", extra={"send_id": send_id, "to": to})
        return SendResult(ok=True, provider_message_id=f"noop-{send_id}", error=None, send_id=send_id)


class ResendProvider(EmailProvider):
    """Resend.com HTTP provider — simple, modern, good DX for dev/staging."""

    name = "resend"

    def __init__(self, api_key: str):
        if not api_key:
            raise ValueError("Resend API key required")
        self._api_key = api_key

    async def send(self, *, to, from_addr, from_name, subject, html, text, headers) -> SendResult:
        send_id = str(uuid.uuid4())
        try:
            import httpx
        except ImportError:
            return SendResult(ok=False, provider_message_id=None, error="httpx not installed", send_id=send_id)

        payload = {
            "from": f"{from_name} <{from_addr}>",
            "to": [to],
            "subject": subject,
            "html": html,
            "text": text,
            "headers": headers,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    "https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json=payload,
                )
            if resp.status_code >= 400:
                logger.error(
                    "email.send.resend.error",
                    extra={"send_id": send_id, "status": resp.status_code, "body": resp.text[:500]},
                )
                return SendResult(ok=False, provider_message_id=None, error=f"Resend {resp.status_code}", send_id=send_id)
            data = resp.json()
            return SendResult(ok=True, provider_message_id=data.get("id"), error=None, send_id=send_id)
        except Exception as e:
            logger.exception("email.send.resend.exception", extra={"send_id": send_id})
            return SendResult(ok=False, provider_message_id=None, error=str(e), send_id=send_id)


class SESProvider(EmailProvider):
    """AWS SES provider — cheap, high-deliverability for prod.

    Requires boto3 installed and AWS_REGION / AWS credentials (via IAM role ideally).
    """

    name = "ses"

    def __init__(self, region: str):
        self._region = region

    async def send(self, *, to, from_addr, from_name, subject, html, text, headers) -> SendResult:
        send_id = str(uuid.uuid4())
        try:
            import boto3  # type: ignore
        except ImportError:
            return SendResult(ok=False, provider_message_id=None, error="boto3 not installed", send_id=send_id)

        # boto3 ses:SendEmail doesn't allow custom headers; must use SendRawEmail for List-Unsubscribe.
        # We build a minimal MIME message.
        import email.mime.multipart
        import email.mime.text

        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_addr}>"
        msg["To"] = to
        for hdr_name, hdr_value in headers.items():
            msg[hdr_name] = hdr_value
        msg.attach(email.mime.text.MIMEText(text, "plain", "utf-8"))
        msg.attach(email.mime.text.MIMEText(html, "html", "utf-8"))

        try:
            # boto3 is sync — run in thread to not block the event loop
            import asyncio

            def _send():
                ses = boto3.client("ses", region_name=self._region)
                return ses.send_raw_email(RawMessage={"Data": msg.as_string()})

            response = await asyncio.to_thread(_send)
            return SendResult(
                ok=True,
                provider_message_id=response.get("MessageId"),
                error=None,
                send_id=send_id,
            )
        except Exception as e:
            logger.exception("email.send.ses.exception", extra={"send_id": send_id})
            return SendResult(ok=False, provider_message_id=None, error=str(e), send_id=send_id)


def _make_provider() -> EmailProvider:
    """Factory: pick provider based on EMAIL_PROVIDER env var."""
    name = os.environ.get("EMAIL_PROVIDER", "noop").strip().lower()
    if name == "resend":
        return ResendProvider(api_key=os.environ.get("RESEND_API_KEY", ""))
    if name == "ses":
        return SESProvider(region=os.environ.get("AWS_REGION", "us-east-1"))
    return NoopProvider()


_provider: Optional[EmailProvider] = None


def get_provider() -> EmailProvider:
    global _provider
    if _provider is None:
        _provider = _make_provider()
        logger.info("email.provider.initialized", extra={"provider": _provider.name})
    return _provider


# ─── Public send API ───────────────────────────────────────────────


async def send_template(
    *,
    to: str,
    template: TemplateKey,
    locale: str,
    fixture_overrides: dict[str, Any],
    unsubscribe_url: str,
) -> SendResult:
    """Render + send a transactional email.

    The unsubscribe_url is used for two things:
      1. List-Unsubscribe header (RFC 2369) — shown as "unsubscribe" button in Gmail/Apple
      2. List-Unsubscribe-Post header (RFC 8058) — enables one-click without visiting page

    We assume fixture_overrides includes the unsubscribe_url mapping.
    """
    rendered = render_template(template, locale, fixture_overrides)

    settings = _get_settings()
    headers = {
        # RFC 2369 + RFC 8058 one-click unsubscribe — critical for inbox placement
        "List-Unsubscribe": f"<{unsubscribe_url}>, <mailto:unsubscribe@{settings['from_domain']}?subject=unsubscribe>",
        "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        # Signal this is automated so replies don't create support tickets
        "Auto-Submitted": "auto-generated",
        "Precedence": "bulk",
        # X-LinkShield-* for internal correlation
        "X-LinkShield-Template": template,
        "X-LinkShield-Locale": locale,
    }

    return await get_provider().send(
        to=to,
        from_addr=settings["from_addr"],
        from_name=settings["from_name"],
        subject=rendered.subject,
        html=rendered.html,
        text=rendered.text,
        headers=headers,
    )


def _get_settings() -> dict[str, str]:
    return {
        "from_addr": os.environ.get("EMAIL_FROM_ADDR", "no-reply@linkshield.example"),
        "from_name": os.environ.get("EMAIL_FROM_NAME", "LinkShield"),
        "from_domain": os.environ.get("EMAIL_FROM_DOMAIN", "linkshield.example"),
    }
