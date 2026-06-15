"""Sentry event PII scrubber.

Cleanway markets itself as privacy-first. Shipping raw user emails,
auth tokens, and JWT bodies into Sentry contradicts that brand —
Sentry retains events for up to 90 days on the standard plan and
employees of Cleanway-the-business have read access. We strip any
PII from event payloads before sending.

Strategy: pattern-match across the full string representation of the
event (request body, headers, exception messages, breadcrumb data,
extra context, user context). Replace matched substrings with
`[redacted]`. We deliberately err on the side of OVER-redacting —
a Sentry event with `[redacted]` next to a stack trace is still
actionable, but an event with a live JWT is a security incident.

Wired in api/main.py via `sentry_sdk.init(..., before_send=...,
before_breadcrumb=...)`.
"""
from __future__ import annotations

import re
from typing import Any

# Order matters — JWT match must come BEFORE the generic Bearer header
# match so the actual token gets replaced, not the literal word "Bearer".
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JWT: three base64url segments separated by dots, starting with eyJ
    # (any standard JWS header). Catches both Authorization bearer values
    # and any JWT body that leaks into exception messages.
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[redacted-jwt]"),
    # Generic Bearer header — covers non-JWT tokens (Supabase service-role
    # keys, custom bearer tokens). Anchored so we don't eat random
    # "Bearer" in prose.
    (re.compile(r"Bearer\s+[A-Za-z0-9\._\-\+/=]{8,}", re.IGNORECASE), "Bearer [redacted]"),
    # Stripe object IDs — secret/public keys, customers, sessions, etc.
    # Anyone with the secret key owns the account; even customer IDs
    # leak account-to-card linkage.
    (
        re.compile(r"(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}"),
        "[redacted-stripe-key]",
    ),
    (
        re.compile(r"(cus|sub|pi|ch|cs|tok|re|in|seti|src|prod|price)_[A-Za-z0-9]{14,}"),
        "[redacted-stripe-id]",
    ),
    # Supabase service-role key: prefixed eyJ JWT, already covered above.
    # Supabase anon key: same prefix, intentionally public — we still
    # redact it to avoid burning rate limit on a fresh project key
    # rotation if we ever migrate.
    # Email addresses (RFC-ish — generous on TLD length).
    (
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
        "[redacted-email]",
    ),
    # User UUIDs / session IDs / device hashes. 8-4-4-4-12 hex with
    # optional braces. Matches Supabase auth.uid() values which are
    # the primary user-PII key in our DB.
    (
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        "[redacted-uuid]",
    ),
    # IP addresses (IPv4 + IPv6). Sentry has its own "send_default_pii"
    # toggle for the request IP but it doesn't catch IPs embedded in
    # exception messages or in our X-Forwarded-For audit-log breadcrumbs.
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[redacted-ip]"),
    (
        re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"),
        "[redacted-ip6]",
    ),
]

# Keys whose VALUE we always redact regardless of content — these are
# always sensitive even if the value doesn't match a pattern (e.g.
# a short token, a recovery code, a PIN).
_ALWAYS_REDACT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "auth_token",
        "authorization",
        "cookie",
        "set-cookie",
        "session",
        "supabase_service_key",
        "supabase_jwt_secret",
        "stripe_secret_key",
        "stripe_webhook_secret",
        "parental_pin",
        "parental_pin_hash",
        "pin",
        "recovery_code",
        "ssn",
        "credit_card",
        "card_number",
        "cvv",
    }
)


def _scrub_string(s: str) -> str:
    for pattern, replacement in _PII_PATTERNS:
        s = pattern.sub(replacement, s)
    return s


def _scrub(node: Any) -> Any:
    """Recursively walk dicts/lists and scrub leaf strings.

    For dicts: if the KEY is in _ALWAYS_REDACT_KEYS we replace the value
    entirely. Otherwise we recurse and scrub the value's leaf strings.
    """
    if isinstance(node, str):
        return _scrub_string(node)
    if isinstance(node, dict):
        out: dict[Any, Any] = {}
        for k, v in node.items():
            if isinstance(k, str) and k.lower() in _ALWAYS_REDACT_KEYS:
                out[k] = "[redacted]"
            else:
                out[k] = _scrub(v)
        return out
    if isinstance(node, (list, tuple)):
        scrubbed = [_scrub(item) for item in node]
        return type(node)(scrubbed) if isinstance(node, tuple) else scrubbed
    return node


def before_send(event: dict[str, Any], _hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sentry `before_send` callback. Mutate-by-replace the event payload."""
    # `user` context: Sentry SDK already strips `email` / `ip_address`
    # when send_default_pii is False, but we ALSO set `id` ourselves
    # (audit feat: sentry user context). Replace the raw id with a
    # one-way hash so we still get "same user repeatedly" correlation
    # without leaking the auth.uid() itself.
    user = event.get("user")
    if isinstance(user, dict):
        if "id" in user and isinstance(user["id"], str):
            import hashlib

            user["id"] = "u_" + hashlib.sha256(user["id"].encode("utf-8")).hexdigest()[:16]
        # Email / ip_address: drop completely; we don't need them and
        # they're high-impact if breached.
        user.pop("email", None)
        user.pop("ip_address", None)
        user.pop("username", None)

    return _scrub(event)


def before_breadcrumb(
    crumb: dict[str, Any], _hint: dict[str, Any] | None = None
) -> dict[str, Any] | None:
    """Sentry `before_breadcrumb` callback. Same scrubbing applied to
    breadcrumb payloads."""
    return _scrub(crumb)
