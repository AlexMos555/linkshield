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

Performance transactions never pass through `before_send`. A sampled trace
of GET /api/v1/public/check/<site> carried the site in its request URL, the
outgoing probe of that site in a span ("GET https://<site>/"), the cache key
in a Redis span ("GET 'public_check:v2:<site>'") and — for the DoH route —
the whole DNS question in `query_string`. `before_send_transaction` runs the
same scrub over transactions, plus span rules (`_scrub_span`).

Wired in api/main.py through `sentry_init_options()`, which also stops the
SDK from attaching `sentry-trace` / `baggage` headers to outgoing requests and
from attaching request bodies at all (`max_request_body_size="never"`): the
FastAPI integration put the JSON body of every sampled POST, and of every
error, in `request.data` — the checked domains of POST /api/v1/check, an
email's subject and text, a raw family invite code — under key names no
scrub rule can list in full. For the same reason error events carry no stack
frame local variables (`include_local_variables=False`).
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

# The things a person checked, looked up or holds, as they appear in URL
# paths: our landing's /check/<site> and /audit/<site> pages (the same rule
# as landing/lib/sentry-scrub.ts SITE_PATH, which also covers this API's
# /api/v1/public/check/<site> and /api/v1/breach/check/<prefix>), and the
# API routes whose path segment is a site, a phone or device hash or an
# unsubscribe token. Page URLs reach Sentry in Referer headers, request URLs
# and — when a request matched no route — transaction names.
_SENSITIVE_PATH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(/(?:check|audit)/)[^/?#\s\"']+"), r"\1[site]"),
    (re.compile(r"(/api/v1/breach/domain/)[^/?#\s\"']+"), r"\1[site]"),
    (re.compile(r"(/api/v1/phone/lookup/)[^/?#\s\"']+"), r"\1[hash]"),
    (re.compile(r"(/api/v1/user/device/)[^/?#\s\"']+"), r"\1[hash]"),
    (re.compile(r"(/api/v1/email/unsubscribe/)[^/?#\s\"']+"), r"\1[token]"),
    # RFC 8484 GET: the base64url DNS question, i.e. the name being resolved.
    (re.compile(r"([?&]dns=)[^&#\s\"']+"), r"\1[query]"),
]

# Order matters — JWT match must come BEFORE the generic Bearer header
# match so the actual token gets replaced, not the literal word "Bearer".
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    *_SENSITIVE_PATH_PATTERNS,
    # JWT: three base64url segments separated by dots, starting with eyJ
    # (any standard JWS header). Catches both Authorization bearer values
    # and any JWT body that leaks into exception messages.
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "[redacted-jwt]"),
    # Generic Bearer header — covers non-JWT tokens (Supabase service-role
    # keys, custom bearer tokens). Anchored so we don't eat random
    # "Bearer" in prose.
    (re.compile(r"Bearer\s+[A-Za-z0-9\._\-\+/=]{8,}", re.IGNORECASE), "Bearer [redacted]"),
    # Google API keys (Safe Browsing's `?key=` — it lands in a span's
    # http.query and in any exception message that quotes the request URL).
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "[redacted-google-key]"),
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
        # Browsing context — the domain / URL a user is checking. Cleanway's
        # privacy invariant is "even on breach, attackers learn nothing
        # about the user's online activity". The analyzer + safe_browsing
        # threat-intel paths log `extra={"domain": domain}` at ~15 sites;
        # those go to Sentry (a third-party sink with long retention) unless
        # scrubbed here. The domain still appears in stdout / Railway logs
        # (access-controlled, ephemeral) for ops — we only strip it from the
        # external observability sink. (2026-07-01 audit BE-4 follow-up.)
        "domain",
        "domains",
        "raw_url",
        "url",
        "hostname",
        "host",
        # What a person sent us to judge or to join: an email's subject and
        # text, a referral / family invite code. Request bodies never reach
        # Sentry (`max_request_body_size`), but a log call's `extra` does.
        "subject",
        "body_text",
        "body_html",
        "code",
        # Query strings: the DoH GET carries the DNS question in `dns=`, and
        # outgoing spans carry the checked name (Cloudflare `?name=`, crt.sh
        # `?q=`) or an API key (Safe Browsing `?key=`). Nothing in a query
        # string is worth that to debugging.
        "query_string",
        "http.query",
        "http.fragment",
        # The weekly benchmark's rate-limit bypass token, when configured.
        "x-cleanway-benchmark",
        # Billing (api/billing): a phone number is the most sensitive datum in
        # the system and must never reach Sentry, nor a device's bearer
        # secret, a trial fingerprint, a claim / activation code or the
        # provider's own phone field.
        "msisdn",
        "phone",
        "user_phone",
        "device_secret",
        "fingerprint",
        "activation_code",
        "idempotency-key",
        "x-fake-signature",
        "x-partner-signature",
    }
)

# Hosts of the services this API calls. An outgoing-request span to one of
# them keeps the host (which provider was slow is the point of a trace); a
# span to anything else — the site being checked, probed directly — shows
# `[site]`. Paths and queries are always dropped: VirusTotal, IPQS and RDAP
# put the checked name (and IPQS its key) in the path.
_UPSTREAM_HOSTS = frozenset(
    {
        "safebrowsing.googleapis.com",
        "webrisk.googleapis.com",
        "data.phishtank.com",
        "cdn.phishtank.com",
        "urlhaus-api.abuse.ch",
        "threatfox-api.abuse.ch",
        "mb-api.abuse.ch",
        "feodotracker.abuse.ch",
        "otx.alienvault.com",
        "ipqualityscore.com",
        "www.ipqualityscore.com",
        "checkurl.phishtank.com",
        "phishstats.info",
        "crt.sh",
        "rdap.org",
        "cloudflare-dns.com",
        "family.cloudflare-dns.com",
        "api.pwnedpasswords.com",
        "haveibeenpwned.com",
        "api.anthropic.com",
        "api.resend.com",
        "api.stripe.com",
        "tranco-list.eu",
    }
)
_UPSTREAM_SUFFIXES = (".supabase.co",)

# A host name anywhere in a string (ASCII, punycode or Cyrillic labels). Used
# only on span descriptions / data of datastore spans, where the only names
# are the ones inside cache keys — never on whole events (it would eat module
# paths like api.services.analyzer).
_HOSTNAME = re.compile(
    r"(?<![\w.-])(?:[a-z0-9\u0400-\u04ff](?:[a-z0-9\u0400-\u04ff-]{0,61}[a-z0-9\u0400-\u04ff])?\.)+"
    r"(?:xn--[a-z0-9-]{1,59}|[a-z\u0400-\u04ff]{2,63})(?![\w-])",
    re.IGNORECASE,
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


def _redact_hostnames(node: Any) -> Any:
    if isinstance(node, str):
        return _HOSTNAME.sub("[site]", node)
    if isinstance(node, dict):
        return {k: _redact_hostnames(v) for k, v in node.items()}
    if isinstance(node, (list, tuple)):
        return [_redact_hostnames(item) for item in node]
    return node


def _is_upstream(host: str) -> bool:
    return host in _UPSTREAM_HOSTS or host.endswith(_UPSTREAM_SUFFIXES)


def _outgoing_request_description(description: str) -> str:
    """'GET https://evil.example/login?x=1' → 'GET [site]';
    'POST https://safebrowsing.googleapis.com/v4/...' → 'POST https://safebrowsing.googleapis.com'."""
    method, _, url = description.partition(" ")
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        host = ""
    if host and _is_upstream(host):
        return f"{method} {parts.scheme}://{host}"
    return f"{method} [site]"


def _scrub_span(span: Any) -> Any:
    """Span rules that the generic scrub cannot express: an outgoing request
    names its target host in the description, and a datastore span names the
    cache key — both can be the site being checked."""
    if not isinstance(span, dict):
        return span
    op = str(span.get("op") or "")
    out = dict(span)
    description = span.get("description")
    if op.startswith("http.client") and isinstance(description, str):
        out["description"] = _outgoing_request_description(description)
    if op.startswith(("http.client", "db", "cache")):
        for key in ("data", "tags"):
            if key in span:
                out[key] = _redact_hostnames(span[key])
        if not op.startswith("http.client") and isinstance(description, str):
            out["description"] = _redact_hostnames(description)
    return out


def before_send_transaction(
    event: dict[str, Any], _hint: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Sentry `before_send_transaction` callback. Transactions skip
    `before_send`, so without this a sampled trace shipped the checked site as
    is. Span rules first (they need the raw URL), then the event-wide scrub —
    which also rewrites the transaction name and request URL paths."""
    spans = event.get("spans")
    if isinstance(spans, list):
        event = {**event, "spans": [_scrub_span(span) for span in spans]}
    return before_send(event)


def sentry_init_options(dsn: str, debug: bool) -> dict[str, Any]:
    """Every privacy-relevant `sentry_sdk.init` option, in one place a test
    can pin."""
    return {
        "dsn": dsn,
        "traces_sample_rate": 0.1,
        "environment": "production" if not debug else "development",
        # send_default_pii is False by default in modern sentry-sdk but we set
        # it explicitly so a future SDK version bumping the default to True
        # doesn't silently leak.
        "send_default_pii": False,
        "before_send": before_send,
        "before_send_transaction": before_send_transaction,
        "before_breadcrumb": before_breadcrumb,
        # The SDK's default is to add `sentry-trace` and `baggage` headers to
        # EVERY outgoing request — including the probe of the site being
        # checked. That tells a phishing kit "this visitor is Cleanway's
        # scanner" (a free cloaking signal) and hands it our Sentry public
        # key and the route name. Nothing downstream of this API reads them.
        "trace_propagation_targets": [],
        # The SDK's default ("medium") attaches the JSON body of each request
        # to its transaction and to any error it raises. Our bodies are the
        # checked domains, email content and invite codes; the scrubber only
        # catches the keys it knows, so no body is sent at all.
        "max_request_body_size": "never",
        # Error events also carried every stack frame's local variables, by
        # default — the parsed request model (`CheckRequest(domains=[...])`),
        # a URL being probed, a hostname — under names like `req`, `d` or
        # `target` that no key rule can foresee. The stack trace itself stays.
        "include_local_variables": False,
    }
