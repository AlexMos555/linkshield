"""
Credential-guardian backend.

Strategy doc Top-20 #1 / #7 — the extension's credential-form
guardian (packages/extension-core/src/content/credential-guardian.js)
warns when a password field appears and the form posts to a host that
doesn't match the visible host. The local check uses a small inline
allowlist (LEGIT_AUTH_HOSTS) for federated SSO providers. This router
adds the SERVER-SIDE allowlist for brand-specific verified-login
hosts so the extension can ask: "if I see a paypal-styled login page,
which hosts is paypal actually using?".

Public endpoint (anonymous, IP-rate-limited). The response is a
short list of host strings; the extension matches the form's action
host against them. Privacy invariant: the EXTENSION sends only a
brand identifier (paypal / apple / chase) — never the URL the user
visited, never the visible host of the suspect page. The lookup is
opaque to anyone watching network traffic.

No persistent storage — the allowlist lives in a Python dict here.
For a 50-brand starter set the lookup is O(1) and the dict refreshes
on every container restart. Maintenance is the same workflow as
data/typosquat_targets.json: edit, redeploy.

Future: pull from a Supabase table so security ops can rotate
allowlist entries without a backend deploy.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from api.services.rate_limiter import rate_limit

logger = logging.getLogger("cleanway.credentials")

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])


# Hand-curated allowlist of verified-login hostnames per major brand.
# The keys mirror the BRAND_HOSTS table in credential-guardian.js so
# the extension can resolve `brand → expected_hosts` with one call.
#
# Maintenance: when a brand renames their login flow (rare but
# happens, e.g. paypal → paypal-id) add the new host AND keep the old
# one for a transition window. Removing entries is more dangerous
# than adding — a legitimate login surface that disappears from this
# list will trigger every Cleanway user's credential-guardian banner.
_VERIFIED_HOSTS: dict[str, list[str]] = {
    "paypal": ["www.paypal.com", "paypal.com", "login.paypal.com"],
    "apple": [
        "appleid.apple.com",
        "idmsa.apple.com",
        "secure1.store.apple.com",
        "www.apple.com",
    ],
    "google": [
        "accounts.google.com",
        "accounts.youtube.com",
        "myaccount.google.com",
    ],
    "amazon": ["www.amazon.com", "amazon.com", "signin.aws.amazon.com"],
    "microsoft": [
        "login.microsoftonline.com",
        "login.live.com",
        "account.microsoft.com",
        "login.microsoft.com",
    ],
    "netflix": ["www.netflix.com", "netflix.com"],
    "facebook": ["www.facebook.com", "facebook.com", "m.facebook.com"],
    "instagram": ["www.instagram.com", "instagram.com"],
    "whatsapp": ["web.whatsapp.com", "whatsapp.com"],
    "chase": [
        "secure01a.chase.com",
        "secure02a.chase.com",
        "www.chase.com",
        "chaseonline.chase.com",
    ],
    "coinbase": ["www.coinbase.com", "login.coinbase.com"],
    "binance": ["accounts.binance.com", "www.binance.com"],
    "dhl": ["www.dhl.com", "mydhl.express.dhl"],
    "fedex": ["www.fedex.com", "auth.fedex.com"],
    "ups": ["www.ups.com"],
    "ebay": ["signin.ebay.com", "www.ebay.com"],
    "discord": ["discord.com", "discordapp.com"],
    "telegram": ["web.telegram.org", "telegram.org"],
    "linkedin": ["www.linkedin.com", "linkedin.com"],
    "citi": [
        "online.citi.com",
        "citi.com",
        "www.citi.com",
    ],
    "wellsfargo": ["connect.secure.wellsfargo.com", "www.wellsfargo.com"],
    "capitalone": ["verified.capitalone.com", "www.capitalone.com"],
    "hsbc": ["www.hsbc.com", "online-banking.hsbc.com"],
}


class VerifiedHostsResponse(BaseModel):
    brand: str
    hosts: list[str]
    is_known: bool


@router.get(
    "/verified",
    response_model=VerifiedHostsResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="creds_verified"))],
)
async def verified_hosts(
    brand: str = Query(
        ...,
        min_length=2,
        max_length=64,
        description="Brand identifier (e.g. paypal, apple, chase). Case-insensitive — server lowercases.",
        # Allow case-insensitive input so PayPal and PAYPAL both
        # resolve. The lookup itself is lowercase.
        pattern=r"^[A-Za-z0-9_-]+$",
    ),
) -> VerifiedHostsResponse:
    """
    Resolve a brand identifier to the list of hostnames that are
    actually used as that brand's verified login surfaces.

    The credential-guardian content script uses this to decide whether
    a same-brand-looking form action is plausibly legitimate. If
    `is_known` is False the brand isn't in our allowlist — the
    extension should fall back to its inline LEGIT_AUTH_HOSTS check
    plus its three-signal heuristic.

    Response is anonymous + IP-rate-limited. The brand identifier
    leaks NO information about the user's current page or browsing
    behaviour — it's just a brand name like "paypal", same kind of
    request a price comparison page might make.
    """
    key = brand.strip().lower()
    if not key:
        raise HTTPException(400, "brand is required")
    hosts = _VERIFIED_HOSTS.get(key)
    if hosts is None:
        # Don't 404 — that's a signal to attackers ("this brand IS in
        # the allowlist", "this isn't"). Return an empty list + flag.
        return VerifiedHostsResponse(brand=key, hosts=[], is_known=False)
    return VerifiedHostsResponse(brand=key, hosts=hosts, is_known=True)


# ── Strategy doc Top-20 #8 — Honeypot Shield ──
# The extension's credential-guardian modal offers a "Send fake
# password" button. When the user takes it, the content script
# pings this endpoint so the quarterly transparency report can
# show "Cleanway intercepted N credential-theft attempts last
# quarter" — a hard-evidence number competitors cannot publish.
#
# Privacy invariants:
#   * No user_id, no IP-derived identity. Anonymous POST.
#   * Domain ONLY in the request body. No URL, no path, no value.
#   * We INCR daily + quarterly Redis counters. The raw domains
#     are NEVER stored — they exit the request scope unrecorded.
#   * No write to Postgres. Pure counter.

class HoneypotReportRequest(BaseModel):
    domain: str


class HoneypotReportResponse(BaseModel):
    ok: bool


@router.post(
    "/report-honeypot",
    response_model=HoneypotReportResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="creds_honeypot_report"))],
)
async def report_honeypot(body: HoneypotReportRequest) -> HoneypotReportResponse:
    """Record one honeypot-shield activation.

    The endpoint always returns ok=True so a misbehaving content
    script never breaks the user's submit flow. Validation failures
    silently no-op — there's nothing the client could do to recover.
    """
    import re
    from datetime import datetime, timezone

    domain = (body.domain or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9.\-]{1,253}", domain) or "." not in domain:
        # Drop silently — never tell an attacker which patterns we
        # filter so they can't probe the validator.
        return HoneypotReportResponse(ok=True)

    try:
        from api.services.cache import get_redis
        r = await get_redis()
        now = datetime.now(timezone.utc)
        day_key = now.strftime("honeypot:day:%Y-%m-%d")
        await r.incr(day_key)
        await r.expire(day_key, 90 * 24 * 60 * 60)  # 90-day retention
        quarter = (now.month - 1) // 3 + 1
        q_key = f"honeypot:q:{now.year}-q{quarter}"
        await r.incr(q_key)
    except Exception:
        logger.debug("honeypot counter increment failed", exc_info=True)
    return HoneypotReportResponse(ok=True)
