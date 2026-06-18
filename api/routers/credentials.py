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


# ── Strategy doc Top-20 #8 — Honeypot Shield: NO server endpoint ──
# We intentionally do NOT expose an endpoint that records honeypot
# activations from the extension. The earlier design had a fetch
# from credential-guardian.js to /api/v1/credentials/report-honeypot;
# the adversarial review (2026-06-17) flagged that the request
# itself surfaces in the page's Performance Resource Timing as a
# "this user has Cleanway installed" signal. A phishing kit could
# then serve those users a defeating variant of itself.
#
# Counters live exclusively in chrome.storage.local for the popup
# and the weekly report. The quarterly transparency report cites
# opt-in aggregated extension telemetry, not a hot-path beacon.
