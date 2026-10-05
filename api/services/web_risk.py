"""Google Web Risk — Lookup API client, the commercial stand-in for Safe
Browsing v4.

Why: the Safe Browsing API terms say that without a separate agreement it
"may not be used for commercial purposes" (developers.google.com/
safe-browsing/terms, read 2026-09-29), and v4 is scheduled to end. Web Risk
is the same lookup sold as a Google Cloud product (free up to 100,000
queries a month, then per thousand — cloud.google.com/web-risk/pricing). It
needs a Google Cloud project with billing, which is the founder's decision
(docs/THIRD_PARTY_FEEDS.md): set WEB_RISK_API_KEY and safe_browsing.get_client()
hands out this client instead; unset, nothing changes.

What is the same for callers: a CheckResult (safe_browsing.CheckResult),
the `safe_browsing_hit` signal, the confirmed-threats threat types
(SOCIAL_ENGINEERING / MALWARE are spelled the same in both APIs), the Redis
cache shape. What differs underneath:

  * `GET https://webrisk.googleapis.com/v1/uris:search?uri=…&threatTypes=…`
    (one URI a request; `threatTypes` repeated per type), key in the
    x-goog-api-key header, never in the URL;
  * a match answers {"threat": {"threatTypes": [...], "expireTime": "…"}}
    and no match answers {} — and "Clients must not cache this response
    past this timestamp", so a positive answer is cached until expireTime
    (capped at the usual hour), a negative one for the usual five minutes;
  * the threat types asked for are MALWARE, SOCIAL_ENGINEERING and
    UNWANTED_SOFTWARE (Web Risk has no POTENTIALLY_HARMFUL_APPLICATION).

Web Risk's terms bar passing its verdicts on to third parties: the
server-confirmed-hosts publisher (PUBLISH_CONFIRMED_THREATS) stays off with
this client exactly as with Safe Browsing.
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from api.services.safe_browsing import (
    NEGATIVE_CACHE_TTL, POSITIVE_CACHE_TTL, CheckResult, CheckStatus, ThreatMatch, _cache_get, _cache_set,
)

logger = logging.getLogger("cleanway.web_risk")

WEB_RISK_API_URL = "https://webrisk.googleapis.com/v1/uris:search"
WEB_RISK_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
WEB_RISK_TIMEOUT_SECONDS = 3.0
WEB_RISK_RETRY_COUNT = 2  # total attempts = 1 + RETRY_COUNT
CACHE_PREFIX = "wr:"
# One URI a request: a batch is this many lookups side by side.
BATCH_CONCURRENCY = 4


def seconds_until(expire_time: Optional[str], now: Optional[float] = None) -> Optional[int]:
    """Seconds from `now` to an RFC 3339 UTC timestamp ("2026-09-29T15:01:23Z",
    fractional seconds allowed); None when it cannot be read. Never negative."""
    if not expire_time or not isinstance(expire_time, str):
        return None
    text = expire_time.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    current = time.time() if now is None else now
    return max(0, int(when.timestamp() - current))


def positive_ttl(result: CheckResult) -> int:
    """How long a match may be cached: until its expireTime, at most the
    usual hour; a match without a readable expiry only as long as a
    negative answer."""
    durations = [m.cache_duration for m in result.matches if m.cache_duration is not None]
    if not durations:
        return NEGATIVE_CACHE_TTL
    return max(1, min(min(durations), POSITIVE_CACHE_TTL))


def parse_response(response: dict, domain: str, now: Optional[float] = None) -> CheckResult:
    threat = (response or {}).get("threat") or {}
    types = [str(t) for t in (threat.get("threatTypes") or []) if t]
    if not types:
        return CheckResult(status=CheckStatus.safe)
    expires_in = seconds_until(threat.get("expireTime"), now)
    matches = tuple(
        ThreatMatch(url=f"http://{domain}/", threat_type=t, platform="ANY_PLATFORM", cache_duration=expires_in)
        for t in types
    )
    logger.info("web_risk_hit", extra={"domain": domain, "threat_types": types})
    return CheckResult(status=CheckStatus.threat, matches=matches)


def _params(domain: str) -> list[tuple[str, str]]:
    return [("uri", f"http://{domain}/")] + [("threatTypes", t) for t in WEB_RISK_THREAT_TYPES]


async def _request_with_retry(domain: str, api_key: str, timeout: float) -> dict:
    """One lookup, retried on timeouts, network errors, 429 and 5xx."""
    last_exc: Optional[Exception] = None
    for attempt in range(WEB_RISK_RETRY_COUNT + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(WEB_RISK_API_URL, params=_params(domain),
                                        headers={"x-goog-api-key": api_key})
                resp.raise_for_status()
                return resp.json() or {}
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            last_exc = e
            if status < 500 and status != 429:
                raise
            logger.info("web_risk_retry", extra={"attempt": attempt, "status": status})
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            last_exc = e
            logger.info("web_risk_retry", extra={"attempt": attempt, "error": str(e)})
        if attempt < WEB_RISK_RETRY_COUNT:
            await asyncio.sleep(0.2 * (2 ** attempt))
    assert last_exc is not None
    raise last_exc


class WebRiskClient:
    """Same surface as safe_browsing.SafeBrowsingClient: `is_configured`,
    `check(domain)`, `check_batch(domains)`; never raises."""

    def __init__(self, api_key: str = "", timeout: float = WEB_RISK_TIMEOUT_SECONDS) -> None:
        self._api_key = api_key
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def check(self, domain: str) -> CheckResult:
        if not self.is_configured:
            return CheckResult(status=CheckStatus.unavailable, reason="no_api_key")
        cached = await _cache_get(domain, prefix=CACHE_PREFIX)
        if cached is not None:
            return cached
        try:
            result = parse_response(await _request_with_retry(domain, self._api_key, self._timeout), domain)
        except Exception as e:  # noqa: BLE001
            status = getattr(getattr(e, "response", None), "status_code", None)
            logger.warning("web_risk_api_error", extra={"error": type(e).__name__, "status": status,
                                                        "domain": domain})
            result = CheckResult(status=CheckStatus.unavailable, reason=type(e).__name__)
        ttl = positive_ttl(result) if result.status == CheckStatus.threat else None
        await _cache_set(domain, result, prefix=CACHE_PREFIX, ttl=ttl)
        return result

    async def check_batch(self, domains: list[str]) -> dict[str, CheckResult]:
        """One lookup per distinct domain, a few side by side. A failure
        marks that domain unavailable and no other."""
        ordered = list(dict.fromkeys(d.lower().strip() for d in domains if d and d.strip()))
        if not self.is_configured:
            return {d: CheckResult(status=CheckStatus.unavailable, reason="no_api_key") for d in ordered}
        gate = asyncio.Semaphore(BATCH_CONCURRENCY)

        async def _one(d: str) -> CheckResult:
            async with gate:
                return await self.check(d)

        results = await asyncio.gather(*(_one(d) for d in ordered))
        return dict(zip(ordered, results))
