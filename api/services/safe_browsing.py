"""
Google Safe Browsing v4 client wrapper.

Provides a typed, cached, batch-capable wrapper around the
``threatMatches:find`` endpoint. Used by analyzer.py (single-domain) and can be
used for batch lookups from the /check router.

Design goals:

- **Typed**: ``CheckResult`` / ``ThreatMatch`` frozen dataclasses; callers never
  need to touch raw JSON.
- **Cached**: Redis-backed. Positive results honor the API's ``cacheDuration``
  field, negative results are cached for a short window so repeated hot-path
  queries don't all hit Google. Unavailable results are cached for an even
  shorter window so we recover quickly from transient outages.
- **Fallback**: when the API key is missing, the API is unreachable, or the
  circuit breaker is open, callers get ``status == unavailable`` instead of
  an exception — so the analyzer can degrade gracefully.
- **Retry**: exponential backoff for transient HTTP errors (5xx, timeouts).
- **Batchable**: ``check_batch(domains)`` wraps the batch API (up to 500 URLs
  per request) and merges cached + API results.

The circuit breaker is owned by the *caller* (analyzer.py uses
``safe_browsing_breaker.call(...)``), so this module does not wrap itself in
one — that keeps concerns separated.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

from api.config import get_settings
from api.services.cache import get_redis

logger = logging.getLogger("cleanway.safe_browsing")

# ─── Constants ────────────────────────────────────────────────────────────────

GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_MAX_URLS_PER_REQUEST = 500  # Google documented cap per request
GSB_TIMEOUT_SECONDS = 3.0
GSB_CLIENT_ID = "cleanway"
GSB_CLIENT_VERSION = "0.3.0"
GSB_RETRY_COUNT = 2  # Total attempts = 1 + RETRY_COUNT

DEFAULT_THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)

# Cache TTLs (seconds)
POSITIVE_CACHE_TTL = 3600   # 1 hour — threats ebb slowly, but not forever
NEGATIVE_CACHE_TTL = 300    # 5 min — new threats appear fast
UNAVAILABLE_CACHE_TTL = 60  # 1 min — quick recovery from outages

CACHE_PREFIX = "gsb:"


# ─── Types ────────────────────────────────────────────────────────────────────


class CheckStatus(str, Enum):
    """Outcome of a Safe Browsing lookup."""

    safe = "safe"
    threat = "threat"
    unavailable = "unavailable"  # no API key / transient / quota


@dataclass(frozen=True)
class ThreatMatch:
    url: str
    threat_type: str = "UNKNOWN"
    platform: str = "ANY_PLATFORM"
    cache_duration: Optional[int] = None  # seconds, parsed from response

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "threat_type": self.threat_type,
            "platform": self.platform,
            "cache_duration": self.cache_duration,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatMatch":
        return cls(
            url=data["url"],
            threat_type=data.get("threat_type", "UNKNOWN"),
            platform=data.get("platform", "ANY_PLATFORM"),
            cache_duration=data.get("cache_duration"),
        )


@dataclass(frozen=True)
class CheckResult:
    status: CheckStatus
    matches: tuple[ThreatMatch, ...] = field(default_factory=tuple)
    cached: bool = False
    reason: str = ""  # populated when status == unavailable

    @property
    def is_threat(self) -> bool:
        return self.status == CheckStatus.threat

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "matches": [m.to_dict() for m in self.matches],
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict, *, cached: bool = True) -> "CheckResult":
        return cls(
            status=CheckStatus(data["status"]),
            matches=tuple(ThreatMatch.from_dict(m) for m in data.get("matches", [])),
            cached=cached,
            reason=data.get("reason", ""),
        )


# ─── Parsing helpers ──────────────────────────────────────────────────────────


def _parse_duration_seconds(duration: Optional[str]) -> Optional[int]:
    """
    Parse Google's duration format (e.g. ``"300s"``, ``"1.5s"``) to an integer
    number of seconds. Returns None for unparseable input.
    """
    if not duration or not isinstance(duration, str):
        return None
    trimmed = duration.strip()
    if trimmed.endswith("s"):
        trimmed = trimmed[:-1]
    try:
        return max(0, int(float(trimmed)))
    except ValueError:
        return None


def _extract_domain_from_url(url: str) -> str:
    """Strip scheme + path, return bare host."""
    s = url
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    return s.lower()


# ─── Cache layer ──────────────────────────────────────────────────────────────


async def _cache_get(domain: str) -> Optional[CheckResult]:
    try:
        r = await get_redis()
        raw = await r.get(f"{CACHE_PREFIX}{domain}")
    except Exception as e:  # Redis unreachable — skip cache
        logger.debug("gsb_cache_get_failed", extra={"error": str(e), "domain": domain})
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return CheckResult.from_dict(data, cached=True)
    except (ValueError, KeyError) as e:
        logger.warning("gsb_cache_decode_failed", extra={"error": str(e), "domain": domain})
        return None


async def _cache_set(domain: str, result: CheckResult) -> None:
    if result.status == CheckStatus.threat:
        # Use API-supplied cacheDuration if any match provided it, else default
        ttl = _positive_ttl(result)
    elif result.status == CheckStatus.safe:
        ttl = NEGATIVE_CACHE_TTL
    else:
        ttl = UNAVAILABLE_CACHE_TTL
    try:
        r = await get_redis()
        await r.setex(f"{CACHE_PREFIX}{domain}", ttl, json.dumps(result.to_dict()))
    except Exception as e:
        logger.debug("gsb_cache_set_failed", extra={"error": str(e), "domain": domain})


def _positive_ttl(result: CheckResult) -> int:
    """Use the shortest cacheDuration across matches, floored at 60s."""
    durations = [m.cache_duration for m in result.matches if m.cache_duration]
    if durations:
        return max(60, min(durations))
    return POSITIVE_CACHE_TTL


# ─── HTTP call + retry ────────────────────────────────────────────────────────


async def _do_request(
    client: httpx.AsyncClient,
    payload: dict,
    api_key: str,
) -> dict:
    """
    Single HTTP POST to GSB with basic validation. Raises httpx.HTTPStatusError
    on 4xx/5xx; the caller handles retries.
    """
    resp = await client.post(
        GSB_API_URL,
        json=payload,
        headers={"x-goog-api-key": api_key},
    )
    resp.raise_for_status()
    return resp.json() or {}


async def _request_with_retry(payload: dict, api_key: str, timeout: float) -> dict:
    """Retry transient errors (timeouts, 5xx) with exponential backoff."""
    last_exc: Optional[Exception] = None
    for attempt in range(GSB_RETRY_COUNT + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                return await _do_request(client, payload, api_key)
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            last_exc = e
            # 4xx (except 429) is non-retryable
            if status < 500 and status != 429:
                raise
            logger.info(
                "gsb_retry",
                extra={"attempt": attempt, "status": status},
            )
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            last_exc = e
            logger.info("gsb_retry", extra={"attempt": attempt, "error": str(e)})
        if attempt < GSB_RETRY_COUNT:
            await asyncio.sleep(0.2 * (2**attempt))  # 200ms, 400ms
    assert last_exc is not None
    raise last_exc


# ─── Client ───────────────────────────────────────────────────────────────────


class SafeBrowsingClient:
    """
    Stateless wrapper around the Safe Browsing v4 `threatMatches:find` API.

    The client itself holds no connections — each call opens a fresh
    ``httpx.AsyncClient`` so callers can safely await concurrently.
    """

    def __init__(
        self,
        api_key: str = "",
        timeout: float = GSB_TIMEOUT_SECONDS,
    ) -> None:
        self._api_key = api_key
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    # ── Public API ────────────────────────────────────────────────────────────

    async def check(self, domain: str) -> CheckResult:
        """
        Check a single domain. Always returns a ``CheckResult`` — never raises.

        Cached hits short-circuit the HTTP call.
        """
        if not self.is_configured:
            return CheckResult(status=CheckStatus.unavailable, reason="no_api_key")

        cached = await _cache_get(domain)
        if cached is not None:
            return cached

        try:
            response = await _request_with_retry(
                self._build_payload([domain]),
                self._api_key,
                self._timeout,
            )
            result = self._parse_single(response, domain)
        except Exception as e:
            logger.warning(
                "safe_browsing_api_error",
                extra={"error": type(e).__name__, "domain": domain},
            )
            result = CheckResult(
                status=CheckStatus.unavailable,
                reason=f"{type(e).__name__}",
            )

        await _cache_set(domain, result)
        return result

    async def check_batch(self, domains: list[str]) -> dict[str, CheckResult]:
        """
        Check many domains. Returns mapping ``{domain: CheckResult}``.

        Behavior:
        - Domains with cache hits are served from Redis.
        - Remaining domains are split into chunks of ``GSB_MAX_URLS_PER_REQUEST``
          (each URL counts as one, and we submit 2 URLs/domain — http+https).
        - Per-chunk failures propagate ``status=unavailable`` to that chunk's
          domains only; other chunks are unaffected.
        """
        results: dict[str, CheckResult] = {}
        unknown: list[str] = []

        # Dedupe / normalize
        seen: set[str] = set()
        ordered: list[str] = []
        for d in domains:
            low = d.lower().strip()
            if low and low not in seen:
                seen.add(low)
                ordered.append(low)

        if not self.is_configured:
            return {d: CheckResult(status=CheckStatus.unavailable, reason="no_api_key") for d in ordered}

        # Check cache first
        for d in ordered:
            cached = await _cache_get(d)
            if cached is not None:
                results[d] = cached
            else:
                unknown.append(d)

        # Each domain expands to 2 URLs (http + https). Chunk accordingly.
        domains_per_chunk = GSB_MAX_URLS_PER_REQUEST // 2
        for i in range(0, len(unknown), domains_per_chunk):
            chunk = unknown[i : i + domains_per_chunk]
            try:
                response = await _request_with_retry(
                    self._build_payload(chunk),
                    self._api_key,
                    self._timeout,
                )
                chunk_results = self._parse_batch(response, chunk)
            except Exception as e:
                logger.warning(
                    "safe_browsing_batch_error",
                    extra={"error": type(e).__name__, "count": len(chunk)},
                )
                chunk_results = {
                    d: CheckResult(
                        status=CheckStatus.unavailable,
                        reason=type(e).__name__,
                    )
                    for d in chunk
                }

            for d, r in chunk_results.items():
                results[d] = r
                await _cache_set(d, r)

        return results

    # ── Internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _build_payload(domains: list[str]) -> dict:
        threat_entries: list[dict] = []
        for d in domains:
            threat_entries.append({"url": f"http://{d}/"})
            threat_entries.append({"url": f"https://{d}/"})
        return {
            "client": {"clientId": GSB_CLIENT_ID, "clientVersion": GSB_CLIENT_VERSION},
            "threatInfo": {
                "threatTypes": list(DEFAULT_THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries,
            },
        }

    @staticmethod
    def _parse_single(response: dict, domain: str) -> CheckResult:
        matches = response.get("matches") or []
        if not matches:
            return CheckResult(status=CheckStatus.safe)

        parsed = tuple(
            ThreatMatch(
                url=(m.get("threat") or {}).get("url", ""),
                threat_type=m.get("threatType", "UNKNOWN"),
                platform=m.get("platformType", "ANY_PLATFORM"),
                cache_duration=_parse_duration_seconds(m.get("cacheDuration")),
            )
            for m in matches
        )
        logger.info(
            "safe_browsing_hit",
            extra={"domain": domain, "threat_types": [p.threat_type for p in parsed]},
        )
        return CheckResult(status=CheckStatus.threat, matches=parsed)

    @staticmethod
    def _parse_batch(response: dict, domains: list[str]) -> dict[str, CheckResult]:
        """
        Group matches by domain (extracted from ``match.threat.url``).
        Domains with zero matches are marked safe.
        """
        by_domain: dict[str, list[ThreatMatch]] = {d: [] for d in domains}
        for m in response.get("matches") or []:
            url = (m.get("threat") or {}).get("url", "")
            d = _extract_domain_from_url(url)
            if d in by_domain:
                by_domain[d].append(
                    ThreatMatch(
                        url=url,
                        threat_type=m.get("threatType", "UNKNOWN"),
                        platform=m.get("platformType", "ANY_PLATFORM"),
                        cache_duration=_parse_duration_seconds(m.get("cacheDuration")),
                    )
                )

        out: dict[str, CheckResult] = {}
        for d, matches in by_domain.items():
            if matches:
                out[d] = CheckResult(status=CheckStatus.threat, matches=tuple(matches))
            else:
                out[d] = CheckResult(status=CheckStatus.safe)
        return out


# ─── Module-level convenience ─────────────────────────────────────────────────


_singleton: Optional[SafeBrowsingClient] = None


def get_client() -> SafeBrowsingClient:
    """
    Returns a process-wide client. Rebuilt whenever the API key changes (eg.
    when tests override settings).
    """
    global _singleton
    settings = get_settings()
    if _singleton is None or _singleton._api_key != settings.google_safe_browsing_key:
        _singleton = SafeBrowsingClient(api_key=settings.google_safe_browsing_key)
    return _singleton


def reset_client() -> None:
    """Test helper — forces the next `get_client()` call to rebuild."""
    global _singleton
    _singleton = None


# Backwards-compatible boolean API for existing analyzer.py / circuit breaker.
async def check_safe_browsing(domain: str) -> bool:
    """
    Legacy boolean interface. ``True`` if the domain is a known threat,
    ``False`` if safe, no API key, or the API is unavailable.

    New code should use ``get_client().check(domain)`` for full status.
    """
    result = await get_client().check(domain)
    return result.is_threat
