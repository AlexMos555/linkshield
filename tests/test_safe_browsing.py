"""
Tests for the Google Safe Browsing client wrapper.

Covers:
- Typed result parsing (safe, threat, unavailable)
- Single-domain and batch lookups
- Redis cache (read, write, decoding, TTL selection)
- Retry on transient errors and 5xx
- Fallback behavior when API key missing
- Legacy boolean API (backward-compat with analyzer.py)
"""
from __future__ import annotations

from typing import Dict
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from api.services import safe_browsing as sb


# ─── Fake redis ──────────────────────────────────────────────────────────────


class FakeRedis:
    def __init__(self) -> None:
        self._data: Dict[str, str] = {}
        self._ttl: Dict[str, int] = {}

    async def get(self, key: str):
        return self._data.get(key)

    async def setex(self, key: str, ttl: int, value: str):
        self._data[key] = value
        self._ttl[key] = ttl
        return True

    async def incr(self, key: str) -> int:  # pragma: no cover — unused here
        self._data[key] = int(self._data.get(key, 0)) + 1
        return int(self._data[key])

    async def expire(self, key: str, seconds: int) -> bool:  # pragma: no cover
        self._ttl[key] = seconds
        return True

    async def ttl(self, key: str) -> int:  # pragma: no cover
        return self._ttl.get(key, -1)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr(sb, "get_redis", _get_redis)
    sb.reset_client()
    yield fake
    sb.reset_client()


@pytest.fixture
def configured(monkeypatch):
    """Force a stable API key regardless of env."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "google_safe_browsing_key", "test-api-key", raising=False)
    sb.reset_client()
    yield settings
    sb.reset_client()


# ─── Pure-function unit tests ────────────────────────────────────────────────


def test_parse_duration_seconds_happy():
    assert sb._parse_duration_seconds("300s") == 300
    assert sb._parse_duration_seconds("1.5s") == 1
    assert sb._parse_duration_seconds("60") == 60


def test_parse_duration_seconds_invalid():
    assert sb._parse_duration_seconds(None) is None
    assert sb._parse_duration_seconds("") is None
    assert sb._parse_duration_seconds("garbage") is None
    assert sb._parse_duration_seconds("-5s") == 0  # clamped at 0


def test_extract_domain_from_url():
    assert sb._extract_domain_from_url("https://evil.test/path?q=1") == "evil.test"
    assert sb._extract_domain_from_url("http://EXAMPLE.com") == "example.com"
    assert sb._extract_domain_from_url("bare.domain") == "bare.domain"


def test_threat_match_roundtrip():
    original = sb.ThreatMatch(
        url="https://bad.test/",
        threat_type="SOCIAL_ENGINEERING",
        platform="ANY_PLATFORM",
        cache_duration=300,
    )
    restored = sb.ThreatMatch.from_dict(original.to_dict())
    assert original == restored


def test_check_result_roundtrip():
    original = sb.CheckResult(
        status=sb.CheckStatus.threat,
        matches=(sb.ThreatMatch(url="u1"), sb.ThreatMatch(url="u2")),
    )
    restored = sb.CheckResult.from_dict(original.to_dict())
    assert restored.status == sb.CheckStatus.threat
    assert len(restored.matches) == 2
    assert restored.cached is True  # from_dict defaults to cached=True


def test_is_threat_property():
    safe = sb.CheckResult(status=sb.CheckStatus.safe)
    threat = sb.CheckResult(status=sb.CheckStatus.threat)
    unavailable = sb.CheckResult(status=sb.CheckStatus.unavailable)
    assert safe.is_threat is False
    assert threat.is_threat is True
    assert unavailable.is_threat is False


def test_positive_ttl_uses_api_duration():
    r = sb.CheckResult(
        status=sb.CheckStatus.threat,
        matches=(
            sb.ThreatMatch(url="a", cache_duration=1200),
            sb.ThreatMatch(url="b", cache_duration=600),
        ),
    )
    # min of cache_durations, floored at 60
    assert sb._positive_ttl(r) == 600


def test_positive_ttl_fallback_when_no_duration():
    r = sb.CheckResult(status=sb.CheckStatus.threat, matches=(sb.ThreatMatch(url="a"),))
    assert sb._positive_ttl(r) == sb.POSITIVE_CACHE_TTL


def test_build_payload_shape():
    payload = sb.SafeBrowsingClient._build_payload(["a.test", "b.test"])
    assert payload["client"]["clientId"] == sb.GSB_CLIENT_ID
    entries = payload["threatInfo"]["threatEntries"]
    assert len(entries) == 4  # http + https per domain
    urls = {e["url"] for e in entries}
    assert "http://a.test/" in urls and "https://b.test/" in urls


def test_parse_single_safe():
    result = sb.SafeBrowsingClient._parse_single({"matches": []}, "good.test")
    assert result.status == sb.CheckStatus.safe
    assert result.matches == ()


def test_parse_single_threat():
    raw = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "http://evil.test/"},
                "cacheDuration": "300s",
            }
        ]
    }
    result = sb.SafeBrowsingClient._parse_single(raw, "evil.test")
    assert result.status == sb.CheckStatus.threat
    assert len(result.matches) == 1
    assert result.matches[0].threat_type == "SOCIAL_ENGINEERING"
    assert result.matches[0].cache_duration == 300


def test_parse_batch_groups_by_domain():
    raw = {
        "matches": [
            {"threatType": "MALWARE", "threat": {"url": "http://a.test/"}},
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "https://a.test/"}},
            {"threatType": "MALWARE", "threat": {"url": "http://b.test/"}},
        ]
    }
    result = sb.SafeBrowsingClient._parse_batch(raw, ["a.test", "b.test", "c.test"])
    assert result["a.test"].status == sb.CheckStatus.threat
    assert len(result["a.test"].matches) == 2
    assert result["b.test"].status == sb.CheckStatus.threat
    assert result["c.test"].status == sb.CheckStatus.safe


# ─── Integration tests: client.check() with mocked httpx ─────────────────────


@pytest.mark.asyncio
async def test_check_no_api_key_returns_unavailable(fake_redis, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "google_safe_browsing_key", "", raising=False)
    sb.reset_client()

    client = sb.get_client()
    result = await client.check("anything.test")
    assert result.status == sb.CheckStatus.unavailable
    assert result.reason == "no_api_key"


@pytest.mark.asyncio
async def test_check_safe_hits_api_then_caches(fake_redis, configured, monkeypatch):
    call_count = {"n": 0}

    async def fake_request(payload, api_key, timeout):
        call_count["n"] += 1
        return {"matches": []}

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)

    client = sb.get_client()
    r1 = await client.check("good.test")
    r2 = await client.check("good.test")  # should come from cache

    assert r1.status == sb.CheckStatus.safe
    assert r1.cached is False
    assert r2.status == sb.CheckStatus.safe
    assert r2.cached is True
    assert call_count["n"] == 1


@pytest.mark.asyncio
async def test_check_threat_parsed_and_cached(fake_redis, configured, monkeypatch):
    async def fake_request(payload, api_key, timeout):
        return {
            "matches": [
                {
                    "threatType": "MALWARE",
                    "threat": {"url": "http://evil.test/"},
                    "cacheDuration": "180s",
                }
            ]
        }

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)

    client = sb.get_client()
    result = await client.check("evil.test")
    assert result.status == sb.CheckStatus.threat
    assert result.matches[0].threat_type == "MALWARE"

    # Verify it was written to cache
    assert fake_redis._data.get("gsb:evil.test") is not None
    # TTL should be derived from cacheDuration (180s), min-floored at 60
    assert fake_redis._ttl["gsb:evil.test"] == 180


@pytest.mark.asyncio
async def test_check_api_error_returns_unavailable(fake_redis, configured, monkeypatch):
    async def fake_request(payload, api_key, timeout):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)

    client = sb.get_client()
    result = await client.check("any.test")
    assert result.status == sb.CheckStatus.unavailable
    assert result.reason == "TimeoutException"
    # Unavailable cached with short TTL to allow recovery
    assert fake_redis._ttl["gsb:any.test"] == sb.UNAVAILABLE_CACHE_TTL


@pytest.mark.asyncio
async def test_batch_uses_cache_for_known(fake_redis, configured, monkeypatch):
    """Cached domains must NOT count against the API call."""
    # Pre-populate cache for two domains
    cached_safe = sb.CheckResult(status=sb.CheckStatus.safe)
    cached_threat = sb.CheckResult(
        status=sb.CheckStatus.threat, matches=(sb.ThreatMatch(url="http://x.test/"),)
    )
    await sb._cache_set("cached-safe.test", cached_safe)
    await sb._cache_set("cached-threat.test", cached_threat)

    api_calls = []

    async def fake_request(payload, api_key, timeout):
        api_calls.append(payload)
        # Return empty matches for the uncached domains
        return {"matches": []}

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)

    client = sb.get_client()
    result = await client.check_batch(
        ["cached-safe.test", "cached-threat.test", "new-one.test"]
    )

    assert result["cached-safe.test"].status == sb.CheckStatus.safe
    assert result["cached-safe.test"].cached is True
    assert result["cached-threat.test"].status == sb.CheckStatus.threat
    assert result["new-one.test"].status == sb.CheckStatus.safe
    # API called only for the uncached one
    assert len(api_calls) == 1
    entries = api_calls[0]["threatInfo"]["threatEntries"]
    urls = {e["url"] for e in entries}
    assert "http://new-one.test/" in urls


@pytest.mark.asyncio
async def test_batch_chunk_failure_localized(fake_redis, configured, monkeypatch):
    """A failing chunk should not poison other chunks."""

    call_count = {"n": 0}

    async def fake_request(payload, api_key, timeout):
        call_count["n"] += 1
        # First chunk fails, second succeeds
        if call_count["n"] == 1:
            raise httpx.ConnectError("down")
        return {"matches": []}

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)
    monkeypatch.setattr(sb, "GSB_MAX_URLS_PER_REQUEST", 4)  # 2 domains/chunk
    client = sb.get_client()

    domains = ["a.test", "b.test", "c.test", "d.test"]
    result = await client.check_batch(domains)

    # First 2 -> unavailable; last 2 -> safe
    assert result["a.test"].status == sb.CheckStatus.unavailable
    assert result["b.test"].status == sb.CheckStatus.unavailable
    assert result["c.test"].status == sb.CheckStatus.safe
    assert result["d.test"].status == sb.CheckStatus.safe


@pytest.mark.asyncio
async def test_batch_no_api_key_all_unavailable(fake_redis, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "google_safe_browsing_key", "", raising=False)
    sb.reset_client()
    client = sb.get_client()

    result = await client.check_batch(["a.test", "b.test"])
    for r in result.values():
        assert r.status == sb.CheckStatus.unavailable
        assert r.reason == "no_api_key"


@pytest.mark.asyncio
async def test_batch_dedupes_input(fake_redis, configured, monkeypatch):
    api_calls = []

    async def fake_request(payload, api_key, timeout):
        api_calls.append(payload)
        return {"matches": []}

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)
    client = sb.get_client()

    result = await client.check_batch(["dup.test", "DUP.TEST", "dup.test"])
    assert len(result) == 1  # deduped
    # Only 1 API request for 1 unique domain
    assert len(api_calls) == 1


# ─── Retry behavior ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retry_on_5xx_then_success(monkeypatch):
    calls = {"n": 0}

    async def fake_do_request(client, payload, api_key):
        calls["n"] += 1
        if calls["n"] < 2:
            response = httpx.Response(503)
            raise httpx.HTTPStatusError("server down", request=MagicMock(), response=response)
        return {"matches": []}

    monkeypatch.setattr(sb, "_do_request", fake_do_request)
    monkeypatch.setattr(sb.asyncio, "sleep", AsyncMock())  # skip backoff delay

    result = await sb._request_with_retry(
        sb.SafeBrowsingClient._build_payload(["x.test"]),
        "key",
        timeout=1.0,
    )
    assert result == {"matches": []}
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_no_retry_on_400(monkeypatch):
    async def fake_do_request(client, payload, api_key):
        response = httpx.Response(400)
        raise httpx.HTTPStatusError("bad req", request=MagicMock(), response=response)

    monkeypatch.setattr(sb, "_do_request", fake_do_request)
    with pytest.raises(httpx.HTTPStatusError):
        await sb._request_with_retry(
            sb.SafeBrowsingClient._build_payload(["x.test"]),
            "key",
            timeout=1.0,
        )


# ─── Legacy boolean API ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_legacy_check_safe_browsing_true(fake_redis, configured, monkeypatch):
    async def fake_request(payload, api_key, timeout):
        return {"matches": [{"threat": {"url": "http://x.test/"}}]}

    monkeypatch.setattr(sb, "_request_with_retry", fake_request)
    result = await sb.check_safe_browsing("x.test")
    assert result is True


@pytest.mark.asyncio
async def test_legacy_check_safe_browsing_false_on_unavailable(fake_redis, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "google_safe_browsing_key", "", raising=False)
    sb.reset_client()
    assert await sb.check_safe_browsing("any.test") is False
