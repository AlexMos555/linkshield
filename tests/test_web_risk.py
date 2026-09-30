"""Google Web Risk client (api/services/web_risk) behind WEB_RISK_API_KEY.

With the key set, safe_browsing.get_client() hands out this client and the
analyzer's `safe_browsing_hit`, the email router and the confirmed-threats
recorder all read Web Risk's answer through the same CheckResult. Without
it, Safe Browsing v4 exactly as before. HTTP is mocked throughout.
"""
from __future__ import annotations

import json
import time
from typing import Dict

import httpx
import pytest

from api.services import confirmed_threats
from api.services import safe_browsing as sb
from api.services import web_risk


class FakeRedis:
    def __init__(self) -> None:
        self.data: Dict[str, str] = {}
        self.ttl: Dict[str, int] = {}

    async def get(self, key):
        return self.data.get(key)

    async def setex(self, key, ttl, value):
        self.data[key] = value
        self.ttl[key] = ttl
        return True


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
def keys(monkeypatch):
    """keys(web_risk=..., gsb=...) sets both keys for one test."""
    from api import config

    settings = config.get_settings()

    def _set(web_risk: str = "", gsb: str = "") -> None:
        monkeypatch.setattr(settings, "web_risk_api_key", web_risk, raising=False)
        monkeypatch.setattr(settings, "google_safe_browsing_key", gsb, raising=False)
        sb.reset_client()

    _set()
    yield _set
    sb.reset_client()


class _Response:
    def __init__(self, status: int, body: dict) -> None:
        self.status_code, self._body = status, body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=httpx.Request("GET", web_risk.WEB_RISK_API_URL),
                                        response=httpx.Response(self.status_code))

    def json(self) -> dict:
        return self._body


def _http(monkeypatch, answers) -> list[dict]:
    """Serve `answers` (status, body) in order; record each request."""
    queue, seen = list(answers), []

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, params=None, headers=None):
            seen.append({"url": url, "params": list(params or []), "headers": dict(headers or {})})
            status, body = queue.pop(0)
            return _Response(status, body)

    monkeypatch.setattr(web_risk.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(web_risk.asyncio, "sleep", _no_sleep)
    return seen


async def _no_sleep(_s):
    return None


def _threat(types, expires_in: int) -> dict:
    when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + expires_in))
    return {"threat": {"threatTypes": types, "expireTime": f"{when}.123456Z"}}


# ── Backend selection ────────────────────────────────────────────────────────


def test_without_the_key_safe_browsing_v4_is_the_client(keys):
    keys(gsb="gsb-key")
    assert isinstance(sb.get_client(), sb.SafeBrowsingClient)


def test_with_the_key_web_risk_is_the_client_and_a_new_key_rebuilds_it(keys):
    keys(web_risk="wr-1", gsb="gsb-key")
    first = sb.get_client()
    assert isinstance(first, web_risk.WebRiskClient) and first.is_configured
    keys(web_risk="wr-2")
    second = sb.get_client()
    assert isinstance(second, web_risk.WebRiskClient) and second is not first
    keys(gsb="gsb-key")
    assert isinstance(sb.get_client(), sb.SafeBrowsingClient)


# ── Pure parsing ─────────────────────────────────────────────────────────────


def test_seconds_until_reads_rfc3339_and_rejects_junk():
    now = 1_790_000_000.0  # 2026-09-21T14:13:20Z
    assert web_risk.seconds_until("2026-09-21T14:13:20Z", now) == 0
    assert web_risk.seconds_until("2026-09-21T14:23:20.5Z", now) == 600
    assert web_risk.seconds_until("2026-09-21T14:13:19Z", now) == 0, "never negative"
    assert web_risk.seconds_until("soon", now) is None
    assert web_risk.seconds_until(None, now) is None


def test_no_match_is_safe_and_a_match_carries_its_types():
    assert web_risk.parse_response({}, "fine.example").status is sb.CheckStatus.safe
    assert web_risk.parse_response({"threat": {}}, "fine.example").status is sb.CheckStatus.safe
    result = web_risk.parse_response(_threat(["SOCIAL_ENGINEERING", "MALWARE"], 600), "evil.xyz")
    assert result.is_threat
    assert [m.threat_type for m in result.matches] == ["SOCIAL_ENGINEERING", "MALWARE"]
    assert all(590 <= m.cache_duration <= 600 for m in result.matches)


def test_a_match_is_cached_until_its_expiry_capped_at_an_hour():
    soon = web_risk.parse_response(_threat(["MALWARE"], 120), "a.xyz")
    assert 110 <= web_risk.positive_ttl(soon) <= 120
    late = web_risk.parse_response(_threat(["MALWARE"], 7 * 86_400), "b.xyz")
    assert web_risk.positive_ttl(late) == sb.POSITIVE_CACHE_TTL
    unreadable = web_risk.parse_response({"threat": {"threatTypes": ["MALWARE"], "expireTime": "?"}}, "c.xyz")
    assert web_risk.positive_ttl(unreadable) == sb.NEGATIVE_CACHE_TTL


# ── The client ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_no_key_is_unavailable_without_a_request(fake_redis, monkeypatch):
    seen = _http(monkeypatch, [])
    result = await web_risk.WebRiskClient(api_key="").check("evil.xyz")
    assert result.status is sb.CheckStatus.unavailable and result.reason == "no_api_key"
    assert seen == []


@pytest.mark.asyncio
async def test_the_key_travels_in_a_header_and_the_three_threat_types_in_the_query(fake_redis, monkeypatch):
    seen = _http(monkeypatch, [(200, {})])
    result = await web_risk.WebRiskClient(api_key="wr-key").check("fine.example")
    assert result.status is sb.CheckStatus.safe
    request = seen[0]
    assert request["url"] == web_risk.WEB_RISK_API_URL
    assert request["headers"] == {"x-goog-api-key": "wr-key"}
    assert ("uri", "http://fine.example/") in request["params"]
    assert [v for k, v in request["params"] if k == "threatTypes"] == ["MALWARE", "SOCIAL_ENGINEERING",
                                                                       "UNWANTED_SOFTWARE"]
    assert "wr-key" not in json.dumps(request["params"])


@pytest.mark.asyncio
async def test_answers_are_cached_under_their_own_prefix(fake_redis, monkeypatch):
    seen = _http(monkeypatch, [(200, {}), (200, _threat(["SOCIAL_ENGINEERING"], 900))])
    client = web_risk.WebRiskClient(api_key="wr-key")
    assert (await client.check("fine.example")).status is sb.CheckStatus.safe
    assert fake_redis.ttl["wr:fine.example"] == sb.NEGATIVE_CACHE_TTL
    assert (await client.check("fine.example")).cached, "the second answer comes from Redis"
    assert len(seen) == 1

    threat = await client.check("evil.xyz")
    assert threat.is_threat
    assert 890 <= fake_redis.ttl["wr:evil.xyz"] <= 900
    assert "gsb:evil.xyz" not in fake_redis.data, "never in Safe Browsing's cache"


@pytest.mark.asyncio
async def test_a_5xx_is_retried_and_a_lasting_error_is_unavailable(fake_redis, monkeypatch):
    seen = _http(monkeypatch, [(503, {}), (200, _threat(["MALWARE"], 300))])
    assert (await web_risk.WebRiskClient(api_key="k").check("evil.xyz")).is_threat
    assert len(seen) == 2

    _http(monkeypatch, [(403, {})])  # billing off / key refused: no retry
    result = await web_risk.WebRiskClient(api_key="k").check("other.xyz")
    assert result.status is sb.CheckStatus.unavailable and result.reason == "HTTPStatusError"
    assert fake_redis.ttl["wr:other.xyz"] == sb.UNAVAILABLE_CACHE_TTL


@pytest.mark.asyncio
async def test_batch_asks_once_per_distinct_domain(fake_redis, monkeypatch):
    seen = _http(monkeypatch, [(200, {}), (200, _threat(["MALWARE"], 300))])
    results = await web_risk.WebRiskClient(api_key="k").check_batch(["A.example", "a.example ", "evil.xyz"])
    assert set(results) == {"a.example", "evil.xyz"}
    assert results["evil.xyz"].is_threat and not results["a.example"].is_threat
    assert len(seen) == 2
    assert await web_risk.WebRiskClient(api_key="").check_batch(["x.example"]) == {
        "x.example": sb.CheckResult(status=sb.CheckStatus.unavailable, reason="no_api_key"),
    }


# ── Through the shared entry points ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_analyzers_boolean_check_reads_web_risk(fake_redis, keys, monkeypatch):
    keys(web_risk="wr-key")
    _http(monkeypatch, [(200, _threat(["SOCIAL_ENGINEERING"], 300)), (200, {})])
    assert await sb.check_safe_browsing("evil.xyz") is True
    assert await sb.check_safe_browsing("fine.example") is False


@pytest.mark.asyncio
async def test_confirmed_threats_sees_web_risk_threat_types(fake_redis, keys, monkeypatch):
    keys(web_risk="wr-key")
    _http(monkeypatch, [(200, _threat(["SOCIAL_ENGINEERING"], 300))])
    assert await confirmed_threats._safe_browsing_types("evil.xyz") == frozenset({"SOCIAL_ENGINEERING"})
