"""Verdicts cached before the SSRF fix must not outlive it (#197 follow-up).

Before #197 an internal name (redis.railway.internal) got 'dangerous 100,
ssrf_blocked — resolves to a blocked network', cached for a day. After the
deploy production still served it from cache, so the anonymous check kept
telling internal names apart from missing ones. A cached verdict carrying
the retired ssrf_blocked reason is a cache miss now.
"""
from __future__ import annotations

import asyncio
import json

from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import cache as cache_mod
from api.services.verdict_basis import not_found_result


def _old_ssrf_verdict(domain: str) -> str:
    return DomainResult(
        domain=domain, score=100, level=RiskLevel.dangerous,
        reasons=[DomainReason(signal="ssrf_blocked", detail="Domain resolves to a blocked network", weight=100)],
        exists=True, verdict_basis="heuristics",
    ).model_dump_json()


def test_public_cache_ignores_retired_ssrf_verdicts(fake_redis):
    asyncio.run(fake_redis.set(public_router._PUBLIC_CACHE_PREFIX + "redis.railway.internal",
                               _old_ssrf_verdict("redis.railway.internal")))
    assert asyncio.run(public_router._get_public_cache("redis.railway.internal")) is None


def test_public_cache_still_serves_current_verdicts(fake_redis):
    asyncio.run(fake_redis.set(public_router._PUBLIC_CACHE_PREFIX + "gone.example.com",
                               not_found_result("gone.example.com").model_dump_json()))
    hit = asyncio.run(public_router._get_public_cache("gone.example.com"))
    assert hit is not None and hit.cached is True and hit.exists is False


def test_check_cache_ignores_retired_ssrf_verdicts(fake_redis):
    asyncio.run(fake_redis.set("check:redis.railway.internal", _old_ssrf_verdict("redis.railway.internal")))
    assert asyncio.run(cache_mod.get_cached_result("redis.railway.internal")) is None
    asyncio.run(fake_redis.set("check:ok.example.com", json.dumps(
        not_found_result("ok.example.com").model_dump(mode="json"))))
    assert asyncio.run(cache_mod.get_cached_result("ok.example.com")) is not None
