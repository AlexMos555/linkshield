import json
from typing import Optional

import redis.asyncio as redis

from api.config import get_settings
from api.models.schemas import DomainResult

_redis_client: Optional[redis.Redis] = None

# Reasons no fresh analysis produces any more. A cached verdict carrying one
# is a miss: "ssrf_blocked" ("resolves to a blocked network") told internal
# names apart from missing ones and was retired in #197 — internal names now
# get the not-found verdict.
RETIRED_REASONS = frozenset({"ssrf_blocked"})


def is_retired(result: DomainResult) -> bool:
    signals = {r.signal for r in result.reasons or ()}
    if signals & RETIRED_REASONS:
        return True
    # A level the analyzer gave an LLM judge's shifted score by its old lines
    # (30 / 70) that the scorer's (20 / 50) do not: 'safe' at 21-29 (two
    # phishing hosts on 2026-11-01), caution at 51-69. And any judged score
    # past the top of caution: the judge alone no longer lifts one there, and
    # by the old lines a caution of 50 it lifted to 70 was 'dangerous' — a
    # full-page block in the extension. Fresh analyses do neither since
    # 2026-11-03; a full verdict is cached for a day.
    if "llm_judge" in signals:
        from api.services.scoring import DANGEROUS_ABOVE, level_for_score
        return result.level != level_for_score(result.score) or result.score > DANGEROUS_ABOVE
    return False


async def get_redis() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def get_cached_result(domain: str) -> Optional[DomainResult]:
    """Get cached domain check result."""
    try:
        r = await get_redis()
        data = await r.get(f"check:{domain}")
        if data:
            result = DomainResult(**json.loads(data))
            if is_retired(result):
                return None
            result.cached = True
            return result
    except Exception:
        pass
    return None


async def cache_result(result: DomainResult) -> None:
    """Cache domain check result with appropriate TTL."""
    settings = get_settings()

    if result.level == "safe":
        ttl = settings.cache_ttl_safe
    elif result.level == "caution":
        ttl = settings.cache_ttl_suspicious
    else:
        ttl = settings.cache_ttl_dangerous

    try:
        r = await get_redis()
        data = result.model_dump_json()
        await r.setex(f"check:{result.domain}", ttl, data)
    except Exception:
        pass  # Cache failures shouldn't break the API


async def close_redis() -> None:
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None
