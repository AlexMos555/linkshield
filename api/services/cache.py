import json
from typing import Optional

import redis.asyncio as redis

from api.config import get_settings
from api.models.schemas import DomainResult

_redis_client: Optional[redis.Redis] = None


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
