"""Capacity test only: fill the rest of what production Redis holds next to
the blocklist (scripts/doh_loadtest.py seed): tranco:ranks (~1M-entry hash,
scripts/refresh_tranco.py) and the :prev copies the blocklist publisher keeps
for rollback. Synthetic names, real shapes. Run inside the API image:

  docker run --rm --network cwcap -e REDIS_URL=redis://cwcap-redis:6379 \\
      -v $PWD/scripts:/app/scripts:ro cleanway-api python scripts/capacity/seed_extra.py
"""
import asyncio
import json
import os

import redis.asyncio as redis


async def main() -> None:
    r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    top = json.load(open("/app/data/top_100k.json"))  # a list of names, by rank
    pipe = r.pipeline(transaction=False)
    n = 0
    for k in range(10):
        for i, d in enumerate(top):
            head, _, tail = d.partition(".")
            name = d if k == 0 else f"{head}{k}.{tail or 'com'}"
            pipe.hset("tranco:ranks", name, str(k * len(top) + i + 1))
            n += 1
            if n % 20000 == 0:
                await pipe.execute()
    await pipe.execute()
    await r.sunionstore("dangerous_domains:prev", ["dangerous_domains"])
    await r.set("dangerous_domains:mobile:v1:prev", await r.get("dangerous_domains:mobile:v1"))
    print("tranco:ranks", await r.hlen("tranco:ranks"))
    await r.aclose()


if __name__ == "__main__":
    asyncio.run(main())
