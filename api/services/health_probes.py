"""The /health/deep components that watch grandma's protection, not the API.

Redis and Supabase decide whether /health/deep pages (HTTP 503). These two do
not — each has its own watcher that runs the full path from outside (the DNS
canary, the refresh job's red runs) — but until 2026-09-27 nothing a minute-
level monitor could see went red while the phones' list rotted or the gateway
stopped filtering: /health/deep stayed green through both. Now they are in the
body, and in `warnings`, where a keyword monitor can alert on them.

  * blocklist — the artifact phones sync: published, non-empty, and younger
    than MAX_HEALTHY_AGE_S (the canary's threshold).
  * doh — one query for the list canary through the gateway's real decision
    code (routers.doh.handle_query), in process, with an upstream that never
    touches the network and without the gateway's per-block log line. Pass = NXDOMAIN carrying OUR SOA marker. If the
    canary is not in `dangerous_domains` (set expired, Redis down so the
    gateway fails open, publisher broken), the stub upstream answers and the
    probe sees SERVFAIL — the state in which the DNS profile blocks nothing.

Both are bounded by PROBE_TIMEOUT_S and never raise: a probe that crashes is
reported as `{"ok": false, "error": <exception class>}`.
"""
from __future__ import annotations

import asyncio
import os
import struct
import time
from typing import Awaitable, Callable, Optional

from api.services.blocklist_artifact import LIST_CANARY, MAX_HEALTHY_AGE_S
from api.services.dns_wire import BLOCK_SOA_MNAME, parse_response

PROBE_TIMEOUT_S = 2.0
# The publisher writes the list canary into every artifact, so a list whose
# only entry is the canary protects nobody.
_MIN_REAL_COUNT = 2


async def _bounded(probe: Callable[[], Awaitable[dict]]) -> dict:
    try:
        return await asyncio.wait_for(probe(), timeout=PROBE_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as exc:  # noqa: BLE001 — a health probe must not raise
        return {"ok": False, "error": type(exc).__name__}


def blocklist_verdict(meta: Optional[dict], now: Optional[int] = None) -> dict:
    """Judge the published artifact's meta (None = nothing servable)."""
    if not meta:
        return {"ok": False, "error": "unavailable"}
    try:
        generated = int(meta.get("generated_at", 0))
        count = int(meta.get("count", 0))
    except (TypeError, ValueError):
        return {"ok": False, "error": "bad_meta"}
    age = max(0, int(now if now is not None else time.time()) - generated)
    out = {
        "ok": True,
        "version": str(meta.get("version", "")),
        "generated_at": generated,
        "age_s": age,
        "count": count,
        "max_age_s": MAX_HEALTHY_AGE_S,
    }
    if count < _MIN_REAL_COUNT:
        return {**out, "ok": False, "error": "empty"}
    if age > MAX_HEALTHY_AGE_S:
        return {**out, "ok": False, "error": "stale"}
    return out


async def _blocklist() -> dict:
    # load_artifact, not load_meta: the answer must be "phones can get it",
    # and a meta whose sha does not match the stored body is refused by the
    # sync route (503), so it is refused here too.
    from api.routers.blocklist import load_artifact
    loaded = await load_artifact()
    return blocklist_verdict(loaded[1] if loaded else None)


async def blocklist_component() -> dict:
    return await _bounded(_blocklist)


def _canary_query() -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in LIST_CANARY.split("."))
    header = os.urandom(2) + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
    return header + labels + b"\x00" + struct.pack("!HH", 1, 1)  # A, IN


async def _no_upstream(_wire: bytes) -> Optional[bytes]:
    return None


async def _doh() -> dict:
    from api.routers.doh import handle_query
    started = time.monotonic()
    body, status = await handle_query(_canary_query(), proxy=_no_upstream, log_block=False)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    from api.services.doh_filter import HOLDER
    # Which list the decision came from: the in-memory artifact (normal) or,
    # when it is not loaded, the per-query Redis fallback.
    out = {"probe": LIST_CANARY, "elapsed_ms": elapsed_ms, "filter": HOLDER.status()}
    if status != 200:
        return {**out, "ok": False, "error": f"http_{status}"}
    answer = parse_response(body)
    out = {**out, "rcode": answer.rcode}
    if answer.rcode == 3 and answer.soa_mname == BLOCK_SOA_MNAME:
        return {**out, "ok": True}
    return {**out, "ok": False, "error": "listed_name_not_blocked"}


async def doh_component() -> dict:
    return await _bounded(_doh)
