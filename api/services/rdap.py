"""Domain age and registrar from the registry's own RDAP server.

The server for a zone comes from IANA's RDAP bootstrap file (RFC 9224,
https://data.iana.org/rdap/dns.json), kept in memory for a day — IANA's own
Cache-Control — and refreshed in the background, so only the very first
lookup after start waits for it.

Until 2026-10-26 the lookup asked rdap.org instead. rdap.org answers every
name with a 302 to that same registry server (rdap.org/domain/example.com →
rdap.verisign.com/com/v1/domain/example.com); the client did not follow
redirects, so every lookup since the first release returned {}. rdap.org
covers no zone the bootstrap file does not (both answer nothing for .ru,
.io, .de, .co, .me, .eu), so asking the registry directly costs nothing and
saves a hop and a third party that saw every checked name.

What is asked:
  * the registrable name: login.example.com → example.com. Registries know
    only what they register and answer 404 (Verisign) or 400 (Google) for a
    host under it;
  * nothing for a tenant of a hosting or dynamic-DNS platform
    (scoring._platform_tenant_site): the registrable there is the platform,
    and vercel.app's registration (2020, through Tucows) is not one
    customer's site's;
  * nothing for an IP address, or a zone with no https server in the
    bootstrap file (.ru, .su, .рф have no RDAP at all).
Those answer {} — age unknown, as before.

The registry is contacted over the SSRF-pinned client (pinned_http): https
only, every address it resolves to public, redirects never followed, HTTP/2
offered. A registry or bootstrap failure (any status but 200 and 404, bad
JSON, no connection) raises: the check is then unmeasured and its breaker
counts it, never "no data". 404 is the registry's real answer and reads as {}.
On 2026-10-26, of 1,109 names asked: 993 answered 200, 76 404, 37 429 (33 of
them GMO Registry, .shop), 3 no connection; median 0.43 s, 7 above 2.5 s.

Privacy: the registry receives the registrable name only; IANA receives
nothing about the checked site.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from api.services.pinned_http import pinned_client
from api.services.scoring import _platform_tenant_site, registrable_domain
from api.services.tls_contexts import client_tls_context

logger = logging.getLogger("cleanway.rdap")

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
# IANA serves the file with Cache-Control: max-age=86400.
BOOTSTRAP_MAX_AGE_S = 24 * 3600
# After a failed refresh the old file stays in use; the next attempt waits
# this long instead of hitting IANA on every lookup while it is down.
BOOTSTRAP_RETRY_S = 600

# The clock the bootstrap's age is read on — a seam the tests replace.
_clock = time.monotonic


@dataclass
class _Bootstrap:
    servers: Optional[dict[str, str]] = None   # zone → https base URL, ending in /
    fetched_at: float = 0.0
    refresh: Optional[asyncio.Task] = None


_bootstrap = _Bootstrap()


async def registration(domain: str, timeout: float) -> dict:
    """{"age_days", "registered", "registrar"} — whichever the registry gives —
    or {} when there is no one to ask or the registry has no such name.
    Raises when the bootstrap file or the registry cannot be read."""
    name = _registered_name(domain)
    if name is None:
        return {}
    base = _server_for(name, await _servers(timeout))
    if base is None:
        return {}
    # HTTP/2 offered: TWNIC (.tw) answers 426 Upgrade Required to HTTP/1.1.
    async with pinned_client(timeout=timeout, http2=True) as client:
        resp = await client.get(f"{base}domain/{name}", headers={"Accept": "application/rdap+json"})
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()  # redirects too: never followed
    return _parse(resp.json(), datetime.now(timezone.utc))


def _registered_name(domain: str) -> Optional[str]:
    host = (domain or "").lower().strip().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None
    except ValueError:
        pass
    if not host or "." not in host or _platform_tenant_site(host):
        return None
    return registrable_domain(host)


def _server_for(name: str, servers: dict[str, str]) -> Optional[str]:
    """RFC 9224 §4: the longest matching zone. IANA lists TLDs only today."""
    labels = name.split(".")
    for i in range(1, len(labels)):
        base = servers.get(".".join(labels[i:]))
        if base:
            return base
    return None


# ── The bootstrap file ──

async def _servers(timeout: float) -> dict[str, str]:
    """The zone → server map. A stale one is answered at once while a refresh
    runs; without one, every caller waits for the same fetch. The fetch is
    its own task, so a caller cut off by its time limit does not cancel it."""
    boot = _bootstrap
    fresh = boot.servers is not None and _clock() - boot.fetched_at < BOOTSTRAP_MAX_AGE_S
    if fresh:
        return boot.servers
    loop = asyncio.get_running_loop()
    task = boot.refresh
    if task is None or task.done() or task.get_loop() is not loop:
        task = boot.refresh = loop.create_task(_refresh(boot, timeout))
        task.add_done_callback(_retrieve)
    if boot.servers is not None:
        return boot.servers
    return await asyncio.shield(task)


async def _refresh(boot: _Bootstrap, timeout: float) -> dict[str, str]:
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=client_tls_context()) as client:
            resp = await client.get(BOOTSTRAP_URL)
        resp.raise_for_status()
        servers = _servers_from(resp.json())
    except Exception as exc:
        if boot.servers is None:
            raise
        boot.fetched_at = _clock() - BOOTSTRAP_MAX_AGE_S + BOOTSTRAP_RETRY_S
        logger.warning("rdap_bootstrap_refresh_failed", extra={"error": type(exc).__name__})
        return boot.servers
    boot.servers, boot.fetched_at = servers, _clock()
    logger.info("rdap_bootstrap_loaded", extra={"count": len(servers)})
    return servers


def _retrieve(task: asyncio.Task) -> None:
    # A first fetch can fail after every caller waiting for it hit its own
    # time limit: nobody would read the exception, and asyncio would log it.
    if not task.cancelled():
        task.exception()


def _servers_from(data: Any) -> dict[str, str]:
    """{"services": [[[zones…], [urls…]], …]} → zone → its first https URL.
    A zone that lists only http:// servers is left out: the name would travel
    in the clear, and the answer could be rewritten on the way."""
    servers: dict[str, str] = {}
    entries = data.get("services") if isinstance(data, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not (isinstance(entry, list) and len(entry) == 2
                and isinstance(entry[0], list) and isinstance(entry[1], list)):
            continue
        base = next((u for u in entry[1] if isinstance(u, str) and u.startswith("https://")), None)
        if base is None:
            continue
        base = base if base.endswith("/") else base + "/"
        for zone in entry[0]:
            if isinstance(zone, str) and zone:
                servers[zone.lower().rstrip(".")] = base
    if not servers:
        # A captive portal or a broken mirror answering 200 must not switch
        # age off for a day.
        raise ValueError("RDAP bootstrap file lists no https server")
    return servers


# ── The registry's answer (RFC 9083) ──

def _parse(data: Any, now: datetime) -> dict:
    out: dict = {}
    if not isinstance(data, dict):
        return out
    events = data.get("events")
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            registered = _parse_date(event.get("eventDate"))
            if registered is not None:
                # A date ahead of our clock is a name registered moments ago.
                out["age_days"] = max(0, (now - registered).days)
                out["registered"] = event["eventDate"]
            break
    registrar = _registrar_name(data.get("entities"))
    if registrar:
        out["registrar"] = registrar
    return out


def _parse_date(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar_name(entities: Any) -> Optional[str]:
    """The registrar entity's vCard full name (jCard, RFC 7095:
    ["vcard", [[name, params, type, value], …]])."""
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        fields = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
        for field in fields:
            if isinstance(field, list) and len(field) > 3 and field[0] == "fn" and isinstance(field[3], str):
                return field[3]
    return None
