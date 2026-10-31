#!/usr/bin/env python3
"""Tombstone the popular names that stopped existing (data/top_domains_dead.json).

Every name of data/top_100k.json and data/top_domains_reported.json is asked
for its NS records. A name both Cloudflare (1.1.1.1) and Google (8.8.8.8)
answer NXDOMAIN for, and whose parent zone's own servers, asked without
recursion, have no delegation for, is added with today's date
(api/services/dead_top_names.py says why and where the file is read). Only
RCODE 3 counts: a timeout or SERVFAIL is the owner's broken DNS, not a name
anyone may buy. Not Quad9: it answers NXDOMAIN for the names it blocks as
malicious. The parent's word is needed because a delegated name's own
servers may answer NXDOMAIN for its apex and still serve www (FC2, DNSPod,
dns-parking: www.anige-sokuhouvip.com, rank 15,580, a live blog registered
until 2029, was tombstoned by the first cut on 2026-10-31).

Sticky: a tombstoned name that resolves again is reported ("revived"), never
removed — the one who brought it back may be anyone. A person checks it
(RDAP: registered since when, by whom) and deletes the line by hand.

Refusal (exit 2, the file untouched): the resolvers fail the canary (a live
name must answer, a made-up one — a fresh random label each run, so nobody
can register it to stop the sweep — must be NXDOMAIN), or more than MAX_NEW
names would be added in one run — a resolver answering NXDOMAIN wholesale,
not a week of expiries (1,155 on the first run, 2026-10-31).

--pending FILE: the tombstone file of a sweep PR not merged yet. Its names
are kept (the workflow passes it), or the next run's PR would replace that
one and drop them in the very weeks the names change hands.

Usage:
    python3 scripts/refresh_dead_top_names.py               # sweep, write
    python3 scripts/refresh_dead_top_names.py --dry-run     # sweep, report only
    python3 scripts/refresh_dead_top_names.py --report FILE # also write a Markdown report
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import secrets
import sys
from typing import Awaitable, Callable, Iterable, Optional

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA = os.path.join(ROOT, "data")
DEAD_PATH = os.path.join(DATA, "top_domains_dead.json")
TOP_PATH = os.path.join(DATA, "top_100k.json")
REPORTED_PATH = os.path.join(DATA, "top_domains_reported.json")

RESOLVERS = ("1.1.1.1", "8.8.8.8")
CONCURRENCY = 150
PARENT_CONCURRENCY = 8  # to the registries' own servers, which rate-limit
ATTEMPTS = 3
MAX_NEW = 2_500
LIVE_CANARIES = ("google.com", "wikipedia.org", "cloudflare.com")
# Exit code: swept, nothing new, but tombstoned names resolve again — the
# workflow opens an issue for a person to check them.
EXIT_REVIVED = 3

ABOUT = (
    "Names of data/top_100k.json and data/top_domains_reported.json that stopped existing: both "
    "Cloudflare and Google answered NXDOMAIN (scripts/refresh_dead_top_names.py, weekly). Value: the "
    "date it was first seen dead. Read by api/services/dead_top_names.py: such a name gets none of the "
    "lists' trust (allowlist, popularity rank, OTX waiver, ML safe override, the blocklist's never-block "
    "guard, the phone's veto), because anyone may have registered it since. Sticky: a name that resolves "
    "again is reported by the sweep and removed only by a person who checked who holds it now."
)

NXDOMAIN, ALIVE, UNKNOWN = "nxdomain", "alive", "unknown"
Resolve = Callable[[str, str], Awaitable[str]]
# `at_parent(name)` → NXDOMAIN when the parent zone's servers have no such
# name, ALIVE when they delegate it, UNKNOWN when they could not be asked.
AtParent = Callable[[str], Awaitable[str]]


def dead_canary() -> str:
    return f"cleanway-canary-{secrets.token_hex(12)}.com"


def make_resolver(timeout: float = 4.0) -> Resolve:
    """`resolve(name, server)` → NXDOMAIN, ALIVE or UNKNOWN (no answer we trust)."""
    resolvers: dict[str, dns.asyncresolver.Resolver] = {}

    def _for(server: str) -> dns.asyncresolver.Resolver:
        if server not in resolvers:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [server]
            r.timeout, r.lifetime = timeout, timeout * 2
            resolvers[server] = r
        return resolvers[server]

    async def resolve(name: str, server: str) -> str:
        for _ in range(ATTEMPTS):
            try:
                await _for(server).resolve(name, "NS", raise_on_no_answer=False)
                return ALIVE  # NOERROR, with or without NS records (a name below a zone cut)
            except dns.resolver.NXDOMAIN:
                return NXDOMAIN
            except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException:
                return UNKNOWN
        return UNKNOWN

    return resolve


def make_parent_check(timeout: float = 4.0) -> AtParent:
    """Ask the parent zone's own servers, without recursion, whether they
    delegate `name`. The zone is found by walking up from the name's parent
    to the first name with NS records (1.1.1.1); its servers' addresses are
    cached per zone."""
    rec = dns.asyncresolver.Resolver(configure=False)
    rec.nameservers = [RESOLVERS[0]]
    rec.timeout, rec.lifetime = timeout, timeout * 2
    servers: dict[str, asyncio.Future] = {}  # one lookup per zone, however many ask

    async def _lookup(zone: str) -> list[str]:
        try:
            ns = await rec.resolve(zone, "NS")
        except dns.exception.DNSException:
            return []  # not a zone cut (or not answering): the caller goes up
        addrs: list[str] = []
        for host in sorted(str(r.target).rstrip(".") for r in ns)[:3]:
            try:
                addrs += [a.address for a in await rec.resolve(host, "A")][:1]
            except dns.exception.DNSException:
                continue
        return addrs

    async def _zone_servers(name: str) -> tuple[str, list[str]]:
        labels = name.split(".")[1:]
        while labels:
            zone = ".".join(labels)
            if zone not in servers:
                servers[zone] = asyncio.ensure_future(_lookup(zone))
            addrs = await servers[zone]
            if addrs:
                return zone, addrs
            labels = labels[1:]
        return "", []

    async def at_parent(name: str) -> str:
        _, addrs = await _zone_servers(name)
        qname = dns.name.from_text(name)
        # Registries rate-limit (GMO's .shop, DENIC, .xyz, .top dropped 48 of
        # 1,107 answers at 20 in flight, 2026-10-31): every server, three
        # rounds, a pause between them.
        for round_ in range(ATTEMPTS):
            if round_:
                await asyncio.sleep(1.0 * round_)
            for addr in addrs:
                query = dns.message.make_query(qname, dns.rdatatype.NS)
                query.flags &= ~dns.flags.RD
                try:
                    resp = await dns.asyncquery.udp(query, addr, timeout=timeout)
                except (dns.exception.DNSException, OSError):
                    continue
                if resp.rcode() == dns.rcode.NXDOMAIN:
                    return NXDOMAIN
                if resp.rcode() == dns.rcode.NOERROR:
                    # A referral, an answer or NODATA: the zone has the name.
                    return ALIVE
        return UNKNOWN

    return at_parent


async def _states(names: Iterable[str], server: str, resolve: Resolve,
                  concurrency: int = CONCURRENCY) -> dict[str, str]:
    sem = asyncio.Semaphore(concurrency)

    async def one(name: str) -> tuple[str, str]:
        async with sem:
            return name, await resolve(name, server)

    return dict(await asyncio.gather(*(one(n) for n in names)))


async def canary_ok(resolve: Resolve, at_parent: AtParent, canary: str) -> Optional[str]:
    """None when every resolver and the parent check answer like the real
    DNS, else why not."""
    for server in RESOLVERS:
        for name in LIVE_CANARIES:
            if await resolve(name, server) != ALIVE:
                return f"{server} does not resolve {name}"
        if await resolve(canary, server) != NXDOMAIN:
            return f"{server} does not answer NXDOMAIN for {canary}"
    if await at_parent(canary) != NXDOMAIN or await at_parent(LIVE_CANARIES[0]) != ALIVE:
        return "the parent-zone check does not tell a made-up name from a delegated one"
    return None


async def sweep(names: list[str], resolve: Resolve, at_parent: AtParent) -> tuple[set[str], set[str]]:
    """(dead: NXDOMAIN at every resolver and at the parent zone's servers,
    alive: NOERROR at the first resolver)."""
    first = await _states(names, RESOLVERS[0], resolve)
    # A resolver drops answers at 150 in flight: the unanswered are asked
    # again, slowly (5 dead names were missed that way, 2026-10-31).
    unanswered = sorted(n for n, s in first.items() if s == UNKNOWN)
    first.update(await _states(unanswered, RESOLVERS[0], resolve, concurrency=PARENT_CONCURRENCY))
    dead = {n for n, s in first.items() if s == NXDOMAIN}
    for server in RESOLVERS[1:]:
        dead &= {n for n, s in (await _states(sorted(dead), server, resolve)).items() if s == NXDOMAIN}
    sem = asyncio.Semaphore(PARENT_CONCURRENCY)

    async def parent(name: str) -> tuple[str, str]:
        async with sem:
            return name, await at_parent(name)

    dead = {n for n, s in await asyncio.gather(*(parent(n) for n in sorted(dead))) if s == NXDOMAIN}
    return dead, {n for n, s in first.items() if s == ALIVE}


def load_names(top_path: str = TOP_PATH, reported_path: str = REPORTED_PATH) -> list[str]:
    with open(top_path, encoding="utf-8") as f:
        top = json.load(f)
    with open(reported_path, encoding="utf-8") as f:
        reported = json.load(f)
    return sorted({n.lower() for n in top} | {n.lower() for n in reported})


def load_dead(path: str = DEAD_PATH) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return dict(json.load(f)["names"])
    except FileNotFoundError:
        return {}


def render(dead: dict[str, str]) -> str:
    return json.dumps({"_about": ABOUT, "names": dict(sorted(dead.items()))}, ensure_ascii=False, indent=1) + "\n"


def report(added: list[str], revived: list[str], total: int, swept: int) -> str:
    lines = [f"Swept {swept:,} names; {len(added):,} newly dead, {total:,} tombstoned in all.", ""]
    if added:
        lines += ["**Newly dead** (NXDOMAIN at 1.1.1.1 and 8.8.8.8):", ""]
        lines += [f"- `{n}`" for n in added[:300]]
        if len(added) > 300:
            lines.append(f"- … and {len(added) - 300:,} more (see the diff)")
        lines.append("")
    if revived:
        lines += ["**Revived** (tombstoned, resolving again — NOT removed; check RDAP: registered since when, "
                  "by whom, before deleting a line by hand):", ""]
        lines += [f"- `{n}`" for n in revived]
        lines.append("")
    return "\n".join(lines)


async def run(args: argparse.Namespace, resolve: Optional[Resolve] = None,
              at_parent: Optional[AtParent] = None) -> int:
    resolve = resolve or make_resolver()
    at_parent = at_parent or make_parent_check()
    why = await canary_ok(resolve, at_parent, dead_canary())
    if why:
        print(f"refused: {why}", file=sys.stderr)
        return 2
    names = load_names(args.top, args.reported)
    previous = load_dead(args.out)
    if args.pending:
        for n, day in load_dead(args.pending).items():
            previous.setdefault(n, day)
    dead, alive = await sweep(names, resolve, at_parent)
    added = sorted(dead - set(previous))
    if len(added) > args.max_new:
        print(f"refused: {len(added):,} names would be added (more than {args.max_new:,})", file=sys.stderr)
        return 2
    merged = dict(previous)
    for n in added:
        merged[n] = args.today
    revived = sorted(set(previous) & alive)
    text = report(added, revived, len(merged), len(names))
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text)
    if not args.dry_run and merged != load_dead(args.out):
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(render(merged))
        os.replace(tmp, args.out)
    return EXIT_REVIVED if revived and not added else 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="sweep and report, write nothing")
    p.add_argument("--report", help="also write the Markdown report here (the PR body)")
    p.add_argument("--today", default=datetime.date.today().isoformat())
    p.add_argument("--max-new", type=int, default=MAX_NEW)
    p.add_argument("--out", default=DEAD_PATH)
    p.add_argument("--top", default=TOP_PATH)
    p.add_argument("--reported", default=REPORTED_PATH)
    p.add_argument("--pending", help="the tombstone file of an unmerged sweep PR, kept")
    return asyncio.run(run(p.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
