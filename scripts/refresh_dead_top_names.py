#!/usr/bin/env python3
"""Tombstone the popular names that stopped existing (data/top_domains_dead.json).

Every name of data/top_100k.json and data/top_domains_reported.json is asked
for its NS records. A name both Cloudflare (1.1.1.1) and Google (8.8.8.8)
answer NXDOMAIN for — the parent zone has no such name — is added with
today's date (api/services/dead_top_names.py says why and where the file is
read). Only RCODE 3 counts: a timeout, SERVFAIL or a lame delegation is the
owner's broken DNS, not a name anyone may buy. Not Quad9: it answers
NXDOMAIN for the names it blocks as malicious.

Sticky: a tombstoned name that resolves again is reported ("revived"), never
removed — the one who brought it back may be anyone. A person checks it
(RDAP: registered since when, by whom) and deletes the line by hand.

Refusal (exit 2, the file untouched): the resolvers fail the canary (a live
name must answer, a made-up one must be NXDOMAIN), or more than MAX_NEW names
would be added in one run — a resolver answering NXDOMAIN wholesale, not a
week of expiries (1,139 on the first run, 2026-10-31).

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
import sys
from typing import Awaitable, Callable, Iterable, Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA = os.path.join(ROOT, "data")
DEAD_PATH = os.path.join(DATA, "top_domains_dead.json")
TOP_PATH = os.path.join(DATA, "top_100k.json")
REPORTED_PATH = os.path.join(DATA, "top_domains_reported.json")

RESOLVERS = ("1.1.1.1", "8.8.8.8")
CONCURRENCY = 150
ATTEMPTS = 3
MAX_NEW = 2_500
LIVE_CANARIES = ("google.com", "wikipedia.org", "cloudflare.com")
DEAD_CANARY = "cleanway-dead-canary-7f3a91c2e5.com"

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


async def _states(names: Iterable[str], server: str, resolve: Resolve) -> dict[str, str]:
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(name: str) -> tuple[str, str]:
        async with sem:
            return name, await resolve(name, server)

    return dict(await asyncio.gather(*(one(n) for n in names)))


async def canary_ok(resolve: Resolve) -> Optional[str]:
    """None when every resolver answers like the real DNS, else why not."""
    for server in RESOLVERS:
        for name in LIVE_CANARIES:
            if await resolve(name, server) != ALIVE:
                return f"{server} does not resolve {name}"
        if await resolve(DEAD_CANARY, server) != NXDOMAIN:
            return f"{server} does not answer NXDOMAIN for {DEAD_CANARY}"
    return None


async def sweep(names: list[str], resolve: Resolve) -> tuple[set[str], set[str]]:
    """(dead: NXDOMAIN at every resolver, alive: NOERROR at the first)."""
    first = await _states(names, RESOLVERS[0], resolve)
    dead = {n for n, s in first.items() if s == NXDOMAIN}
    for server in RESOLVERS[1:]:
        dead &= {n for n, s in (await _states(sorted(dead), server, resolve)).items() if s == NXDOMAIN}
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


async def run(args: argparse.Namespace, resolve: Optional[Resolve] = None) -> int:
    resolve = resolve or make_resolver()
    why = await canary_ok(resolve)
    if why:
        print(f"refused: {why}", file=sys.stderr)
        return 2
    names = load_names(args.top, args.reported)
    previous = load_dead(args.out)
    dead, alive = await sweep(names, resolve)
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
    if not args.dry_run and added:
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(render(merged))
        os.replace(tmp, args.out)
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="sweep and report, write nothing")
    p.add_argument("--report", help="also write the Markdown report here (the PR body)")
    p.add_argument("--today", default=datetime.date.today().isoformat())
    p.add_argument("--max-new", type=int, default=MAX_NEW)
    p.add_argument("--out", default=DEAD_PATH)
    p.add_argument("--top", default=TOP_PATH)
    p.add_argument("--reported", default=REPORTED_PATH)
    return asyncio.run(run(p.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
