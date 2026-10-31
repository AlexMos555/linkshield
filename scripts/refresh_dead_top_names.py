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

--pending FILE --pending-base FILE: the tombstone file of an open sweep PR
and of the commit it was built on. The names that PR adds (FILE minus BASE)
are kept — the next run's PR replaces it, and would drop them in the very
weeks the names change hands — but nothing else of its file: a line a
person removed on main stays removed.

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
# The parent delegates the name, but no server it names serves the zone:
# nobody controls its DNS, and on a DNS host that lets any account claim a
# zone delegated to it ("Sitting Ducks") anyone can. Dead, for the lists.
LAME = "lame"
REFERRAL = "referral"
DEAD_STATES = (NXDOMAIN, LAME)
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


def make_parent_check(timeout: float = 4.0,
                      zone_servers: Optional[Callable[[str], Awaitable[tuple[str, list[str]]]]] = None) -> AtParent:
    """Ask the parent zone's own servers, without recursion, whether they
    delegate `name`, and when they do, whether a server they name serves it.
    The zone is found by walking up from the name's parent to the first name
    with NS records (1.1.1.1); its servers' addresses are cached per zone.
    `zone_servers` replaces that walk (tests)."""
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

    async def _addresses(host: str, resp: dns.message.Message) -> list[str]:
        glue = [r.address for rr in resp.additional if rr.rdtype == dns.rdatatype.A
                and str(rr.name).rstrip(".") == host for r in rr]
        if glue:
            return glue[:1]
        try:
            return [a.address for a in await rec.resolve(host, "A")][:1]
        except dns.exception.DNSException:
            return []

    async def _served(qname: dns.name.Name, resp: dns.message.Message) -> str:
        """Does a server of the referral answer for the zone (SOA of the
        name, or www under it) with authority? 5d6d.com, bshare.cn and
        chinagwy.org are delegated to DNSPod, which answers NXDOMAIN for
        them and their www alike; dns-parking and dnsv2 do the same or
        refuse (2026-10-31). Only FC2 serves anige-sokuhouvip.com's www."""
        replies: list[Optional[dns.message.Message]] = []
        www = dns.name.from_text("www", origin=qname)
        for host in referral_hosts(resp, qname)[:4]:
            for addr in await _addresses(host, resp):
                for q, rtype in ((qname, dns.rdatatype.SOA), (www, dns.rdatatype.A)):
                    query = dns.message.make_query(q, rtype)
                    query.flags &= ~dns.flags.RD
                    try:
                        reply, _ = await dns.asyncquery.udp_with_fallback(query, addr, timeout=timeout)
                    except (dns.exception.DNSException, OSError):
                        reply = None
                    replies.append(reply)
                    if served_verdict(replies) == ALIVE:
                        return ALIVE
        return served_verdict(replies)

    async def at_parent(name: str) -> str:
        _, addrs = await (zone_servers or _zone_servers)(name)
        qname = dns.name.from_text(name)
        # Registries rate-limit (GMO's .shop, DENIC, .xyz, .top dropped 48 of
        # 1,107 answers at 20 in flight, 2026-10-31): every server, three
        # rounds, a pause between them. Over TCP: over UDP a.registry.qa
        # answers an empty truncated NOERROR and gov.az a TTL-0 "cookie"
        # referral for any name, both of which only a resolver's retry
        # unwraps; over TCP both answer NXDOMAIN.
        for round_ in range(ATTEMPTS):
            if round_:
                await asyncio.sleep(1.0 * round_)
            for addr in addrs:
                query = dns.message.make_query(qname, dns.rdatatype.NS)
                query.flags &= ~dns.flags.RD
                try:
                    resp = await dns.asyncquery.tcp(query, addr, timeout=timeout)
                except (dns.exception.DNSException, OSError):
                    continue
                verdict = parent_verdict(resp, qname)
                if verdict == REFERRAL:
                    return await _served(qname, resp)
                if verdict != UNKNOWN:
                    return verdict
        return UNKNOWN

    return at_parent


def parent_verdict(resp: dns.message.Message, qname: dns.name.Name) -> str:
    """What a parent zone's reply says about `qname`: NXDOMAIN; REFERRAL (it
    names the name's servers, which are asked next); ALIVE (an answer, or
    NODATA under the zone's SOA: the zone holds the name itself); or UNKNOWN
    for anything else — truncated, refused, or a NOERROR that names neither,
    which is a server's evasion, not the zone's word."""
    if resp.flags & dns.flags.TC:
        return UNKNOWN
    if resp.rcode() == dns.rcode.NXDOMAIN:
        return NXDOMAIN
    if resp.rcode() != dns.rcode.NOERROR:
        return UNKNOWN
    if referral_hosts(resp, qname):
        return REFERRAL
    if resp.answer:
        return ALIVE
    if any(rrset.rdtype == dns.rdatatype.SOA for rrset in resp.authority):
        return ALIVE
    return UNKNOWN


def referral_hosts(resp: dns.message.Message, qname: dns.name.Name) -> list[str]:
    """The servers a referral for `qname` names, sorted."""
    return sorted({str(r.target).rstrip(".") for rr in resp.authority
                   if rr.rdtype == dns.rdatatype.NS and rr.name == qname for r in rr})


def served_verdict(replies: list[Optional[dns.message.Message]]) -> str:
    """The delegated servers' replies (None: no reply) → ALIVE when one
    answers with authority (NOERROR, AA), LAME when every reply came and
    none did (NXDOMAIN, REFUSED, or NOERROR without AA), else UNKNOWN."""
    if any(r is not None and r.rcode() == dns.rcode.NOERROR and r.flags & dns.flags.AA for r in replies):
        return ALIVE
    if replies and all(r is not None for r in replies):
        return LAME
    return UNKNOWN


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

    at_parent_states = dict(await asyncio.gather(*(parent(n) for n in sorted(dead))))
    # Alive: answers at the resolver, or the parent delegates it and one of
    # its servers serves it although the apex is denied (FC2) — a tombstone
    # of that kind is "revived" too.
    alive = {n for n, s in first.items() if s == ALIVE} | {n for n, s in at_parent_states.items() if s == ALIVE}
    return {n for n, s in at_parent_states.items() if s in DEAD_STATES}, alive


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


def report(added: list[str], revived: list[str], total: int, swept: int, carried: Iterable[str] = ()) -> str:
    carried = set(carried)
    lines = [f"Swept {swept:,} names; {len(added):,} newly dead, {total:,} tombstoned in all.", ""]
    if added:
        lines += ["**Newly dead** (NXDOMAIN at 1.1.1.1 and 8.8.8.8, and the parent zone has no name or "
                  "no server serving it; *carried over* from the replaced sweep PR where marked):", ""]
        lines += [f"- `{n}`" + (" *(carried over)*" if n in carried else "") for n in added[:300]]
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
    on_main = load_dead(args.out)
    previous = dict(on_main)
    if args.pending:
        base = load_dead(args.pending_base) if args.pending_base else {}
        for n, day in load_dead(args.pending).items():
            if n not in base:
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
    # What the PR adds to main: this run's finds and the open PR's carried over.
    new_vs_main = sorted(set(merged) - set(on_main))
    text = report(new_vs_main, revived, len(merged), len(names), carried=sorted(set(new_vs_main) - set(added)))
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text)
    if not args.dry_run and merged != on_main:
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(render(merged))
        os.replace(tmp, args.out)
    return EXIT_REVIVED if revived and not new_vs_main else 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="sweep and report, write nothing")
    p.add_argument("--report", help="also write the Markdown report here (the PR body)")
    p.add_argument("--today", default=datetime.date.today().isoformat())
    p.add_argument("--max-new", type=int, default=MAX_NEW)
    p.add_argument("--out", default=DEAD_PATH)
    p.add_argument("--top", default=TOP_PATH)
    p.add_argument("--reported", default=REPORTED_PATH)
    p.add_argument("--pending", help="the tombstone file of an open sweep PR: the names it adds are kept")
    p.add_argument("--pending-base", help="the tombstone file of the commit that PR was built on")
    return asyncio.run(run(p.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
