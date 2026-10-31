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

--ranking FILE: sweep the rest of the top-1M ranking instead ([[domain, rank],
...] as scripts/refresh_tranco.py --dump writes it; ranks 100k-1M, 2.46% dead
in a 20,000-name sample on 2026-10-31) into data/top_1m_dead.json — a file
of its own, with a cap of its own (MAX_NEW_BAND), so the band can neither
cost nor drown the top lists' tombstones. Its revived names are counted,
not listed, and raise no issue: a band name only loses a small bonus, the
vouch and the publisher's guard. Already tombstoned band names skip the
parent check (sticky; only the resolver's "alive" matters for them).

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
BAND_PATH = os.path.join(DATA, "top_1m_dead.json")
TOP_PATH = os.path.join(DATA, "top_100k.json")
REPORTED_PATH = os.path.join(DATA, "top_domains_reported.json")

RESOLVERS = ("1.1.1.1", "8.8.8.8")
CONCURRENCY = 150
PARENT_CONCURRENCY = 8  # to the registries' own servers, which rate-limit
MAX_DELEGATED = 4       # of a referral's servers, asked about the zone
ATTEMPTS = 3
MAX_NEW = 2_500
MAX_NEW_BAND = 10_000  # a week's expiries in ranks 100k-1M; the bootstrap passes --max-new
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

ABOUT_BAND = (
    "Names of the top-1M popularity ranking outside data/top_100k.json and data/top_domains_reported.json "
    "(ranks 100k-1M, scripts/refresh_tranco.py) that stopped existing, swept and read like "
    "data/top_domains_dead.json (scripts/refresh_dead_top_names.py --ranking): such a name has no rank, "
    "so no popularity bonus, vouch, OTX waiver or blocklist never-block guard. Sticky as well."
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
        replies: list[tuple[dns.name.Name, Optional[dns.message.Message]]] = []
        www = dns.name.from_text("www", origin=qname)
        hosts = referral_hosts(resp, qname)
        if len(hosts) > MAX_DELEGATED:
            replies.append((qname, None))  # a server not asked: never LAME
        for host in hosts[:MAX_DELEGATED]:
            addrs = await _addresses(host, resp)
            if not addrs:
                replies.append((qname, None))  # no IPv4 address to ask it at
            for addr in addrs:
                for q, rtype in ((qname, dns.rdatatype.SOA), (www, dns.rdatatype.A)):
                    query = dns.message.make_query(q, rtype)
                    query.flags &= ~dns.flags.RD
                    try:
                        reply, _ = await dns.asyncquery.udp_with_fallback(query, addr, timeout=timeout)
                    except (dns.exception.DNSException, OSError):
                        reply = None
                    replies.append((q, reply))
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


def served_verdict(replies: list[tuple[dns.name.Name, Optional[dns.message.Message]]]) -> str:
    """The delegated servers' replies, each with the name it was asked
    (None: no reply, or a server not asked) → ALIVE when one serves the
    zone: NOERROR with authority, or NOERROR carrying a record of the asked
    name (Sberbank's servers answer sberbank.com's SOA and www without AA);
    LAME when every server replied and none did (NXDOMAIN, REFUSED, an empty
    or sideways NOERROR without authority); else UNKNOWN."""
    for qname, r in replies:
        if r is None or r.rcode() != dns.rcode.NOERROR:
            continue
        if r.flags & dns.flags.AA or any(rr.name == qname for rr in r.answer):
            return ALIVE
    if replies and all(r is not None for _, r in replies):
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


async def sweep(names: list[str], resolve: Resolve, at_parent: AtParent,
                known_dead: Iterable[str] = ()) -> tuple[set[str], set[str]]:
    """(dead: NXDOMAIN at every resolver and at the parent zone's servers,
    alive: NOERROR at the first resolver). `known_dead` skip the parent
    check: tombstoned already, they stay dead while the resolvers agree."""
    known_dead = set(known_dead)
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

    at_parent_states = {n: NXDOMAIN for n in dead & known_dead}
    at_parent_states.update(await asyncio.gather(*(parent(n) for n in sorted(dead - known_dead))))
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


def load_band(ranking_path: str, top_names: Iterable[str], tombstoned: Iterable[str]) -> list[str]:
    """The ranking's names that are neither on the top lists nor tombstoned
    there already."""
    with open(ranking_path, encoding="utf-8") as f:
        ranking = json.load(f)
    return sorted({str(d).lower() for d, _ in ranking} - set(top_names) - set(tombstoned))


def load_dead(path: str = DEAD_PATH) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return dict(json.load(f)["names"])
    except FileNotFoundError:
        return {}


def render(dead: dict[str, str], about: str = ABOUT) -> str:
    return json.dumps({"_about": about, "names": dict(sorted(dead.items()))}, ensure_ascii=False, indent=1) + "\n"


def report(added: list[str], revived: list[str], total: int, swept: int, carried: Iterable[str] = (),
           band: bool = False) -> str:
    carried = set(carried)
    what = "names of the ranking off the top lists (ranks 100k-1M)" if band else "names of the top lists"
    lines = [f"Swept {swept:,} {what}; {len(added):,} newly dead, {total:,} tombstoned in all.", ""]
    if added:
        lines += ["**Newly dead** (NXDOMAIN at 1.1.1.1 and 8.8.8.8, and the parent zone has no name or "
                  "no server serving it; *carried over* from the replaced sweep PR where marked):", ""]
        lines += [f"- `{n}`" + (" *(carried over)*" if n in carried else "") for n in added[:300]]
        if len(added) > 300:
            lines.append(f"- … and {len(added) - 300:,} more (see the diff)")
        lines.append("")
    if revived and band:
        lines += [f"{len(revived):,} tombstoned names of ranks 100k-1M resolve again; they stay tombstoned, "
                  "no action needed.", ""]
    elif revived:
        lines += ["**Revived** (tombstoned, resolving again — NOT removed; check RDAP: registered since when, "
                  "by whom, before deleting a line by hand):", ""]
        lines += [f"- `{n}`" for n in revived]
        lines.append("")
    return "\n".join(lines)


def _carried(on_main: dict[str, str], pending: Optional[str], pending_base: Optional[str]) -> dict[str, str]:
    """`on_main` plus what the open sweep PR adds (pending minus its base)."""
    merged = dict(on_main)
    if pending:
        base = load_dead(pending_base) if pending_base else {}
        for n, day in load_dead(pending).items():
            if n not in base:
                merged.setdefault(n, day)
    return merged


async def run(args: argparse.Namespace, resolve: Optional[Resolve] = None,
              at_parent: Optional[AtParent] = None) -> int:
    if args.carry_only:
        # No DNS at all: the band step failed, and the resolvers may be why;
        # the open PR's additions must not be dropped with it.
        out = args.out or DEAD_PATH
        on_main = load_dead(out)
        merged = _carried(on_main, args.pending, args.pending_base)
        if merged != on_main and not args.dry_run:
            about = ABOUT_BAND if os.path.basename(out) == os.path.basename(BAND_PATH) else ABOUT
            with open(out + ".tmp", "w", encoding="utf-8") as f:
                f.write(render(merged, about))
            os.replace(out + ".tmp", out)
        print(f"carried over {len(merged) - len(on_main):,} names into {os.path.basename(out)}")
        return 0
    resolve = resolve or make_resolver()
    at_parent = at_parent or make_parent_check()
    why = await canary_ok(resolve, at_parent, dead_canary())
    if why:
        print(f"refused: {why}", file=sys.stderr)
        return 2
    band = bool(args.ranking)
    out = args.out or (BAND_PATH if band else DEAD_PATH)
    cap = args.max_new if args.max_new is not None else (MAX_NEW_BAND if band else MAX_NEW)
    names = load_names(args.top, args.reported)
    if band:
        names = load_band(args.ranking, names, load_dead(args.top_dead))
    on_main = load_dead(out)
    previous = _carried(on_main, args.pending, args.pending_base)
    # Band tombstones of names now on the top lists (a rebuild put them
    # there): they take the allowlist and the phone's veto too, and the band
    # no longer sweeps them, so a revived one is reported here.
    band_on_top = set() if band else set(load_dead(args.band_dead)) & set(names)
    dead, alive = await sweep(names, resolve, at_parent, known_dead=previous if band else ())
    # The resolvers must still answer like the real DNS after hours of it.
    why = await canary_ok(resolve, at_parent, dead_canary())
    if why:
        print(f"refused after the sweep: {why}", file=sys.stderr)
        return 2
    added = sorted(dead - set(previous))
    if len(added) > cap:
        print(f"refused: {len(added):,} names would be added (more than {cap:,})", file=sys.stderr)
        return 2
    merged = dict(previous)
    for n in added:
        merged[n] = args.today
    revived = sorted((set(previous) | band_on_top) & alive)
    # What the PR adds to main: this run's finds and the open PR's carried over.
    new_vs_main = sorted(set(merged) - set(on_main))
    text = report(new_vs_main, revived, len(merged), len(names), carried=sorted(set(new_vs_main) - set(added)),
                  band=band)
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(text)
    if not args.dry_run and merged != on_main:
        tmp = out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(render(merged, ABOUT_BAND if band else ABOUT))
        os.replace(tmp, out)
    return EXIT_REVIVED if revived and not new_vs_main and not band else 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="sweep and report, write nothing")
    p.add_argument("--report", help="also write the Markdown report here (the PR body)")
    p.add_argument("--today", default=datetime.date.today().isoformat())
    p.add_argument("--max-new", type=int, default=None,
                   help=f"refuse above this many new names (default {MAX_NEW:,}; {MAX_NEW_BAND:,} with --ranking)")
    p.add_argument("--out", default=None, help="default data/top_domains_dead.json, or data/top_1m_dead.json with --ranking")
    p.add_argument("--ranking", help="sweep the rest of this top-1M ranking (refresh_tranco.py --dump) instead")
    p.add_argument("--top-dead", default=DEAD_PATH, help="the top lists' tombstones, left out of a --ranking sweep")
    p.add_argument("--band-dead", default=BAND_PATH,
                   help="the band's tombstones; those of names now on the top lists are reported when revived")
    p.add_argument("--carry-only", action="store_true",
                   help="no sweep: write --out plus what --pending adds over --pending-base")
    p.add_argument("--top", default=TOP_PATH)
    p.add_argument("--reported", default=REPORTED_PATH)
    p.add_argument("--pending", help="the tombstone file of an open sweep PR: the names it adds are kept")
    p.add_argument("--pending-base", help="the tombstone file of the commit that PR was built on")
    return asyncio.run(run(p.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
