#!/usr/bin/env python3
"""Find brand-owned defensive domains the live phone blocklist blocks.

Brands register their name under many ccTLDs (roblox.de, roblox.fr …) and
redirect them home. When a feed lists one, every phone blocks the brand's own
domain — a false positive. This sweep looks for that class:

  1. candidates: <brand>.<cc>, www.<brand>.<cc>, <brand>.com.<cc>,
     www.<brand>.com.<cc>, <brand>.co.<cc> for every brand in
     data/typosquat_targets.json and a broad ccTLD list;
  2. keep those the live artifact covers (the phone's own rule,
     api.services.blocklist_artifact.artifact_covers) through a listed name
     that carries the brand label — a candidate covered only by a generic
     parent (co.pt) cannot be fixed by vetoing it and is not the brand's;
  3. for each, follow HTTP redirects from http://<host>/ and read the zone's
     nameservers.

A host is BRAND-OWNED only when the redirect lands on the brand's apex (or a
subdomain of it) AND the zone's DNS is the brand's: it shares a nameserver
with the brand's apex, or it sits on a corporate brand-protection registrar.
A redirect alone proves nothing — a phishing kit bounces `/` to the real site
so a reviewer sees the brand (2026-09-19: roblox.com.hr / roblox.ly did
exactly that while serving /users/<id>/profile themselves). Such hosts are
reported as CLOAKING-SUSPECT and must never be vetoed.

A host on the brand's DNS that serves its own page instead of redirecting
(americanexpress.io, Amex's tech blog) is BRAND-DNS-REVIEW: likely the
brand's, confirmed only after a human reads the WHOIS registrant.

BRAND-OWNED hosts (and reviewed BRAND-DNS-REVIEW ones) are the candidates for
the publisher's veto list, data/brand_owned_hosts.txt; a human still reads
the evidence before adding one.

Usage:
    python3 scripts/sweep_brand_owned_fps.py                    # live artifact
    python3 scripts/sweep_brand_owned_fps.py --artifact list.bin --delay 2

Read-only: one GET of the public artifact, then one HTTP GET chain and one NS
lookup per covered brand-listed candidate, sequentially with a delay. No
secrets, no writes.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable, NamedTuple, Optional

import dns.exception
import dns.resolver
import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.services.blocklist_artifact import LIST_CANARY, name_hash, parse_artifact_v2  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("brand-owned-sweep")

ARTIFACT_URL = "https://api.cleanway.ai/api/v1/blocklist/dns"
TARGETS_PATH = ROOT / "data" / "typosquat_targets.json"
USER_AGENT = "Cleanway-fp-sweep/1.0 (+https://cleanway.ai)"
HTTP_TIMEOUT = 8.0
DNS_LIFETIME = 5.0

CCTLDS = (
    "hr", "ly", "bn", "et", "am", "bi", "mu", "ru", "ua", "by", "kz", "de", "fr", "it", "es", "pt",
    "nl", "pl", "cz", "tr", "br", "mx", "ar", "co", "cl", "pe", "in", "id", "my", "th", "vn", "ph",
    "sg", "jp", "kr", "cn", "tw", "hk", "au", "nz", "za", "ng", "ke", "eg", "ae", "sa", "il", "gr",
    "ro", "bg", "hu", "se", "no", "fi", "dk", "ie", "be", "at", "ch", "uk", "ca", "us", "io", "me",
    "tv", "cc", "gg", "gl", "gs", "st", "la", "ws", "to", "ms", "lt", "lv", "ee", "sk", "si", "rs",
)
SHAPES = ("{b}.{cc}", "www.{b}.{cc}", "{b}.com.{cc}", "www.{b}.com.{cc}", "{b}.co.{cc}")

# Registrars that only serve corporate brand portfolios: a zone on their DNS
# is not something a phisher can buy into.
BRAND_PROTECTION_NS = ("markmonitor.com", "cscdns.net", "cscdns.uk", "comlaude-dns.com",
                       "comlaude-dns.net", "comlaude-dns.eu")
_THREE_LABEL_APEX_SUFFIXES = frozenset({"co.uk", "com.au", "co.jp", "com.br"})

BRAND_OWNED = "brand-owned"
CLOAKING_SUSPECT = "cloaking-suspect"
BRAND_DNS_REVIEW = "brand-dns-review"
NOT_BRAND = "not-brand"
UNREACHABLE = "unreachable"
GENERIC_PARENT = "generic-parent"


class Candidate(NamedTuple):
    host: str
    label: str
    apex: str


def apex_of(domain: str) -> str:
    """Registrable of a legit brand domain (store.steampowered.com → steampowered.com)."""
    parts = domain.lower().rstrip(".").split(".")
    keep = 3 if ".".join(parts[-2:]) in _THREE_LABEL_APEX_SUFFIXES else 2
    return ".".join(parts[-keep:])


def brand_apexes(targets: dict) -> dict[str, str]:
    """Brand label → legit apex, from the keys and from each apex's own label."""
    out: dict[str, str] = {}
    for key, domain in targets.items():
        apex = apex_of(domain)
        out.setdefault(key.lower(), apex)
        out.setdefault(apex.split(".")[0], apex)
    return out


def candidates(targets: dict, cctlds: Iterable[str] = CCTLDS) -> list[Candidate]:
    seen: dict[str, Candidate] = {}
    for label, apex in sorted(brand_apexes(targets).items()):
        for cc in cctlds:
            for shape in SHAPES:
                host = shape.format(b=label, cc=cc)
                seen.setdefault(host, Candidate(host=host, label=label, apex=apex))
    return list(seen.values())


def covering_name(hashes: set[int], host: str) -> Optional[str]:
    """The most specific listed name that blocks `host` on a phone, or None."""
    parts = host.split(".")
    for i in range(len(parts) - 1):
        name = ".".join(parts[i:])
        if name_hash(name) in hashes:
            return name
    return None


def is_brand_listing(listed: str, label: str) -> bool:
    return label in listed.split(".")


def lands_on_brand(final_host: Optional[str], apex: str) -> bool:
    return bool(final_host) and (final_host == apex or final_host.endswith("." + apex))


def brand_dns(nameservers: frozenset[str], apex_ns: frozenset[str]) -> bool:
    if nameservers & apex_ns:
        return True
    return any(ns == p or ns.endswith("." + p) for ns in nameservers for p in BRAND_PROTECTION_NS)


def verdict(final_host: Optional[str], error: Optional[str], nameservers: frozenset[str],
            apex: str, apex_ns: frozenset[str]) -> str:
    if final_host is None:
        return UNREACHABLE if error else NOT_BRAND
    on_brand_dns = brand_dns(nameservers, apex_ns)
    if not lands_on_brand(final_host, apex):
        return BRAND_DNS_REVIEW if on_brand_dns else NOT_BRAND
    return BRAND_OWNED if on_brand_dns else CLOAKING_SUSPECT


def zone_of(host: str) -> str:
    """Candidates are shaped so the zone is the host minus a leading www."""
    return host[4:] if host.startswith("www.") else host


def nameservers(zone: str) -> frozenset[str]:
    try:
        answer = dns.resolver.resolve(zone, "NS", lifetime=DNS_LIFETIME)
    except (dns.exception.DNSException, OSError) as e:
        log.info("NS %s: %s", zone, type(e).__name__)
        return frozenset()
    return frozenset(str(r.target).lower().rstrip(".") for r in answer)


def final_host(client: httpx.Client, host: str) -> tuple[Optional[str], Optional[str]]:
    """(host the redirect chain from http://host/ ends on, error name)."""
    try:
        resp = client.get(f"http://{host}/")
    except httpx.HTTPError as e:
        return None, type(e).__name__
    return resp.url.host.lower(), None


def load_hashes(source: str) -> set[int]:
    if source.startswith("http"):
        req = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=90) as r:
            blob = r.read()
    else:
        blob = Path(source).read_bytes()
    header, hashes = parse_artifact_v2(blob)
    log.info("artifact: generated=%s count=%s", header["generated"], header["count"])
    return set(hashes) - {name_hash(LIST_CANARY)}


def probe_all(covered: list[tuple[Candidate, str]], delay: float) -> list[dict]:
    rows: list[dict] = []
    apex_ns: dict[str, frozenset[str]] = {}
    with httpx.Client(follow_redirects=True, timeout=HTTP_TIMEOUT, max_redirects=10,
                      headers={"User-Agent": USER_AGENT}) as client:
        for cand, listed in covered:
            if not is_brand_listing(listed, cand.label):
                rows.append({"host": cand.host, "listed": listed, "verdict": GENERIC_PARENT})
                continue
            if cand.apex not in apex_ns:
                apex_ns[cand.apex] = nameservers(cand.apex)
            landed, error = final_host(client, cand.host)
            ns = nameservers(zone_of(cand.host))
            rows.append({"host": cand.host, "listed": listed, "apex": cand.apex, "final": landed,
                         "error": error, "ns": sorted(ns),
                         "verdict": verdict(landed, error, ns, cand.apex, apex_ns[cand.apex])})
            time.sleep(delay)
    return rows


def report(rows: list[dict], checked: int) -> None:
    for row in rows:
        if row["verdict"] != GENERIC_PARENT:
            print(f"{row['verdict']:<17} {row['host']:<32} listed={row['listed']:<26} "
                  f"final={row.get('final') or '-':<24} error={row.get('error') or '-'} ns={','.join(row['ns']) or '-'}")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print(f"\nchecked {checked} candidates, {len(rows)} covered by the live artifact: {counts}")
    for title, wanted in (("brand-owned (read the evidence above before adding to the veto list)", BRAND_OWNED),
                          ("brand DNS, no redirect (confirm the WHOIS registrant first)", BRAND_DNS_REVIEW)):
        print(f"\n# {title}:")
        for row in rows:
            if row["verdict"] == wanted:
                print(row["host"])


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--artifact", default=ARTIFACT_URL, help="artifact URL or local v2 file")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between probed hosts")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        targets = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))["brands"]
        hashes = load_hashes(args.artifact)
    except (OSError, ValueError, KeyError) as e:
        log.error("cannot start the sweep: %s", e)
        return 2
    cands = candidates(targets)
    covered = [(c, listed) for c in cands if (listed := covering_name(hashes, c.host))]
    log.info("%d candidates, %d covered — probing brand-listed ones", len(cands), len(covered))
    report(probe_all(covered, args.delay), len(cands))
    return 0


if __name__ == "__main__":
    sys.exit(main())
