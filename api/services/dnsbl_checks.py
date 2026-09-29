"""Spamhaus DBL and SURBL lookups over DNS, with their answer codes read
properly.

Both lists answer a query with an address in 127/8, and both use part of
that space for errors, not listings:

  Spamhaus DBL (public mirror)
    127.0.1.2 spam, .4 phish, .5 malware, .6 botnet C&C, .102-.106 the same
    on an abused legitimate domain — LISTED. 127.0.1.255 "IP queries
    prohibited" and 127.255.255.252 (typing error in the DNSBL name),
    127.255.255.254 (query via a public/open resolver — no answer given) and
    127.255.255.255 (excessive queries) are ERRORS: the list said nothing
    about the domain. Until 2026-09-29 any 127.0.1.x counted as listed and
    anything else as "not listed", so a DBL that refused us (the plan's
    127.255.255.254 case — the API's resolver is a public one) was read as
    "clean" on every check and counted as a measured answer.

  SURBL (multi.surbl.org)
    127.0.0.X with bits 2..128 set — LISTED (PH, MW, ABUSE, CR …).
    127.0.0.1 — "your access is blocked" (surbl.org/guidelines): an ERROR
    that the old `startswith("127.")` read as a LISTING, so a blocked mirror
    would have flagged every domain as spam.

An error raises DnsblUnavailable, so the circuit breaker counts it and opens
after a few, and the analyzer reports the check as not measured — which is
what happened: the list was not consulted. NXDOMAIN is the normal "not
listed".

Both are consulted only when LICENSED_INTEL=all (api/services/licensed_intel).
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging

from api.services.scoring import _extract_base_domain

logger = logging.getLogger("cleanway.analyzer")

DNSBL_TIMEOUT_S = 2.5

SPAMHAUS_DBL_ZONE = "dbl.spamhaus.org"
SURBL_ZONE = "multi.surbl.org"

# 127.0.1.<code>: the DBL's listing codes; 255 is "IP queries prohibited".
SPAMHAUS_LISTED_CODES = frozenset({2, 4, 5, 6, 102, 103, 104, 105, 106})
SPAMHAUS_ERROR_PREFIX = "127.255.255."
SPAMHAUS_IP_QUERY_PROHIBITED = "127.0.1.255"
SURBL_BLOCKED = "127.0.0.1"


class DnsblUnavailable(RuntimeError):
    """The list answered with an error code, not a verdict."""


def _resolver():
    import dns.resolver as dns_resolver

    resolver = dns_resolver.Resolver()
    resolver.timeout = DNSBL_TIMEOUT_S
    resolver.lifetime = DNSBL_TIMEOUT_S
    return resolver


async def _query(name: str) -> list[str]:
    """A records for `name`, [] when the zone says 'not listed'."""
    import dns.resolver as dns_resolver

    resolver = _resolver()
    try:
        answers = await asyncio.to_thread(resolver.resolve, name, "A")
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer):
        return []
    return [str(a) for a in answers]


def spamhaus_verdict(answers: list[str]) -> bool:
    """True when listed. Raises DnsblUnavailable on an error code."""
    for ip in answers:
        if ip.startswith(SPAMHAUS_ERROR_PREFIX) or ip == SPAMHAUS_IP_QUERY_PROHIBITED:
            raise DnsblUnavailable(f"spamhaus dbl answered {ip}")
    for ip in answers:
        if ip.startswith("127.0.1.") and int(ip.rsplit(".", 1)[1]) in SPAMHAUS_LISTED_CODES:
            return True
    return False


def surbl_verdict(answers: list[str]) -> bool:
    """True when listed. Raises DnsblUnavailable when the mirror blocks us."""
    for ip in answers:
        if ip == SURBL_BLOCKED:
            raise DnsblUnavailable("surbl answered 127.0.0.1: access blocked")
    for ip in answers:
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.packed[:3] == b"\x7f\x00\x00" and addr.packed[3] > 1:
            return True
    return False


async def check_spamhaus_dbl(domain: str) -> bool:
    """Spamhaus DBL via the public mirror (non-commercial terms — see
    licensed_intel). True when listed as spam, phishing, malware or C&C."""
    answers = await _query(f"{domain}.{SPAMHAUS_DBL_ZONE}")
    hit = spamhaus_verdict(answers)
    if hit:
        logger.info("spamhaus_hit", extra={"domain": domain, "result": answers})
    return hit


async def check_surbl(domain: str) -> bool:
    """SURBL multi via the public mirror (non-commercial terms — see
    licensed_intel). SURBL indexes registrable domains, so the base domain is
    what is asked about."""
    base = _extract_base_domain(domain)
    answers = await _query(f"{base}.{SURBL_ZONE}")
    hit = surbl_verdict(answers)
    if hit:
        logger.info("surbl_hit", extra={"domain": domain, "result": answers})
    return hit
