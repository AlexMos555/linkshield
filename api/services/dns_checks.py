"""DNS questions about a domain: does it exist, and what does its DNS look like.

Existence comes first in the analyzer. A typo such as sbertank.ru used to go
through the whole fan-out and come back "dangerous, 53: no HTTPS, no mail
server" — every failed connection to a site that does not exist read as a
red flag (report 2026-09-25 #18). An NXDOMAIN now ends the analysis with an
honest "no such site".
"""

from __future__ import annotations

import asyncio
from typing import Optional

import dns.resolver  # dnspython

# Existence is on the critical path of every fresh check, so it gets a short
# leash; the enrichment lookups run in parallel with everything else.
EXISTENCE_TIMEOUT_S = 1.5
ENRICHMENT_TIMEOUT_S = 2.0


def _resolver(timeout_s: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_s
    resolver.lifetime = timeout_s
    return resolver


async def check_domain_exists(domain: str) -> Optional[bool]:
    """Does DNS know this name? False ONLY on an authoritative NXDOMAIN.

    A timeout, SERVFAIL or a refused resolver is None ("could not tell"),
    never False: a name server that ignores foreign resolvers must not turn a
    real site into "does not exist". A name with no IPv4 address still exists.
    """
    try:
        await asyncio.to_thread(_resolver(EXISTENCE_TIMEOUT_S).resolve, domain, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return True
    except Exception:
        return None


async def check_dns(domain: str) -> dict:
    """
    Analyze DNS records for phishing indicators:
    - Low TTL = fast-flux (bulletproof hosting)
    - No MX = not a real business domain
    - Many A records = CDN or fast-flux
    - Few/suspicious NS = cheap/disposable hosting

    The three lookups run concurrently: in sequence they could take three
    full resolver timeouts, the whole analysis budget and more.
    """
    resolver = _resolver(ENRICHMENT_TIMEOUT_S)

    async def _lookup(rdtype: str):
        try:
            return await asyncio.to_thread(resolver.resolve, domain, rdtype)
        except Exception:
            return None

    a_answers, ns_answers, mx_answers = await asyncio.gather(
        _lookup("A"), _lookup("NS"), _lookup("MX"),
    )
    result: dict = {
        "a_count": len(a_answers) if a_answers is not None else 0,
        "ttl": a_answers.rrset.ttl if a_answers is not None and a_answers.rrset else None,
        "ns_count": len(ns_answers) if ns_answers is not None else 0,
        "has_mx": mx_answers is not None and len(mx_answers) > 0,
    }
    if ns_answers is not None:
        result["nameservers"] = [str(ns) for ns in ns_answers]
    return result
