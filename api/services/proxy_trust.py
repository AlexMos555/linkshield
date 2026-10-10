"""Which networks the proxies in front of us connect from — aggregate only.

Why: production must set TRUSTED_PROXY_CIDRS, and a wrong value is dangerous.
If the real proxy peer is outside the list, X-Forwarded-For is ignored, every
user collapses onto the proxy's address and shares one rate-limit bucket — DNS
on every phone would get 429. Railway does not publish its proxy range (forum
reports point at 100.64.0.0/10), so we measure it before trusting it.

What is counted: the TCP peer's network (the proxy, not the user) bucketed to
a prefix, whether the request carried X-Forwarded-For, and whether the
configured list trusted the peer. No client address, no header value, nothing
per request is kept. The counters go out in the periodic `doh_stats` log line.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Optional

# Railway's edge has been observed connecting from the shared address space.
CANDIDATE_RAILWAY_PROXY_NET = ipaddress.ip_network("100.64.0.0/10")

_MAX_KEYS = 32
_BUCKET_CACHE_MAX = 1024
_bucket_cache: dict[str, str] = {}
COUNTS: Counter = Counter()


def peer_bucket(peer: Optional[str]) -> str:
    """A coarse network label for the proxy's address."""
    if not peer:
        return "none"
    cached = _bucket_cache.get(peer)
    if cached is not None:
        return cached
    try:
        ip = ipaddress.ip_address(peer.strip().lstrip("[").rstrip("]"))
    except ValueError:
        label = "unparsed"
    else:
        if ip.version == 4 and ip in CANDIDATE_RAILWAY_PROXY_NET:
            label = str(CANDIDATE_RAILWAY_PROXY_NET)
        elif ip.version == 4:
            label = str(ipaddress.ip_network(f"{ip}/16", strict=False))
        else:
            label = str(ipaddress.ip_network(f"{ip}/32", strict=False))
    if len(_bucket_cache) < _BUCKET_CACHE_MAX:
        _bucket_cache[peer] = label
    return label


def observe(peer: Optional[str], has_xff: bool, trust_configured: bool, xff_trusted: bool) -> None:
    trust = "trusted" if xff_trusted else "untrusted"
    key = f"{peer_bucket(peer)}|xff={int(has_xff)}|{trust if trust_configured else 'no_list'}"
    if key not in COUNTS and len(COUNTS) >= _MAX_KEYS:
        key = "other"
    COUNTS[key] += 1
    # The collapse signal: a proxy sent the client's address and we threw it away.
    if trust_configured and has_xff and not xff_trusted:
        COUNTS["xff_ignored_untrusted_peer"] += 1


def snapshot() -> dict:
    return dict(COUNTS)


def reset_for_tests() -> None:
    COUNTS.clear()
    _bucket_cache.clear()
