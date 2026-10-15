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

Cloudflare (when api.cleanway.ai is proxied, docs/runbooks/cloudflare-proxy.md):
`cloudflare|client=header` / `cloudflare|client=xff` count requests whose hop in
front of Railway's edge was a Cloudflare address (client taken from
CF-Connecting-IP / from the address Cloudflare appended to X-Forwarded-For);
`cloudflare_header_ignored` counts a CF-Connecting-IP that did not come through
Cloudflare (forged, or sent straight to the Railway origin).
"""
from __future__ import annotations

import ipaddress
import pathlib
from collections import Counter
from functools import lru_cache
from typing import Optional

# Railway's edge has been observed connecting from the shared address space.
CANDIDATE_RAILWAY_PROXY_NET = ipaddress.ip_network("100.64.0.0/10")

# Vendored from https://www.cloudflare.com/ips/ by scripts/refresh_cloudflare_ips.py.
CLOUDFLARE_IPS_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "cloudflare_ips.txt"

_MAX_KEYS = 32
_BUCKET_CACHE_MAX = 1024
_bucket_cache: dict[str, str] = {}
COUNTS: Counter = Counter()


def load_networks(path: pathlib.Path) -> list:
    """CIDRs from a vendored ranges file; `#` comments and blank lines skipped.
    A malformed line raises: a broken file must fail tests, not trust less."""
    nets = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line))
    return nets


@lru_cache(maxsize=1)
def cloudflare_networks() -> tuple:
    return tuple(load_networks(CLOUDFLARE_IPS_PATH))


def parse_ip(value: Optional[str]):
    """An address, or None. Tolerates whitespace and IPv6 brackets."""
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip().lstrip("[").rstrip("]"))
    except ValueError:
        return None


def is_cloudflare(value) -> bool:
    ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else parse_ip(value)
    if ip is None:
        return False
    return any(ip.version == net.version and ip in net for net in cloudflare_networks())


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
        if is_cloudflare(ip):
            label = "cloudflare"
        elif ip.version == 4 and ip in CANDIDATE_RAILWAY_PROXY_NET:
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


CLOUDFLARE_OUTCOMES = frozenset({"cloudflare|client=header", "cloudflare|client=xff", "cloudflare_header_ignored"})


def observe_cloudflare(outcome: str) -> None:
    """One of CLOUDFLARE_OUTCOMES — a fixed set, so the key count stays bounded."""
    if outcome in CLOUDFLARE_OUTCOMES:
        COUNTS[outcome] += 1


def snapshot() -> dict:
    return dict(COUNTS)


def reset_for_tests() -> None:
    COUNTS.clear()
    _bucket_cache.clear()
