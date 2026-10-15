"""
Domain validation and SSRF protection.

Validates domain format and ensures it doesn't resolve to internal/private IPs.
This prevents Server-Side Request Forgery (SSRF) attacks where an attacker
submits domains like "169.254.169.254" to probe cloud metadata endpoints.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("cleanway.domain_validator")

# RFC 1035: max domain length is 253 characters
_MAX_DOMAIN_LENGTH = 253

# Blocked IP ranges — internal networks, cloud metadata, loopback
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),         # Private (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),       # Private (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),      # Private (RFC 1918)
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / AWS metadata
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("0.0.0.0/8"),           # "This" network
    ipaddress.ip_network("100.64.0.0/10"),       # Shared address space (CGN)
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol Assignments
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
]

# Simple domain regex: letters, digits, hyphens, dots
# The TLD alternative accepts punycode zones (xn--…). The previous pattern
# required a purely alphabetic TLD, which 400'd every IDN-zone domain even in
# its correct ASCII form — пример.рф arrives as xn--e1afmkfd.xn--p1ai, and
# ".рф", ".中国", ".भारत" users simply could not get a verdict. Homograph
# phishing leans on exactly these zones, so rejecting them disabled analysis
# where it matters most.
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(\.[a-zA-Z0-9-]{1,63})*"
    r"\.([a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{1,59}(?<!-))$"
)

# Valid IP address pattern (for explicit IP check)
_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Blocked domain names (case-insensitive)
_BLOCKED_DOMAINS = {
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
}


class DomainValidationError(Exception):
    """Raised when domain validation fails."""

    pass


class SSRFBlocked(DomainValidationError):
    """The name, address or port points inside a private network (not a
    mere typo). Counted by api/services/security_alerts.py as `ssrf_blocked`."""


def normalize_domain(raw_input: str) -> str:
    """
    Normalize user input into a clean domain name.
    Strips protocols, paths, ports, auth info.
    """
    domain = raw_input.lower().strip().rstrip("/")

    # If it looks like a URL, extract hostname
    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain

    # Strip port if present (e.g., "example.com:8080")
    if ":" in domain and not domain.startswith("["):
        domain = domain.split(":")[0]

    return domain


def validate_domain(domain: str) -> str:
    """
    Validate and sanitize a domain name.
    Returns the validated domain or raises DomainValidationError.
    """
    if not domain:
        raise DomainValidationError("Domain cannot be empty")

    domain = normalize_domain(domain)

    if not domain:
        raise DomainValidationError("Domain cannot be empty after normalization")

    if len(domain) > _MAX_DOMAIN_LENGTH:
        raise DomainValidationError(f"Domain exceeds max length ({_MAX_DOMAIN_LENGTH} chars)")

    # Check blocked domain names
    if domain in _BLOCKED_DOMAINS:
        raise SSRFBlocked(f"Domain '{domain}' is not allowed")

    # Check if it's an IP address
    if _IP_PATTERN.match(domain):
        _validate_ip(domain)
        return domain  # Valid public IP — allow analysis

    # Validate domain format
    if not _DOMAIN_PATTERN.match(domain):
        raise DomainValidationError(f"Invalid domain format: '{domain}'")

    return domain


def _validate_ip(ip_str: str) -> None:
    """Validate that an IP address is not in a blocked range."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        raise DomainValidationError(f"Invalid IP address: '{ip_str}'")

    if _is_blocked_ip(ip):
        raise SSRFBlocked(f"IP address '{ip_str}' is in a blocked range")


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP falls in any blocked range."""
    return any(ip in network for network in _BLOCKED_NETWORKS)


# ── Where the server may connect ──
#
# Everything below guards the connections WE open to a user-supplied host
# (site probes, favicon fetch, look-alike page fetch). The rules, in order:
#
#   1. only ports 80 and 443, on the first request and on every redirect;
#   2. the NAME must be a public one: no single-label names, nothing under
#      .internal / .local / .localhost / .railway.internal (Railway's private
#      network — redis.railway.internal is our own Redis), and the last label
#      must be a TLD in the IANA root zone (data/iana_tlds.txt);
#   3. EVERY address the name resolves to must be globally routable, after
#      unwrapping IPv6 forms that carry an IPv4 address (::ffff:a.b.c.d,
#      6to4 2002::/16, NAT64 64:ff9b::/96); Teredo is refused outright;
#   4. the connection goes to the address that was checked — never a second
#      lookup of the name — so a DNS answer that changes between the check
#      and the connect (DNS rebinding) cannot point us inside.

ALLOWED_PORTS = frozenset({80, 443})

# Suffixes that only ever name something on a private network.
_INTERNAL_SUFFIXES = (
    ".internal", ".railway.internal", ".local", ".localhost", ".localdomain",
    ".home.arpa", ".arpa",
)

_TEREDO = ipaddress.ip_network("2001::/32")
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_EXTRA_BLOCKED = [
    ipaddress.ip_network("64:ff9b:1::/48"),     # local-use NAT64: maps to anything
    ipaddress.ip_network("2001:db8::/32"),      # documentation
    ipaddress.ip_network("100::/64"),           # discard-only
    ipaddress.ip_network("::/128"),             # unspecified
]


def _load_known_tlds() -> frozenset[str]:
    path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "iana_tlds.txt")
    try:
        with open(path, encoding="utf-8") as f:
            return frozenset(
                line.strip().lower() for line in f
                if line.strip() and not line.startswith("#")
            )
    except OSError:
        logger.warning("iana_tlds.txt missing — hostnames are not checked against the root zone")
        return frozenset()


_KNOWN_TLDS = _load_known_tlds()


class HostNotFound(DomainValidationError):
    """The name has no address: nothing to connect to (not a policy refusal)."""


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address an IPv6 address really leads to, if it carries one."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for a globally routable unicast address."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            return False
        if ip in _TEREDO:
            # The tunnel's real endpoint is obfuscated in the address; we
            # cannot vouch for where it leads.
            return False
        inner = _embedded_ipv4(ip)
        if inner is not None:
            return is_public_address(inner)
        if ip.is_site_local:
            return False
    if _is_blocked_ip(ip) or any(ip in net for net in _EXTRA_BLOCKED if net.version == ip.version):
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    return ip.is_global


def _ip_literal(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _clean_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def check_hostname_policy(host: str) -> None:
    """Raise DomainValidationError unless `host` may be connected to by name.

    IP literals pass here (their address is checked on its own)."""
    h = _clean_host(host)
    if not h:
        raise DomainValidationError("empty hostname")
    if _ip_literal(h) is not None:
        return
    if "." not in h:
        raise DomainValidationError(f"single-label hostname '{h}' is not allowed")
    if h in _BLOCKED_DOMAINS or any(h.endswith(s) or h == s[1:] for s in _INTERNAL_SUFFIXES):
        raise SSRFBlocked(f"hostname '{h}' names a private network")
    tld = h.rsplit(".", 1)[1]
    if _KNOWN_TLDS and tld not in _KNOWN_TLDS:
        raise DomainValidationError(f"hostname '{h}' is not under a public suffix")


def _getaddrinfo(host: str, port: int):
    """The OS resolver; a seam the tests replace."""
    return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)


def resolve_public_sync(host: str, port: int = 443) -> list[str]:
    """The addresses to connect to for `host`:`port`, every one of them public.

    Raises HostNotFound when the name has no address, DomainValidationError
    when the port, the name or ANY of its addresses is not allowed. Connect
    to one of the returned addresses — never to the name again.
    """
    if port not in ALLOWED_PORTS:
        raise SSRFBlocked(f"port {port} is not allowed")
    h = _clean_host(host)
    literal = _ip_literal(h)
    if literal is not None:
        if not is_public_address(literal):
            raise SSRFBlocked(f"address '{h}' is not public")
        return [str(literal)]
    check_hostname_policy(h)
    try:
        infos = _getaddrinfo(h, port)
    except (socket.gaierror, UnicodeError) as exc:
        raise HostNotFound(f"'{h}' does not resolve") from exc
    addresses: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            # A scoped address (fe80::1%eth0) and anything unparsable.
            raise SSRFBlocked(f"'{h}' resolves to an unusable address")
        if not is_public_address(ip):
            logger.warning("SSRF attempt blocked: domain=%s resolved_ip=%s", h, ip)
            raise SSRFBlocked(f"Domain '{h}' resolves to a blocked IP range")
        if str(ip) not in addresses:
            addresses.append(str(ip))
    if not addresses:
        raise HostNotFound(f"'{h}' has no address")
    return addresses


async def resolve_public(host: str, port: int = 443) -> list[str]:
    """`resolve_public_sync` off the event loop: getaddrinfo blocks for
    50–500 ms normally and seconds on a flaky resolver."""
    return await asyncio.to_thread(resolve_public_sync, host, port)


async def validate_domain_resolution(domain: str) -> None:
    """
    The analyzer's SSRF gate: raises DomainValidationError when the name may
    not be connected to (private name, or any address that is not public).

    A name that does not resolve passes — the WHOIS / reputation checks still
    apply to it, and the probes, which resolve again, will not connect.
    """
    try:
        await resolve_public(domain, 443)
    except HostNotFound:
        logger.debug("Domain does not resolve: %s", domain)
