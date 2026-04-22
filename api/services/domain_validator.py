"""
Domain validation and SSRF protection.

Validates domain format and ensures it doesn't resolve to internal/private IPs.
This prevents Server-Side Request Forgery (SSRF) attacks where an attacker
submits domains like "169.254.169.254" to probe cloud metadata endpoints.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
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
_DOMAIN_PATTERN = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$"
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
        raise DomainValidationError(f"Domain '{domain}' is not allowed")

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
        raise DomainValidationError(f"IP address '{ip_str}' is in a blocked range")


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP falls in any blocked range."""
    return any(ip in network for network in _BLOCKED_NETWORKS)


async def validate_domain_resolution(domain: str) -> None:
    """
    Resolve domain via DNS and verify all IPs are safe.
    Call this BEFORE making any HTTP requests to the domain.
    Raises DomainValidationError if domain resolves to blocked IP.
    """
    # Skip DNS check for known-good domains (top sites)
    # This is handled upstream by scoring.py TOP_DOMAINS check

    try:
        infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        # Domain doesn't resolve — might be dead/parked
        # Allow analysis to continue (WHOIS check will still work)
        logger.debug("Domain does not resolve: %s", domain)
        return

    for family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if _is_blocked_ip(ip):
            logger.warning(
                "SSRF attempt blocked: domain=%s resolved_ip=%s",
                domain, ip_str,
            )
            raise DomainValidationError(
                f"Domain '{domain}' resolves to a blocked IP range"
            )
