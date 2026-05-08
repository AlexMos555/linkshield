"""Disposable / throwaway email detection.

Defense against free-tier farming: an attacker registers thousands of
accounts via temp-mail providers (mailinator.com, 10minutemail.com,
guerrillamail.com, …) to consume our 50-threat freemium quota and burn
3rd-party API budget (Google Safe Browsing 10K/day, IPQualityScore
5K/month).

The list is vendored from
  https://github.com/disposable-email-domains/disposable-email-domains
(MIT-licensed, ~5400 domains, refreshed quarterly). Loaded once at
import time into a frozenset for O(1) lookup; ~80KB resident, no
network calls at runtime.

This is defense-in-depth, not absolute:
  - Sophisticated attackers spin up custom temp domains we don't list.
  - Anyone with the public Supabase anon key can call signInWithOtp
    directly, bypassing our /api/v1/auth/check-email pre-flight.
The mitigation is to also flag emails server-side at trigger level
(future migration) so even direct Supabase Auth signups land in a
quarantined state. For now this catches the noisy 90% of bots.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger("cleanway.email_validator")

_BLOCKLIST_PATH = Path(__file__).resolve().parent.parent / "data" / "disposable_emails.txt"


def _load_blocklist() -> frozenset[str]:
    """Read the vendored blocklist into an immutable, lower-cased set.

    Frozenset membership is O(1) and the import-time load means the
    cost (~5400 hash table inserts) hits process startup, not per-
    request. Failed reads degrade open: log and return an empty set so
    the API still serves — better than crashing on a missing data
    file in some unrelated deploy.
    """
    try:
        with _BLOCKLIST_PATH.open("r", encoding="utf-8") as f:
            domains = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        logger.info("disposable_blocklist_loaded", extra={"count": len(domains)})
        return frozenset(domains)
    except OSError as e:  # pragma: no cover — file is committed
        logger.error("disposable_blocklist_load_failed", extra={"error": str(e)})
        return frozenset()


_DISPOSABLE_DOMAINS: frozenset[str] = _load_blocklist()


def is_disposable_email(email: str) -> bool:
    """Return True if `email`'s domain is in the disposable blocklist.

    Empty / malformed inputs return False so the caller can decide what
    to do with bad shapes (the standard email-format check belongs
    upstream, not here).
    """
    if not email or "@" not in email:
        return False
    # rsplit handles edge cases like `"foo@bar"@example.com` (legal RFC
    # but Postel's-law-treated by everyone) — we always take the bit
    # after the LAST @ as the domain.
    domain = email.rsplit("@", 1)[1].strip().lower()
    if not domain:
        return False
    return domain in _DISPOSABLE_DOMAINS


def disposable_blocklist_size() -> int:
    """Exposed for /health/deep style debug endpoints."""
    return len(_DISPOSABLE_DOMAINS)
