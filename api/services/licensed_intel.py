"""Which threat-intelligence lookups the analyzer may consult under our
licences (plan §4, docs/THIRD_PARTY_FEEDS.md).

Six of the analyzer's sources are free only for non-commercial use of a
public mirror: SURBL (surbl.org/usage-policy: the free service "excludes
embedding SURBL data in a paid product or service"), the Spamhaus DBL public
mirror (spamhaus.org/blocklists/dnsbl-fair-use-policy: "free of charge for
non-commercial use"), and abuse.ch's URLhaus, ThreatFox, MalwareBazaar and
Feodo Tracker (abuse.ch/terms-of-use, 2025-11-04: not-for-profit only, no
derivative works). Since 2026-10-21 abuse.ch's APIs also answer 401 without
a personal Auth-Key (Feodo's download still answers, under the same terms).

LICENSED_INTEL=licensed — the default since 2026-10-21, because Cleanway
sells plans — switches them off. Switched off, a source is not consulted at
all — never asked, so never "not listed": it leaves the check plan and the
total the confidence figures are measured against, so a verdict built on 13
answers of 13 says so, rather than 13 of 19 with six that were never asked.
LICENSED_INTEL=all is an explicit opt-in for a not-for-profit deployment
(and needs an abuse.ch key the analyzer does not send — without one those
lookups fail, which is counted as not measured, never as "not listed").
"""
from __future__ import annotations

from api.config import get_settings

# Check names as api/services/analyzer._check_calls keys them.
RESTRICTED_CHECKS = frozenset({"surbl", "spamhaus", "urlhaus", "threatfox", "malware_bazaar", "feodo"})
LICENSED = "licensed"
ALL = "all"


def licensed_only() -> bool:
    return get_settings().licensed_intel == LICENSED


def skipped_checks() -> frozenset:
    """The checks this deployment does not consult."""
    return RESTRICTED_CHECKS if licensed_only() else frozenset()


def total_checks(full: int) -> int:
    """How many checks a complete analysis has, out of `full`."""
    return full - len(skipped_checks())
