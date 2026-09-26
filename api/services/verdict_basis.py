"""What a verdict rests on — the machine-readable `verdict_basis` of every check.

The phone blocks a site dynamically (after a tapped link came back
'dangerous') and that block outlives the moment: the site stops opening until
the shield restarts. A block is a strong act, so it must rest on evidence,
never on a guess. On 2026-09-25 the server called bankspb.ru, президент.рф and
two regional administrations 'dangerous' from heuristics alone (report #1),
and the phone would have darkened them.

So every response says which kind of evidence carried it:

  blocklist          our own published list (the one the phone already has)
  threat_intel       an external feed lists this host (Google Safe Browsing,
                     URLhaus, Spamhaus …) and the verdict is 'dangerous'
  allowlist          a popular domain / the person's own whitelist
  ml_and_heuristics  our rules plus the ML model (and the LLM judge, if it ran)
  heuristics         our rules only
  unreachable        the site exists but our scanner could not open it; the
                     verdict rests on name, DNS and threat-intel misses only
  not_found          the domain does not exist (NXDOMAIN)
  user_content       the host is a real service where anyone can publish
                     pages (disk.yandex.ru, onedrive.live.com): we can vouch
                     for the service, never for the page

Only BLOCKING_BASES justify a block. A client MUST treat any other value —
including one it has never seen — as advice to show, not a reason to block.
"""

from __future__ import annotations

from typing import Iterable, Optional

from api.models.schemas import ConfidenceLevel, DomainReason, DomainResult, RiskLevel
from api.services.scoring import calculate_confidence_pct

BASIS_BLOCKLIST = "blocklist"
BASIS_THREAT_INTEL = "threat_intel"
BASIS_ALLOWLIST = "allowlist"
BASIS_ML_AND_HEURISTICS = "ml_and_heuristics"
BASIS_HEURISTICS = "heuristics"
BASIS_UNREACHABLE = "unreachable"
BASIS_NOT_FOUND = "not_found"
BASIS_USER_CONTENT = "user_content"

ALL_BASES = frozenset({
    BASIS_BLOCKLIST, BASIS_THREAT_INTEL, BASIS_ALLOWLIST, BASIS_ML_AND_HEURISTICS,
    BASIS_HEURISTICS, BASIS_UNREACHABLE, BASIS_NOT_FOUND, BASIS_USER_CONTENT,
})
BLOCKING_BASES = frozenset({BASIS_BLOCKLIST, BASIS_THREAT_INTEL})

# Reason codes introduced with the basis. Clients localize by code
# (mobile.reason.<key>) and fall back to the English detail.
REASON_CLEANWAY_BLOCKLIST = "cleanway_blocklist"
REASON_DOMAIN_NOT_FOUND = "domain_not_found"
REASON_UNREACHABLE = "unreachable_from_scanner"
REASON_CHECKS_INCOMPLETE = "checks_incomplete"
REASON_USER_CONTENT = "user_content_platform"

# Zero-weight reasons that explain the verdict's limits rather than argue for
# or against the site. Shown whatever the verdict's direction (to clients that
# cannot localize them, only when nothing else explains the verdict — see
# public._verdict_reasons).
INFORMATIONAL_REASONS = frozenset({
    REASON_DOMAIN_NOT_FOUND, REASON_UNREACHABLE, REASON_CHECKS_INCOMPLETE,
    REASON_USER_CONTENT, "partial_analysis",
})

# Hard listings of THIS host by an external feed. Deliberately NOT here:
# AlienVault OTX (a pulse that MENTIONS a domain is usually a victim reference —
# it put a national newspaper at 'dangerous'), IPQualityScore (its risk score
# and its `phishing` flag are the vendor's own scoring of the host, not a
# listing), the multi-source bonus (never fires without one of these), and our
# own name heuristics (typosquat watchtower, favicon clone) — judgement, not
# listings. PhishStats qualifies only because check_phishstats requires a
# listed URL's host to BE this host: its old substring search matched any
# phishing URL that merely contained the name (bankspb.ru.secure-login.xyz).
THREAT_INTEL_REASONS = frozenset({
    "safe_browsing", "phishtank", "urlhaus", "phishstats", "threatfox",
    "spamhaus_dbl", "surbl", "malware_bazaar", "feodo",
})
_ALLOWLIST_REASONS = frozenset({"known_legitimate", "user_whitelist"})
_MODEL_REASONS = frozenset({"ml_high_risk", "ml_suspicious", "ml_safe_override", "llm_judge"})

# "We cannot vouch for it": caution, just past the 'safe' line. The analyzer's
# floor for a partial analysis and for an unknown site it could not open, and
# the fixed score of the answers below that need no analysis — so the
# three-level clients need no new state.
CANNOT_VOUCH_SCORE = 25
# A domain that does not exist is shown as caution, never 'dangerous' (it can
# hurt no one today) and never 'safe' (it can be registered tomorrow, and a
# typo of a bank's name is exactly what a scammer registers).
NOT_FOUND_SCORE = CANNOT_VOUCH_SCORE
BLOCKLIST_SCORE = 90

_UNREACHABLE_WHY = {
    "timeout": "it did not answer",
    "refused": "it refused the connection",
    "reset": "it dropped the connection",
    "tls_certificate": "its certificate is from an authority our scanner does not recognise",
    "tls_handshake": "a secure connection could not be set up",
    "too_many_redirects": "it redirected in a loop",
    "dns": "its address could not be looked up",
}


def derive_verdict_basis(result: DomainResult, ml_consulted: bool = False) -> str:
    """The basis for `result`, from its reasons and flags.

    Pure, so it also labels results cached before the field existed.
    `ml_consulted` says the ML model ran and had no strong opinion — a
    neutral model verdict is still part of the judgement, but leaves no
    reason behind.
    """
    codes = {r.signal for r in result.reasons}
    if REASON_CLEANWAY_BLOCKLIST in codes:
        return BASIS_BLOCKLIST
    if result.level == RiskLevel.dangerous and codes & THREAT_INTEL_REASONS:
        return BASIS_THREAT_INTEL
    if result.exists is False or REASON_DOMAIN_NOT_FOUND in codes:
        return BASIS_NOT_FOUND
    if codes & _ALLOWLIST_REASONS:
        return BASIS_ALLOWLIST
    if REASON_UNREACHABLE in codes:
        return BASIS_UNREACHABLE
    if ml_consulted or codes & _MODEL_REASONS:
        return BASIS_ML_AND_HEURISTICS
    return BASIS_HEURISTICS


def basis_of(result: DomainResult) -> str:
    """The stored basis, or a derived one for results that predate it."""
    return result.verdict_basis or derive_verdict_basis(result)


# ── Reasons ──

def unreachable_reason(kind: Optional[str], known_site: bool = True) -> DomainReason:
    """Why the site itself was not checked — neither reassuring nor alarming:
    some banks and government sites refuse foreign connections, and so do
    phishing kits hiding from scanners. `known_site` False adds that nothing
    else vouches for it either (the analyzer then floors the verdict)."""
    why = _UNREACHABLE_WHY.get(kind or "", "it could not be reached")
    unknown = "" if known_site else " It is also not a widely known site, so we cannot vouch for it."
    return DomainReason(
        signal=REASON_UNREACHABLE, weight=0,
        detail=(
            f"Our scanner abroad could not open this site ({why}), so the site itself "
            "was not checked. Some banks and government sites refuse foreign "
            "connections, but so do scam sites hiding from checks: on its own this "
            f"says nothing either way.{unknown}"
        ),
    )


def checks_incomplete_reason(names: Iterable[str]) -> DomainReason:
    """Says THAT checks were cut off, in words a person can use. The internal
    names (llm_judge, phishstats) stay in the result's `checks_incomplete`."""
    unique = set(names)
    if "analysis" in unique:
        detail = "Our full check did not finish in time, so this verdict rests on the address alone."
    else:
        did = "1 check did" if len(unique) == 1 else f"{len(unique)} checks did"
        detail = (
            f"{did} not finish in time and had to be left out, so this verdict "
            "rests on fewer checks than usual."
        )
    return DomainReason(signal=REASON_CHECKS_INCOMPLETE, weight=0, detail=detail)


def user_content_reason() -> DomainReason:
    return DomainReason(
        signal=REASON_USER_CONTENT, weight=0,
        detail=(
            "Anyone can publish pages on this service, scammers included. The "
            "service itself is legitimate; that says nothing about this page."
        ),
    )


# ── Whole verdicts that need no analysis ──

def not_found_result(domain: str) -> DomainResult:
    # NXDOMAIN says the name is not in DNS — NOT that nobody registered it: a
    # suspended .ru domain ("снят с делегирования") and a freshly registered
    # one without name servers look the same. So "does not work", never
    # "is not registered".
    return DomainResult(
        domain=domain, score=NOT_FOUND_SCORE, level=RiskLevel.caution,
        confidence=ConfidenceLevel.high,
        confidence_pct=calculate_confidence_pct(NOT_FOUND_SCORE, 1, 1),
        reasons=[DomainReason(
            signal=REASON_DOMAIN_NOT_FOUND, weight=0,
            detail=(
                "This address does not work right now: there is no site at it. "
                "Check the spelling, and be careful if it starts working later, "
                "because a misspelt bank name is what scammers register."
            ),
        )],
        exists=False, verdict_basis=BASIS_NOT_FOUND,
    )


def blocklist_result(domain: str, listed_as: Optional[str] = None) -> DomainResult:
    """`listed_as` is the name the list matched. The list covers every address
    under a listed name, so when that is a PARENT of `domain`, say so."""
    what = (
        f"Its parent address {listed_as} is on Cleanway's list of known phishing and "
        "scam sites, and the list covers every address under it."
        if listed_as and listed_as != domain else
        "On Cleanway's list of known phishing and scam sites."
    )
    return DomainResult(
        domain=domain, score=BLOCKLIST_SCORE, level=RiskLevel.dangerous,
        confidence=ConfidenceLevel.high,
        confidence_pct=calculate_confidence_pct(BLOCKLIST_SCORE, 1, 1),
        reasons=[DomainReason(
            signal=REASON_CLEANWAY_BLOCKLIST, weight=BLOCKLIST_SCORE,
            detail=f"{what} With protection on, the Cleanway app blocks sites on this list.",
        )],
        verdict_basis=BASIS_BLOCKLIST,
    )


def user_content_result(domain: str) -> DomainResult:
    """The service host of a user-content platform (disk.yandex.ru, see
    hosting_platforms.is_user_content_service): a real service, an unknown page."""
    return DomainResult(
        domain=domain, score=CANNOT_VOUCH_SCORE, level=RiskLevel.caution,
        confidence=ConfidenceLevel.high,
        confidence_pct=calculate_confidence_pct(CANNOT_VOUCH_SCORE, 1, 1),
        reasons=[user_content_reason()],
        verdict_basis=BASIS_USER_CONTENT,
    )


def allowlist_result(domain: str) -> DomainResult:
    """The popular-domain short-circuit: no analysis, nothing to explain."""
    return DomainResult(
        domain=domain, score=0, level=RiskLevel.safe,
        confidence=ConfidenceLevel.high, confidence_pct=99, reasons=[],
        verdict_basis=BASIS_ALLOWLIST,
    )
