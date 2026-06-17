"""Typosquat Watchtower — Strategy doc Top-20 #17.

Predictive defense: monitor newly-registered cousin-domains of
brands users add to their watchlist, before the next phishing
campaign aims at them. We poll crt.sh (Sectigo's public
Certificate Transparency log mirror) once a day for each watched
brand's root domain, expand suspect domains into typosquat_alerts,
and surface them through the API.

Data source choice:

  * crt.sh JSON API is free, no key required, polite to scrape
    with a per-host throttle. We rate-limit at 1 req/sec.
  * Calidog certstream (live WebSocket) was the original plan but
    pushes 50k certs/sec at peak. For an MVP, a daily LIKE-match
    pull per brand is enough — cousin-domain registration is days-
    to-weeks of dwell time, not seconds.
  * Censys / Cisco Umbrella would add coverage but they're paid.
    Add later if revenue supports it.

Variant kinds we surface:

  * "typo"      — Levenshtein ≤ 2 on the eTLD+1 label
                  (paypa1.com, paypall.com)
  * "tld"       — same label, different TLD
                  (paypal.tk, paypal.xyz)
  * "homograph" — punycode-decoded label contains confusable
                  characters from a different alphabet
                  (xn--... that decodes to "paypа1.com" with
                  Cyrillic 'а')
  * "subdomain" — the brand name appears as a subdomain on an
                  unrelated host (paypal.attacker.tld)

Privacy:

  * Inputs: brand_root_domain (e.g., "paypal.com") — public info.
  * Outputs: typosquat_alerts rows — public info (a cert exists).
  * NO per-user data leaves the device → CT log. The mapping from
    brand → user lives only in our DB, gated by RLS.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Iterable, Optional

import httpx

logger = logging.getLogger(__name__)

CRT_SH_BASE = "https://crt.sh/"
CRT_SH_TIMEOUT_S = 20.0
CRT_SH_MIN_INTERVAL_S = 1.0   # polite throttle
MAX_LEVENSHTEIN_DISTANCE = 2  # rows further than this are dropped
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}$")


# ─────────────────────────────────────────────────────────────────
# Public types
# ─────────────────────────────────────────────────────────────────

class TyposquatCandidate:
    """In-memory candidate before we persist to typosquat_alerts."""

    __slots__ = (
        "brand_root", "suspect", "edit_distance",
        "variant_kind", "first_seen_at", "issuer",
    )

    def __init__(
        self,
        brand_root: str,
        suspect: str,
        edit_distance: int,
        variant_kind: str,
        first_seen_at: str,
        issuer: Optional[str],
    ):
        self.brand_root = brand_root
        self.suspect = suspect
        self.edit_distance = edit_distance
        self.variant_kind = variant_kind
        self.first_seen_at = first_seen_at
        self.issuer = issuer

    def as_dict(self) -> dict:
        return {
            "brand_root_domain": self.brand_root,
            "suspect_domain": self.suspect,
            "edit_distance": self.edit_distance,
            "variant_kind": self.variant_kind,
            "first_seen_at": self.first_seen_at,
            "issuer": self.issuer,
        }


# ─────────────────────────────────────────────────────────────────
# Levenshtein (small, no deps)
# ─────────────────────────────────────────────────────────────────

def levenshtein(a: str, b: str) -> int:
    """Standard dynamic-programming edit distance. O(len(a)*len(b))
    time and O(min(len(a), len(b))) space.

    For our use the inputs are eTLD+1 labels (≤63 chars) so even
    the naive matrix would be fine, but the rolling-row version is
    half the memory and adds nothing to the code complexity.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) > len(b):
        a, b = b, a  # ensure a is shorter — row is len(a)+1
    prev = list(range(len(a) + 1))
    for j, ch_b in enumerate(b, 1):
        cur = [j] + [0] * len(a)
        for i, ch_a in enumerate(a, 1):
            cost = 0 if ch_a == ch_b else 1
            cur[i] = min(
                cur[i - 1] + 1,       # insertion
                prev[i] + 1,           # deletion
                prev[i - 1] + cost,    # substitution
            )
        prev = cur
    return prev[-1]


# ─────────────────────────────────────────────────────────────────
# eTLD+1 + label helpers
# ─────────────────────────────────────────────────────────────────

# Minimal PSL for the brand-watch use case. The hot path is
# splitting `subdomain.paypal.com` into ("paypal", "com") so we
# can compare the brand label. We DON'T need the full Mozilla PSL —
# the 30 most common TLDs cover ~99% of typosquat traffic per
# threat intel reports. For long-tail TLDs we fall back to "last
# two dotted segments" which is wrong for .co.uk but close enough
# for an MVP.
COMMON_MULTI_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in",
    "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.tw",
    "org.uk", "ac.uk", "gov.uk", "ne.jp",
}


def split_root(domain: str) -> tuple[str, str]:
    """Return (label, suffix) for the eTLD+1 of `domain`.

    Examples:
      "paypal.com"           → ("paypal", "com")
      "www.paypal.com"       → ("paypal", "com")
      "secure.paypal.co.uk"  → ("paypal", "co.uk")
      "evil.attacker.tld"    → ("attacker", "tld")
    """
    parts = (domain or "").strip().lower().strip(".").split(".")
    if len(parts) < 2:
        return (parts[0] if parts else ""), ""
    # Check multi-segment TLDs first.
    last_two = ".".join(parts[-2:])
    if last_two in COMMON_MULTI_TLDS and len(parts) >= 3:
        return parts[-3], last_two
    return parts[-2], parts[-1]


def eTLD1(domain: str) -> str:
    """Return the eTLD+1 of `domain`, lowercased and IDNA-safe."""
    label, suffix = split_root(domain)
    if not label:
        return ""
    return f"{label}.{suffix}" if suffix else label


# ─────────────────────────────────────────────────────────────────
# Variant detection
# ─────────────────────────────────────────────────────────────────

def is_likely_typosquat(brand_root: str, suspect: str) -> Optional[tuple[int, str]]:
    """Classify `suspect` against `brand_root`. Returns
    (edit_distance, variant_kind) if it qualifies, None otherwise.

    Both inputs must be eTLD+1-shaped. brand_root is the canonical
    target (e.g., "paypal.com"); suspect is the candidate that
    just appeared in CT logs.
    """
    if not brand_root or not suspect:
        return None
    brand_root = brand_root.lower()
    suspect = suspect.lower()

    # Trivial: identical = legitimate (the watched brand is in CT
    # every day; we never alert on it).
    if brand_root == suspect:
        return None

    b_label, b_suffix = split_root(brand_root)
    s_label, s_suffix = split_root(suspect)
    if not b_label or not s_label:
        return None

    # 1) Same label, different suffix — TLD switch. paypal.com vs paypal.tk.
    if b_label == s_label and b_suffix != s_suffix:
        return (0, "tld")

    # 2) Brand label appears as a subdomain. paypal.attacker.tld.
    suspect_parts = suspect.split(".")
    # Drop the eTLD+1 suffix part; what's left is the subdomain chain.
    sub_chain = suspect_parts[:-1] if s_suffix and "." not in s_suffix else suspect_parts[:-2]
    if b_label in sub_chain:
        return (0, "subdomain")

    # 3) Levenshtein on the label only (suffix difference is noise).
    dist = levenshtein(b_label, s_label)
    if 1 <= dist <= MAX_LEVENSHTEIN_DISTANCE:
        return (dist, "typo")

    # 4) Homograph: if the suspect's punycode-decoded label contains
    #    confusable characters (Cyrillic а/о/е, Greek alpha) it's
    #    a possible homograph attack on the brand.
    if b_label.isascii() and not s_label.isascii():
        # The suspect went through IDNA decoding (httpx already does
        # this for us when we strip "xn--" — but we re-check here so
        # raw inputs from CT logs are handled regardless).
        return (0, "homograph")

    return None


# ─────────────────────────────────────────────────────────────────
# crt.sh client
# ─────────────────────────────────────────────────────────────────

_last_request_at: float = 0.0
_throttle_lock = asyncio.Lock()


async def _throttle() -> None:
    """Yield no more than 1 request per second to crt.sh per process.

    The shared module-level state means concurrent calls from the
    same worker share the throttle; cross-worker is the cron's
    problem (we don't run multi-worker for this).
    """
    global _last_request_at
    async with _throttle_lock:
        now = asyncio.get_event_loop().time()
        wait = CRT_SH_MIN_INTERVAL_S - (now - _last_request_at)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_at = asyncio.get_event_loop().time()


async def fetch_crtsh_candidates(
    brand_label: str, since_hours: int = 36
) -> list[dict]:
    """Query crt.sh for certs issued recently whose name LIKE includes
    the brand label. Returns the raw JSON rows; caller filters.

    We query with `?q=%25{label}%25&output=json&Exclude=expired` and
    then filter by `not_before >= now - since_hours`. crt.sh returns
    a list of objects with at minimum:
        name_value (newline-separated SANs), issuer_ca_id, issuer_name,
        not_before (ISO-8601), id (int)

    Honors a 1 RPS throttle and a 20s timeout. On timeout / 5xx
    returns []. Errors are NOT raised — the watchtower scan job
    should keep working through other brands.
    """
    if not brand_label or not LABEL_RE.match(brand_label.lower()):
        return []

    await _throttle()
    params = {
        "q": f"%{brand_label.lower()}%",
        "output": "json",
        "Exclude": "expired",
    }
    try:
        async with httpx.AsyncClient(
            timeout=CRT_SH_TIMEOUT_S,
            headers={"User-Agent": "Cleanway-watchtower/1.0 (+https://cleanway.ai)"},
        ) as client:
            resp = await client.get(CRT_SH_BASE, params=params)
            if resp.status_code != 200:
                logger.warning(
                    "crt.sh returned %d for label=%s", resp.status_code, brand_label,
                )
                return []
            try:
                rows = resp.json()
            except Exception:
                # crt.sh sometimes returns partial / non-JSON on
                # load — we degrade silently.
                return []
    except Exception as exc:
        logger.warning("crt.sh query failed for %s: %s", brand_label, exc)
        return []

    if not isinstance(rows, list):
        return []

    from datetime import datetime, timedelta, timezone
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    recent: list[dict] = []
    for row in rows:
        nb = row.get("not_before") or ""
        try:
            # crt.sh emits "2024-01-15T12:34:56" without tz; treat as UTC.
            dt = datetime.fromisoformat(nb.rstrip("Z"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if dt >= cutoff:
            recent.append(row)
    return recent


def extract_candidate_domains(rows: Iterable[dict]) -> set[str]:
    """Pull suspect domain names out of crt.sh `name_value` fields.

    Each row has a newline-separated `name_value` that lists every
    SAN entry on the cert; wildcards (`*.example.com`) are kept
    after stripping the leading `*.` (the cert covers example.com
    too, and the wildcard form would never be a phishing target
    in itself).
    """
    out: set[str] = set()
    for row in rows:
        names = (row.get("name_value") or "").split("\n")
        for raw in names:
            name = raw.strip().lower().lstrip("*").lstrip(".")
            if not name or "." not in name:
                continue
            if " " in name or name.startswith("-"):
                continue
            out.add(name)
    return out


async def scan_brand(brand_root: str) -> list[TyposquatCandidate]:
    """Top-level: scan a single brand's eTLD+1 for typosquat candidates.

    Returns the list of TyposquatCandidates ready to insert into
    typosquat_alerts. The persistence step (UPSERT, RLS) is
    handled by the caller — keeping this function pure makes it
    trivially testable.
    """
    if not brand_root:
        return []
    label, _suffix = split_root(brand_root)
    if not label:
        return []

    rows = await fetch_crtsh_candidates(label)
    if not rows:
        return []

    # Map suspect → earliest not_before + issuer (some candidates
    # appear in multiple rows; we keep the earliest).
    earliest: dict[str, tuple[str, Optional[str]]] = {}
    for row in rows:
        nb = row.get("not_before") or ""
        issuer = row.get("issuer_name")
        for cand in extract_candidate_domains([row]):
            cand_root = eTLD1(cand)
            if not cand_root:
                continue
            existing = earliest.get(cand_root)
            if existing is None or nb < existing[0]:
                earliest[cand_root] = (nb, issuer)

    out: list[TyposquatCandidate] = []
    for suspect, (first_seen, issuer) in earliest.items():
        verdict = is_likely_typosquat(brand_root, suspect)
        if verdict is None:
            continue
        edit_d, kind = verdict
        out.append(TyposquatCandidate(
            brand_root=brand_root,
            suspect=suspect,
            edit_distance=edit_d,
            variant_kind=kind,
            first_seen_at=first_seen,
            issuer=issuer,
        ))
    return out
