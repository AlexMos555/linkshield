"""Russian-brand lookalikes out of new certificates — with the scorer's rules.

The names come from Certificate Transparency (api/services/ct_tiles.py);
whether a name imitates a Russian brand is decided by the SAME functions the
/check verdict uses — _check_typosquatting_v2, _check_homograph,
_check_brand_under_open_zone in api/services/scoring.py, over
data/typosquat_targets_ru.json and, once PR #64 lands, its Russian lure
vocabulary (api/services/ru_lures.py). There is no second list of brands or
rules here: a false positive fixed in the scorer is fixed in the generator,
and a lure word added there is matched here on the next run.

Why the Watchtower did not cover this: it scans the brands USERS add to a
watchlist (a per-account product feature, Supabase `brand_watchlist`), via a
crt.sh LIKE query per brand, with its own 30-TLD suffix table and an edit
distance of two over any label — the rules PR #61/#62 replaced in the scorer
because they flagged ako.ru and telegraph.co.uk. Nobody added Sber or
Gosuslugi to a watchlist, and the alerts it writes reach one user's screen,
never the phone list. Extending it would mean a second copy of the brand
data and the name rules; this module reuses the scorer's instead and feeds
the list through the publisher's own guards.

A match is a CANDIDATE, never a block. It is published only when (a) the
publisher's false-positive gates pass (scripts/refresh_dangerous_domains.py:
top-100k and Tranco veto, brand-owned exclusions, shared suffixes, zones —
every own-source host goes through build_blockset like a feed host, so the
gates are not re-implemented here) and (b) at least one INDEPENDENT signal
says the site is live phishing, not just a name:

  listed        a feed we ship already lists the host (then there is
                nothing to add — counted, for the measurement)
  blocklist /   the analyzer's verdict_basis: a Safe Browsing / PhishTank /
  threat_intel  URLhaus … hit, or our own list
  credential_form
                the site serves a password form that names the brand
                (fetched from the server, through the analyzer's SSRF
                guard, 256 KB cap, three redirect hops at most)

Everything runs behind LOOKALIKE_GENERATOR_ENABLED (api/services/own_sources.py).
"""
from __future__ import annotations

import encodings.idna
import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from types import MappingProxyType
from typing import Iterable, Mapping, Optional

import httpx

from api.services import ru_brands
from api.services.scoring import (
    RU_BRAND_GROUPS,
    _BRAND_LEGIT_DOMAINS,
    _BRAND_OFFICIAL_DOMAINS,
    _check_brand_under_open_zone,
    _check_homograph,
    _check_typosquatting_v2,
    _extract_base_domain,
    _lookalike_zone_name,
    _ru_registrable_domain,
    is_trusted_top_domain,
    registrable_domain,
)
from api.services.site_probes import _REDIRECT_CODES, _hop_is_safe, wire_host

logger = logging.getLogger("cleanway.lookalike_generator")

SIGNAL_LISTED = "listed"
SIGNAL_BLOCKLIST = "blocklist"
SIGNAL_THREAT_INTEL = "threat_intel"
SIGNAL_CREDENTIAL_FORM = "credential_form"
# The analyzer bases that count as an independent signal: evidence a client
# may block on (verdict_basis.BLOCKING_BASES), never a heuristic.
VERDICT_SIGNALS = MappingProxyType({"blocklist": SIGNAL_BLOCKLIST, "threat_intel": SIGNAL_THREAT_INTEL})

PAGE_MAX_BYTES = 256 * 1024
PAGE_TIMEOUT_S = 5.0
PAGE_MAX_HOPS = 3
_PASSWORD_INPUT = re.compile(r"<input[^>]*type\s*=\s*['\"]?password", re.IGNORECASE)
_LABEL_OK = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

# Brand group by every domain the file ties to it, and by every name.
_GROUP_BY_DOMAIN: Mapping[str, ru_brands.BrandGroup] = MappingProxyType({
    d: g for g in RU_BRAND_GROUPS for d in [*g.names.values(), *g.official]
})
_GROUP_BY_NAME: Mapping[str, ru_brands.BrandGroup] = MappingProxyType({
    n: g for g in RU_BRAND_GROUPS for n in g.names
})
_GROUPS: Mapping[str, ru_brands.BrandGroup] = MappingProxyType({g.key: g for g in RU_BRAND_GROUPS})


@dataclass(frozen=True)
class Match:
    host: str      # punycode wire form, lowercase
    brand: str     # brand group key (sber, gosuslugi …)
    imitates: str  # the brand's domain the name is told to imitate
    method: str    # the scorer's own wording: "character substitution", "TLD confusion" …


# ── Names ──

def normalise(name: str) -> Optional[str]:
    """A certificate name as a DNS host: wildcard prefix dropped (the cert
    covers the base too), lowercase, trailing dot off, IDN labels in
    punycode (the scorer's input form). None for anything that is not a
    host name (an IP, an email, a name with spaces)."""
    raw = (name or "").strip().lower().rstrip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or " " in raw or "@" in raw or "/" in raw or len(raw) > 253:
        return None
    try:
        host = ".".join(
            label if label.isascii() else encodings.idna.ToASCII(label).decode("ascii")
            for label in raw.split(".")
        )
    except (UnicodeError, ValueError):
        return None
    labels = host.split(".")
    if len(labels) < 2 or labels[-1].isdigit() or len(labels[-1]) < 2:
        return None
    if not all(_LABEL_OK.match(label) for label in labels):
        return None
    return host


def skip_reason(host: str) -> Optional[str]:
    """Why `host` is never a candidate: a brand's own domain (or a verified
    same-shaped site of another owner), or a popular site the publisher
    would veto anyway. Saves the analyzer's budget; the publisher's gates
    judge again at publish time."""
    reg = registrable_domain(host)
    forms = ru_brands.idn_forms(reg) | ru_brands.idn_forms(host)
    if forms & _BRAND_LEGIT_DOMAINS:
        return "brand_owned"
    if is_trusted_top_domain(host):
        return "trusted_top"
    return None


def _russian(legit_domain: Optional[str]) -> bool:
    return bool(legit_domain) and legit_domain in _BRAND_OFFICIAL_DOMAINS


def _group_key(legit_domain: str) -> str:
    group = _GROUP_BY_DOMAIN.get(legit_domain)
    return group.key if group else legit_domain.split(".")[0]


def comparison_base(host: str) -> str:
    """The name _check_typosquatting_v2 actually compares for `host` — the
    registrable name under a Russian public suffix, the name registered
    under ru.com / ru.net, else the last two labels — derived with the
    scorer's own helpers. The rule's answer depends on nothing else, so one
    answer serves www.x.ru, mail.x.ru and x.ru (the certificates of one
    site carry all three)."""
    return _lookalike_zone_name(host) or _ru_registrable_domain(host) or _extract_base_domain(host)


@lru_cache(maxsize=262_144)
def _typosquat_of(base: str) -> Optional[tuple[str, str]]:
    return _check_typosquatting_v2(base)


def match(host: str) -> Optional[Match]:
    """How `host` imitates a Russian brand, by the scorer's rules, or None.
    Global brands (paypal, apple) are not this generator's business: their
    phishing reaches the feeds we ship."""
    imitated = _check_homograph(host)
    if _russian(imitated):
        return Match(host, _group_key(imitated), imitated, "homograph")
    typo = _typosquat_of(comparison_base(host))
    if typo and _russian(typo[0]):
        return Match(host, _group_key(typo[0]), typo[0], typo[1])
    zone_brand = _check_brand_under_open_zone(host)
    if zone_brand:
        group = _GROUP_BY_NAME.get(zone_brand)
        imitates = group.names[zone_brand] if group else f"{zone_brand}.ru"
        return Match(host, group.key if group else zone_brand, imitates, "brand under open zone")
    return None


def _match_chunk(hosts: list[str]) -> list[Optional[Match]]:
    return [match(h) if skip_reason(h) is None else None for h in hosts]


def match_many(hosts: Iterable[str], workers: Optional[int] = None, chunk: int = 2_000) -> dict[str, Match]:
    """`match` over many hosts on every CPU core: the scorer compares each
    name with every brand (SequenceMatcher per pair, ~5 ms a host), and an
    hour of Let's Encrypt is ~150k distinct hosts after the pre-gates. Each
    worker keeps its own memo of comparison bases. Hosts a pre-gate skips
    are never compared."""
    rows = sorted(set(hosts))
    if not rows:
        return {}
    chunks = [rows[i:i + chunk] for i in range(0, len(rows), chunk)]
    count = workers or min(len(chunks), os.cpu_count() or 1)
    if count <= 1:
        results = [_match_chunk(c) for c in chunks]
    else:
        with ProcessPoolExecutor(max_workers=count) as pool:
            results = list(pool.map(_match_chunk, chunks))
    return {m.host: m for part in results for m in part if m is not None}


# ── Independent signals ──

def signal_from_verdict(level: Optional[str], verdict_basis: Optional[str]) -> Optional[str]:
    """The analyzer's verdict as an independent signal: only a DANGEROUS
    verdict resting on a blocklist or threat intel — never a heuristic, never
    the ML model, never the LLM judge, which all judge the name as we do."""
    if level != "dangerous":
        return None
    return VERDICT_SIGNALS.get(verdict_basis or "")


def brand_tokens(brand: str) -> frozenset[str]:
    """Words a page impersonating `brand` would carry: the brand's names in
    every script the target file lists, three letters or longer."""
    group = _GROUPS.get(brand)
    names = set(group.names) if group else {brand}
    return frozenset(n for n in names if len(n) >= 3)


def credential_form_impersonates(html: Optional[str], brand: str) -> bool:
    """The page asks for a password AND names the brand. A password form
    alone is any login page; the brand's name alone is any news article."""
    if not html or not _PASSWORD_INPUT.search(html):
        return False
    text = html.lower()
    return any(token in text for token in brand_tokens(brand))


async def fetch_page(host: str, http: httpx.AsyncClient) -> Optional[str]:
    """GET https://<host>/ from the server, the analyzer's way: the host and
    every redirect hop resolved and checked against the SSRF guard before
    being contacted, PAGE_MAX_HOPS hops, PAGE_MAX_BYTES of body, HTML only.
    None when anything stops it; never raises."""
    if not await _hop_is_safe(host):
        return None
    url = f"https://{host}/"
    for _hop in range(PAGE_MAX_HOPS + 1):
        try:
            async with http.stream("GET", url, timeout=PAGE_TIMEOUT_S) as resp:
                location = resp.headers.get("location")
                if resp.status_code in _REDIRECT_CODES and location:
                    target = httpx.URL(url).join(location)
                    next_host = wire_host(target)
                    if target.scheme not in ("http", "https") or not await _hop_is_safe(next_host):
                        return None
                    url = str(target)
                    continue
                if resp.status_code != 200:
                    return None
                content_type = resp.headers.get("content-type", "")
                if "html" not in content_type and "text" not in content_type:
                    return None
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    chunks.append(chunk)
                    if size >= PAGE_MAX_BYTES:
                        break
                return b"".join(chunks)[:PAGE_MAX_BYTES].decode(resp.encoding or "utf-8", "replace")
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("page fetch failed", extra={"host": host, "error": type(exc).__name__})
            return None
    return None


# A phone's browser, named: phishing kits serve their page to mobile browsers
# and a blank one to anything that looks like a scanner.
PAGE_USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Mobile) Cleanway-check/1.0 (+https://cleanway.ai)"


def page_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=PAGE_TIMEOUT_S, follow_redirects=False,
                             headers={"User-Agent": PAGE_USER_AGENT})


def signals(match: Match, *, listed: Optional[str], level: Optional[str], verdict_basis: Optional[str],
            page_html: Optional[str]) -> tuple[str, ...]:
    """Every independent signal present, in a fixed order."""
    out: list[str] = []
    if listed:
        out.append(SIGNAL_LISTED)
    verdict = signal_from_verdict(level, verdict_basis)
    if verdict:
        out.append(verdict)
    if credential_form_impersonates(page_html, match.brand):
        out.append(SIGNAL_CREDENTIAL_FORM)
    return tuple(out)


def publishable(found: tuple[str, ...]) -> bool:
    """One independent signal is enough; the publisher's gates still apply."""
    return bool(found)
