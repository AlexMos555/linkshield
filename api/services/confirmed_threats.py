"""Hosts our own checks confirmed as phishing or malware through Google Safe
Browsing — kept so the blocklist publisher can ship them to every phone.

OFF unless PUBLISH_CONFIRMED_THREATS is set (see `enabled`), on the API and
on the refresh workflow alike. Publishing these hosts redistributes Google's
verdicts to every phone, and the feed-licence audit of 2026-09-21 lists
Google Safe Browsing among the sources whose terms bar commercial
redistribution. Switching it on is a founder/legal decision, never a code
default (docs/runbooks/monitoring.md, "Server-confirmed hosts").

Why it exists: the phone's blocklist is built only from bulk public feeds, and
those miss most fresh phishing (measured 2026-09-25: the list covered 11% of
an independent 30-day TweetFeed sample). The analyzer behind /check already
asks Google Safe Browsing about every host a person checks, and GSB caught
both fresh phishing hosts in that test the list did not. That knowledge died
in a 24-hour result cache. With the switch on, a host whose DANGEROUS verdict
rests on a Safe Browsing phishing/malware listing is recorded, and
scripts/refresh_dangerous_domains.py ships it to every phone through the same
false-positive guards as a feed host.

What never qualifies:
  * heuristic verdicts (young domain, missing headers, lookalike name, the LLM
    judge) — a guess must not become a DNS block on every phone;
  * any source outside INTEL_SIGNALS (see there for why each is out);
  * a Safe Browsing listing for unwanted software or a harmful app only
    (RECORDED_GSB_THREAT_TYPES);
  * a host that is not the site's own name (`is_recordable_host`): a
    per-recipient phishing host such as ivan-petrov-mail-ru.evil.xyz protects
    no one else and would put a person's name into every phone's list.

Storage — one Redis sorted set, CONFIRMED_KEY:
  member = the checked host (lowercase, no trailing dot),
  score  = unix time Safe Browsing last confirmed it through one of our checks.
Capped at CONFIRMED_MAX members (oldest dropped first). No user, IP or URL is
stored. Every write also deletes entries past the window plus the grace
period, and the publisher prunes after each publish, so an entry is deleted
EXPIRED_GRACE_SECONDS after it expires as long as either keeps running; the
key itself expires KEY_TTL_SECONDS after the last write.

A confirmation is never re-checked: if Google delists a host sooner, it stays
on the phones' list until the window runs out.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Mapping, Optional

logger = logging.getLogger("cleanway.confirmed_threats")

CONFIRMED_KEY = "dangerous_domains:confirmed"
ENABLE_ENV = "PUBLISH_CONFIRMED_THREATS"

# The only signal trusted to put a host on every phone. Each other source is
# out for a stated reason:
#   phishtank_hit       PhishTank is our held-out benchmark; ingesting it
#                       would make every coverage figure circular.
#   urlhaus_hit         the /v1/host/ lookup answers for any host that EVER
#                       had a malware URL, offline ones on cleaned sites too
#                       (the publisher's own URLhaus feed is csv_online).
#   threatfox_hit       search_ioc without exact_match is a wildcard search:
#                       "bank.ru" also matches "evilbank.ru".
#   malware_bazaar_hit  get_taginfo searches free-text tags any uploader
#                       sets — not a host listing at all.
#   feodo_hit           botnet C2 IP addresses; DNS blocking cannot use them.
#   PhishStats (substring match), Spamhaus DBL and SURBL (spam listings),
#   AlienVault OTX (pulse counts — our measured false-positive source),
#   IPQualityScore (a score).
# The abuse.ch sources are also excluded by their 2025-11-04 terms (§7.3, no
# derivative works) — the same licence audit that gates this whole module.
INTEL_SIGNALS = ("safe_browsing_hit",)

# Phishing and malware. UNWANTED_SOFTWARE and POTENTIALLY_HARMFUL_APPLICATION
# also flag download portals that bundle adware: a warning for the person who
# checked, not a DNS block in every app on every phone.
RECORDED_GSB_THREAT_TYPES = frozenset({"SOCIAL_ENGINEERING", "MALWARE"})

# A host one label above the site's own name is recorded only when that label
# is a short plain word (allegro.pl-lokalna-oferta.sbs, login.evil.xyz). An
# email address, a full name or an ID needs digits, a separator or length.
_WORD_LABEL = re.compile(r"[a-z]{1,12}")

# A confirmation keeps a host on the list for a week after the last one.
# Then it drops out; refresh_dangerous_domains counts an expired
# confirmation as present, so retention never holds it for another window.
CONFIRMED_WINDOW_SECONDS = 7 * 86_400
# ~6 bytes per name on every phone; 20k is ~120 KB of artifact at worst.
CONFIRMED_MAX = 20_000
# Entries past the window are kept this much longer so the publisher can
# still tell "expired confirmation" from "left a feed" if a publish fails.
EXPIRED_GRACE_SECONDS = 2 * 86_400
KEY_TTL_SECONDS = CONFIRMED_WINDOW_SECONDS + EXPIRED_GRACE_SECONDS + 86_400
# The analyzer's answer must never wait on this bookkeeping.
RECORD_TIMEOUT_S = 0.25


def enabled(environ: Optional[Mapping[str, str]] = None) -> bool:
    """True only when PUBLISH_CONFIRMED_THREATS is set to 1/true/yes/on."""
    raw = (os.environ if environ is None else environ).get(ENABLE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def intel_sources(signals: Mapping) -> tuple:
    """The trusted threat-intel sources that flagged this host."""
    return tuple(name for name in INTEL_SIGNALS if signals.get(name))


def should_record(level: str, signals: Mapping) -> bool:
    """True only for a dangerous verdict backed by trusted threat intel."""
    return level == "dangerous" and bool(intel_sources(signals))


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def site_name(host: str) -> str:
    """The name a site owner registered: a tenant's name on a hosting
    platform or public suffix (paymentsecurelink.vercel.app), else the
    registrable domain (evil.xyz, shop.com.tr)."""
    from api.services.doh_gateway import _registrable_domain
    from api.services.scoring import HOSTING_PLATFORMS, PUBLIC_SUFFIXES_IN_TOP

    parts = host.split(".")
    for k in range(len(parts) - 1, 1, -1):  # the longest shared suffix wins
        suffix = ".".join(parts[-k:])
        if suffix in PUBLIC_SUFFIXES_IN_TOP or suffix in HOSTING_PLATFORMS:
            return ".".join(parts[-(k + 1):])
    return _registrable_domain(host)


def is_recordable_host(host: str) -> bool:
    """The site's own name, its www. host, or one short plain word above it."""
    site = site_name(host)
    if host == site:
        return True
    label = host[: -len(site) - 1] if host.endswith("." + site) else ""
    return label == "www" or bool(_WORD_LABEL.fullmatch(label))


async def _safe_browsing_types(host: str) -> frozenset:
    """Threat types Safe Browsing reports for `host`. Served from the Redis
    cache of the lookup the analyzer just made — not a second call to Google
    in the normal case."""
    from api.services.safe_browsing import get_client

    result = await get_client().check(host)
    return frozenset(m.threat_type for m in result.matches)


def _forget_before(now: float) -> str:
    """ZREMRANGEBYSCORE upper bound: strictly older than window + grace."""
    return f"({int(now) - CONFIRMED_WINDOW_SECONDS - EXPIRED_GRACE_SECONDS}"


async def record(r, host: str, now: float) -> None:
    """Upsert the host with `now`, forget expired entries, trim to the cap,
    refresh the key TTL — in one MULTI/EXEC."""
    pipe = r.pipeline(transaction=True)
    pipe.zadd(CONFIRMED_KEY, {host: int(now)})
    pipe.zremrangebyscore(CONFIRMED_KEY, "-inf", _forget_before(now))
    pipe.zremrangebyrank(CONFIRMED_KEY, 0, -(CONFIRMED_MAX + 1))
    pipe.expire(CONFIRMED_KEY, KEY_TTL_SECONDS)
    await pipe.execute()


async def _confirm_and_record(host: str, name: str, now: float) -> bool:
    if not await _safe_browsing_types(host) & RECORDED_GSB_THREAT_TYPES:
        return False
    from api.services.cache import get_redis
    await record(await get_redis(), name, now)
    return True


async def record_if_confirmed(host: str, level: str, signals: Mapping,
                              now: Optional[float] = None) -> bool:
    """Record `host` when publishing is switched on and its verdict and name
    qualify. Never raises and never delays the caller by more than
    RECORD_TIMEOUT_S. True if recorded."""
    name = normalize_host(host)
    if not name or not enabled() or not should_record(level, signals) or not is_recordable_host(name):
        return False
    try:
        when = time.time() if now is None else now
        recorded = await asyncio.wait_for(_confirm_and_record(host, name, when), RECORD_TIMEOUT_S)
    except Exception:  # noqa: BLE001
        logger.warning("confirmed threat not recorded (safe browsing or redis unavailable)", exc_info=True)
        return False
    if recorded:
        logger.info("confirmed_threat_recorded", extra={"sources": list(intel_sources(signals))})
    return recorded


async def load(r) -> dict[str, float]:
    """The whole set — small by construction (capped)."""
    rows = await r.zrange(CONFIRMED_KEY, 0, -1, withscores=True)
    return {str(name): float(score) for name, score in rows}


def split(entries: Mapping[str, float], now: float,
          window_seconds: int = CONFIRMED_WINDOW_SECONDS) -> tuple[set, set]:
    """(active, expired): confirmed inside the window vs. before it."""
    cutoff = now - window_seconds
    active = {name for name, seen in entries.items() if seen >= cutoff}
    return active, set(entries) - active


async def prune(r, now: float) -> None:
    """Forget confirmations older than the window plus the grace period."""
    await r.zremrangebyscore(CONFIRMED_KEY, "-inf", _forget_before(now))
