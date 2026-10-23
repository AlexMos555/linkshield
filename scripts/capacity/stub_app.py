"""Capacity test only (docs/runbooks/capacity.md) — never deployed.

api.main:app with every outbound network call of the analyzer replaced by
a sleep + a canned "benign site" answer. Redis lookups (blocklist, tranco,
watchtower, rate limits, caches), scoring, ML and serialization stay real.

Latency per stubbed source ~ uniform(STUB_MIN_MS, STUB_MAX_MS).
"""
import asyncio
import os
import random

from api.main import app  # noqa: F401  (uvicorn imports capacity_app:app)
from api.services import analyzer

LO = float(os.environ.get("STUB_MIN_MS", "40")) / 1000
HI = float(os.environ.get("STUB_MAX_MS", "400")) / 1000


async def _nap():
    await asyncio.sleep(random.uniform(LO, HI))


def _ret(value):
    async def fn(domain, *a, **k):
        await _nap()
        return value() if callable(value) else value
    return fn


async def _exists(domain):
    await asyncio.sleep(0.02)
    return True


async def _resolution(domain):
    await asyncio.sleep(0.02)


for name in ("check_safe_browsing", "check_phishtank", "check_urlhaus", "check_phishstats",
             "check_threatfox", "check_spamhaus_dbl", "check_surbl", "check_malware_bazaar",
             "check_feodo_tracker"):
    setattr(analyzer, name, _ret(False))
analyzer.check_alienvault_otx = _ret(lambda: {"pulse_count": 0, "hit": False})
analyzer.check_ipqualityscore = _ret(lambda: {"risk_score": 0, "phishing": False, "hit": False})
analyzer.check_favicon_brand_clone = _ret(lambda: {"cloned": False, "brand": None, "weight": 0, "detail": ""})
analyzer.check_whois_age = _ret(lambda: {"age_days": 2400, "registered": "2020-01-01T00:00:00Z", "registrar": "Stub"})
analyzer.check_ssl = _ret(lambda: {"reachable": True, "has_ssl": True, "issuer": "Let's Encrypt",
                                   "is_free_ssl": True, "cert_age_days": 30})
analyzer.check_security_headers = _ret(lambda: {"reachable": True, "present": ["strict-transport-security"],
                                                "missing": ["content-security-policy"]})
analyzer.check_dns = _ret(lambda: {"a_count": 2, "ttl": 300, "ns_count": 2, "has_mx": True})
analyzer.check_redirect_chain = _ret(lambda: {"reachable": True, "count": 1, "cross_domain": False,
                                              "domains_visited": [], "final_url": None})
analyzer.check_domain_exists = _exists
analyzer.validate_domain_resolution = _resolution

# Cloudflare Families comparison (every public-check response): to the stub
# (scripts/capacity/stub_upstream.py answers application/dns-json too).
# STUB_UPSTREAM: where the stub listens (https://127.0.0.1:8443 outside Docker).
from api.services import competitor_verdicts  # noqa: E402
_UPSTREAM = os.environ.get("STUB_UPSTREAM", "https://upstream:8443")
competitor_verdicts.CLOUDFLARE_FAMILIES_URL = f"{_UPSTREAM}/dns-json"
competitor_verdicts.CLOUDFLARE_UNFILTERED_URL = f"{_UPSTREAM}/dns-json"
