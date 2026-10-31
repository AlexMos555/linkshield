"""
Scoring Engine 3.0 — Production-grade phishing detection.

30+ signals across 6 categories:
  1. Blocklist hits (Safe Browsing, PhishTank, URLhaus)
  2. Allowlist checks (top 100K popular domains: Majestic Million + Chrome UX Report)
  3. URL lexical analysis (length, entropy, special chars, encoding)
  4. Brand impersonation (typosquatting, homograph, subdomain abuse, combosquatting)
  5. DNS/WHOIS enrichment (domain age, SSL, security headers)
  6. TLD & structural analysis (risky TLDs, depth, keywords)

Score 0-100. Thresholds: 0-20 safe / 21-50 caution / 51-100 dangerous.

Architecture: Layered pipeline.
  Layer 1: Blocklist check → instant block
  Layer 2: Allowlist check → instant safe
  Layer 3: Feature extraction + rule scoring → 0-100
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections import Counter
from difflib import SequenceMatcher
from types import MappingProxyType
from typing import AbstractSet, Mapping, NamedTuple, Optional

from api.models.schemas import RiskLevel, DomainReason, ConfidenceLevel
from api.services import ru_brands, ru_lures
from api.services.hosting_platforms import dynamic_dns_suffix_of as _dynamic_dns_suffix_of
from api.services.hosting_platforms import is_shared_platform_site, tenant_suffix_of
from api.services.hosting_platforms import USER_CONTENT_HOSTS, is_user_content_service
from api.services.hosting_platforms import OPERATOR_SUFFIXES, is_operator_zone_name
from api.services import dead_top_names as _dead
from api.services import public_suffix as _public_suffix
from api.services.public_suffix import CCTLD_OPEN_ZONES, ascii_name, heuristic_registrable_domain
from api.services.public_suffix import is_icann_rule, is_ip_literal
from api.services.public_suffix import registrable_domain as _psl_registrable_domain

logger = logging.getLogger("cleanway.scoring")

# ═══════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def _load_json_set(filename: str) -> set[str]:
    """Load a JSON list/dict file as a set of domain strings."""
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return set(d.lower() for d in data)
            elif isinstance(data, dict):
                return set(d.lower() for d in data.keys())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Failed to load %s: %s — using built-in fallback", filename, e)
    return set()


def _load_json_dict(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ── Load the top domains (100K from file, 50 builtin fallback) ──
#
# data/top_100k.json and data/top_10k.json are the first 100,000 / 10,000
# names of Cleanway's popularity ranking: the Majestic Million (CC BY 3.0)
# and the Chrome UX Report top origins (CC BY 4.0), merged by
# scripts/build_top_domains.py (provenance: data/top_domains_sources.json).
# They were Tranco's until 2026-10-23 — no licence of its own, and its
# default list averages Cloudflare Radar, CC BY-NC 4.0.

TOP_100K: set[str] = _load_json_set("top_100k.json")
TOP_10K_RANKS: dict = _load_json_dict("top_10k.json")

_BUILTIN_TOP_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
    "apple.com", "microsoft.com", "github.com", "netflix.com", "whatsapp.com",
    "tiktok.com", "yahoo.com", "bing.com", "zoom.us", "paypal.com",
    "stripe.com", "shopify.com", "wordpress.com", "medium.com", "notion.so",
    "slack.com", "discord.com", "telegram.org", "spotify.com", "twitch.tv",
    "stackoverflow.com", "cloudflare.com", "dropbox.com", "adobe.com",
    "salesforce.com", "oracle.com", "samsung.com", "ebay.com", "walmart.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "usps.com",
    "ups.com", "fedex.com", "dhl.com", "citi.com",
}

TOP_DOMAINS: set[str] = TOP_100K if TOP_100K else _BUILTIN_TOP_DOMAINS

_domains_source = "top_100k" if TOP_100K else "builtin_50"
logger.info("Loaded %d top domains from %s", len(TOP_DOMAINS), _domains_source)

# ── Public suffixes that are ALSO top domains ──
#
# The top 100k ranks `us.org`, `github.io`, `blogspot.com`, `azurewebsites.net`,
# `bounceme.net` … — and every one of them is a public suffix (Mozilla PSL):
# anyone can register a name under it. Trusting "base domain in
# TOP_DOMAINS" for a SUBDOMAIN of these was an instant-safe hole: the live
# phishing host gwcu.us.org came back "safe, 99%" from /public/check without
# ever reaching the analyzer (found 2026-08-18 through the Android shield).
# Every PSL rule whose last-two-labels base is in top_100k.json, multi-label
# ones like s3.amazonaws.com included — rebuilt with the list in the same run
# (scripts/build_top_domains.py, build_public_suffixes_in_top.shared_suffix_rules).
# See is_trusted_top_domain(). Plus the tenant zones of data/tenant_zones.json
# whatever their rank (trycloudflare.com, cloud.goog, s3.cloud.ru …): every
# reader of this set — _check_brand_on_hosting_tenant, the ML tenant features,
# the extension's copy — needs them, and a zone's tenants count nowhere in
# the licensed ranking, so its own name rarely ranks.
PUBLIC_SUFFIXES_IN_TOP: set[str] = _load_json_set("public_suffixes_in_top.json")
if not PUBLIC_SUFFIXES_IN_TOP:
    logger.warning("public_suffixes_in_top.json missing — falling back to the hand list only")

# ── Russian public suffixes (PSL) ──
#
# Every multi-label PSL rule under .ru / .su / .рф / .рус, in ASCII form: the
# reserved gov.ru / mil.ru / ac.ru / edu.ru / int.ru, the regional zones
# (spb.ru, msk.ru, nov.ru, adygeya.ru … and their .su twins), net.ru /
# org.ru / pp.ru, com.ru, ras.ru, the .рус city zones and a few hosting
# platforms. A name under one of them is registered AT that suffix, so it is
# the suffix plus one label — kvs.gov.spb.ru belongs to gov.spb.ru (the
# St Petersburg government), not to 'spb.ru'. Judging the last two labels
# instead compared 'spb' with brand names ("Impersonates ups.com"), read 'gov'
# as a fake TLD and counted three subdomain levels where there is one:
# 100/dangerous in production on 2026-09-27. public_suffixes_in_top.json
# cannot stand in: it only holds rules whose base is in the top list.
# Built by scripts/build_ru_public_suffixes.py. See registrable_domain().
# Wildcard rules ('*.hosting.myjino.ru': every b.hosting.myjino.ru is itself
# a suffix) are kept apart, by their base.
_RU_PSL_RULES: frozenset[str] = frozenset(_load_json_set("ru_public_suffixes.json"))
RU_PUBLIC_SUFFIXES: frozenset[str] = frozenset(r for r in _RU_PSL_RULES if not r.startswith("*."))
_RU_WILDCARD_SUFFIXES: frozenset[str] = frozenset(r[2:] for r in _RU_PSL_RULES if r.startswith("*."))
if not RU_PUBLIC_SUFFIXES:
    logger.warning("ru_public_suffixes.json missing — Russian regional zones read as registrable domains")

# Suffixes in RU_PUBLIC_SUFFIXES whose names are not anyone's pick: the
# cctld.ru reserved zones (gov.ru is for federal bodies, mil.ru for the
# military, edu.ru / ac.ru / int.ru the same way) and ras.ru, whose names the
# Russian Academy of Sciences assigns to its own institutes. Everything else
# — the FAITID regional zones (spb.ru, msk.ru, nov.ru …), com.ru, net.ru,
# org.ru, pp.ru, the .рус city zones, the hosting platforms — sells or hands
# out names like any registry: on 2026-09-27 whois.flexireg.net had
# com.msk.ru, ru.msk.ru and gov.msk.ru held by private persons and
# org.spb.ru free to buy.
_RU_RESTRICTED_ZONES = frozenset({"ac.ru", "edu.ru", "gov.ru", "int.ru", "mil.ru", "ras.ru"})
# Second-level labels that mark a restricted zone under any other country
# code (gov.uk, ac.uk, go.jp, gob.mx …) for the compound-suffix heuristic.
_RESTRICTED_ZONE_LABELS = frozenset({"gov", "mil", "edu", "ac", "int", "gob", "gouv", "govt", "go", "gv", "sch"})

# Government sites registered under an OPEN regional zone, named one by one:
# 'gov' is not reserved there (gov.msk.ru is a private person's name), so
# only a name checked individually is a government's. gov.spb.ru: the
# St Petersburg government (Wikidata Q1993715, official website P856), on
# its own name servers ns{,2,3}.gov.spb.ru. Its 2010-04-23 creation date
# proves nothing — com.spb.ru has the same one, FAITID's migration date.
# Shared by the fake-TLD rule here and the analyzer's government vouch.
REGIONAL_GOVERNMENT_DOMAINS: frozenset[str] = frozenset({"gov.spb.ru"})


def is_regional_government_domain(domain: str) -> bool:
    """True for a REGIONAL_GOVERNMENT_DOMAINS name or any host under it."""
    name = (domain or "").lower().strip(".")
    return any(name == g or name.endswith("." + g) for g in REGIONAL_GOVERNMENT_DOMAINS)

# A site on a free dynamic-DNS service (hosting_platforms.DYNAMIC_DNS_SUFFIXES).
# 15, measured 2026-10-15 against 10 and 20 on the fresh feeds and on the 21
# dynamic-DNS hosts in the Tranco top-1M (scoring rule 3.5b explains).
DYNAMIC_DNS_WEIGHT = 15

# ── Shared platforms: subdomains can be anyone's ──
# Kept in sync with refresh_dangerous_domains. The ML model's tenant feature
# (ml_features.shared_tenant) reads this list through _SCORER_SHARED_SUFFIXES.
HOSTING_PLATFORMS: frozenset[str] = frozenset({
    # CDN / Cloud hosting
    "pages.dev", "workers.dev", "r2.dev",                   # Cloudflare
    "netlify.app", "vercel.app", "onrender.com",             # Jamstack
    "herokuapp.com", "fly.dev", "railway.app", "deno.dev",   # PaaS
    "github.io", "gitlab.io", "bitbucket.io",                # Git hosting
    "web.app", "firebaseapp.com", "appspot.com",             # Google/Firebase
    "azurewebsites.net", "blob.core.windows.net",            # Azure
    "cloudfront.net", "s3.amazonaws.com", "amplifyapp.com",  # AWS
    # Website builders
    "blogspot.com", "wordpress.com", "wixsite.com", "wixstudio.com",
    "weebly.com", "squarespace.com", "webflow.io",
    "framer.app", "framer.website",                          # Framer
    "carrd.co", "notion.site", "super.site",
    "myshopify.com", "square.site", "bigcartel.com",
    "lovable.app", "replit.app", "glitch.me",
    # Free hosting
    "000webhostapp.com", "infinityfreeapp.com",
    "webcindario.com", "bravenet.com", "tripod.com",
    "atwebpages.com", "epizy.com", "rf.gd",
    "contaboserver.net", "hostinger.com",
    # Google Docs (special case)
    "docs.google.com", "forms.google.com", "sites.google.com",
})

# What a broken certificate (site_probes `certificate_problem`) means for the
# person — the browser warning they will see.
_CERTIFICATE_PROBLEM_TEXT: dict[str, str] = {
    "expired": "The site's security certificate has expired, so your browser will warn that the connection is not private",
    "not_yet_valid": "The site's security certificate is not valid yet, so your browser will warn that the connection is not private",
    "self_signed": "The site's security certificate was not issued by a trusted authority, so your browser will warn that the connection is not private",
    "wrong_host": "The site's security certificate belongs to a different address, so your browser will warn that the connection is not private",
    "": "The site's security certificate is invalid, so your browser will warn that the connection is not private",
}

# Google subdomains used for phishing: never auto-safe.
GOOGLE_ABUSED_SUBDOMAINS: frozenset[str] = frozenset({
    "docs.google.com", "forms.google.com", "sites.google.com",
    "drive.google.com", "translate.google.com",
})


# Every suffix the scorer itself knows to be shared; the curated
# data/hosting_platforms.json (tw1.ru, weeblysite.com, forms.yandex.ru …) is
# added on top by hosting_platforms.is_shared_platform_site().
_SCORER_SHARED_SUFFIXES: frozenset[str] = frozenset(PUBLIC_SUFFIXES_IN_TOP) | HOSTING_PLATFORMS


def _is_under_shared_suffix(domain: str) -> bool:
    """True when `domain` is a STRICT subdomain of a public suffix / hosting
    platform (a name someone else could have registered), or a page host
    that many users publish to at different paths (forms.yandex.ru)."""
    # Every proper suffix of length >= 2 labels is checked: evil.s3.amazonaws.com
    # must match s3.amazonaws.com; a.b.evil.us.org must match us.org.
    return is_shared_platform_site(domain, _SCORER_SHARED_SUFFIXES)


def is_hosting_platform_site(domain: str) -> bool:
    """A customer's site on a hosting / site-builder platform, or a page on a
    user-content host — from the curated lists only. Deliberately NOT the
    PSL-derived set: that also holds restricted registries such as gov.ru,
    where "anyone can publish here" would be a false statement."""
    return is_shared_platform_site((domain or "").lower().strip("."), HOSTING_PLATFORMS)


# Platforms that name their customers' hosts themselves (d37rwvwgfzyjhn.cloudfront.net,
# s-gke-usc1-nssi3-45.firebaseio.com): the label is a machine id, so the
# name-shape rules have nothing to judge in it. Measured 2026-10-15 on the
# Tranco top-1M: judging the label would have put 1,114 CloudFront and 112
# Firebase hosts at 'caution' by name alone, and no phishing in the
# evaluation sets was on either.
_PROVIDER_NAMED_SUFFIXES: frozenset[str] = frozenset({"cloudfront.net", "firebaseio.com"})


def _tenant_label(domain: str) -> Optional[str]:
    """The name a customer chose on a dynamic-DNS service (gedivan of
    gedivan.duckdns.org) or a curated hosting platform (HOSTING_PLATFORMS
    and data/hosting_platforms.json: polite-tulumba-704e1b of
    polite-tulumba-704e1b.netlify.app), else None — for registered names,
    their subdomains, the platforms' own hosts (www.duckdns.org) and the
    platforms that name hosts themselves (_PROVIDER_NAMED_SUFFIXES).

    Deliberately not the PSL-derived suffixes: those are mostly
    infrastructure (trafficmanager.net, elb.amazonaws.com) whose host names
    nobody picked."""
    d = (domain or "").lower().strip(".")
    suffix = _dynamic_dns_suffix_of(d)
    if not suffix:
        suffix = tenant_suffix_of(d, HOSTING_PLATFORMS)
        if not suffix or suffix in _PROVIDER_NAMED_SUFFIXES or registrable_domain(d).endswith("." + suffix):
            return None
    return d[: -(len(suffix) + 1)].split(".")[-1]


def top_domain_key(domain: str) -> Optional[str]:
    """The top-100k entry `domain` is, or is a subdomain of — the longest one
    — else None. Also the TOP_10K_RANKS key for its rank.

    The list is keyed by registrable domain (scripts/build_top_domains.py
    folds it with legacy_registrable_domain() and the PSL's ICANN section,
    and leaves public suffixes out), so the host's own ancestors are what to
    look up. The last two labels were looked up until 2026-10-27: 'co.uk' for
    www.amazon.co.uk, which no entry is, so 11,232 of the 100,000 entries
    (bbc.co.uk, yahoo.co.jp, amazon.com.br, www.nhs.uk, hdfc.bank.in) and
    every host under them never got the allowlist, and /public/check called
    www.amazon.co.uk 'caution 40'. Measured that day on the 100k entries and
    their www. hosts: 165 entries stay untrusted (URL shorteners, names under
    shared zones such as spb.ru; 163 until review put encurtador.com.br and
    go.gov.sg, both entries, on the shortener list), against 735 with
    registrable_domain() as the key (measured before that), and no host
    trusted before is lost — registrable_domain() would
    have lost www.web.de and www.id.me, whose 2-label names the
    compound-ccTLD heuristic read as suffixes (it was that heuristic until
    2026-10-28; the PSL lists neither). The longer keys it reaches
    (www.nhs.uk, hdfc.bank.in: 572 entries) all come from the PSL's ICANN
    section, so a name under one is that registrant's.

    A tombstoned entry (dead_top_names: it stopped existing, so anyone may
    have bought it since) is no key, and the search stops there: a shorter
    entry above it is not its owner either."""
    d = (domain or "").lower().strip(".")
    parts = d.split(".")
    # Two labels at least: a bare TLD is nobody's site.
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in TOP_DOMAINS:
            return None if candidate in _dead.DEAD_TOP_NAMES else candidate
    return None


# Shared platforms under a compound suffix whose tenants the allowlist must
# refuse, and which no other list names yet. Before 2026-10-27 the last-two-
# labels lookup never reached them; top_domain_key() does. Measured that day:
# sakura.ne.jp is a PSL private suffix that public_suffixes_in_top.json misses
# (scripts/build_public_suffixes_in_top.py keys rules by their last two
# labels, 'ne.jp'), 85 tenant names in the Chrome UX Report top origins and
# the feeds, 5 of them phishing; dothome.co.kr (15 phishing tenants in the
# feeds: conditions2auth., instagram.), isweb.co.kr (3) and woobi.co.kr
# ("무료 도메인 .woobi.co.kr", per-user records) are free hosting;
# lojaintegrada.com.br and lojavirtualnuvem.com.br (3 each), shop2000.com.tw
# and hostgator.com.br (https://<store code>.hostgator.com.br; a random label
# answers "sua loja não foi encontrada") are shop builders, webeden.co.uk a
# site builder (1); myzen.co.uk is Zen Internet's customer hosting
# (c<account>.myzen.co.uk), where burycatholicprepschool.myzen.co.uk, a
# Phishing.Database host, was "caution 30" in production. Checked and left
# out for lack of tenants in the feeds, crt.sh or a wildcard: blog.co.uk,
# freeserve.co.uk, free-online.co.uk, home.ne.jp. service.gov.uk and
# campaign.gov.uk, the other two PSL rules the builder misses, are GDS-run
# zones for government services and stay trusted.
#
# With these, the hosts and the shorteners below refused, 292 of the
# 1,057,017 feed hosts of 2026-10-24 become trusted and none loses it: 229
# subdomains of universities and government bodies (29 under ulm.ac.id),
# compromised sites of the kind already trusted under .edu and .com; 17
# Google ccTLD hosts; companies' own hosts the feeds list by mistake
# (www.tsb.co.uk, articulo.mercadolibre.com.mx); and pages users fill on real
# services (qr.paypay.ne.jp, pay.kiwify.com.br).
#
# Allowlist only: data/hosting_platforms.json and public_suffixes_in_top.json
# are ML model inputs (ml_features.shared_tenant), so these move there with
# the next retrain.
#
# And 000webhost.com, the one tenant zone of the blocklist publisher
# (scripts/blocklist_shared_zones.HOSTING_PLATFORMS) that the allowlist did
# not refuse: /public/check answers from the allowlist before the blocklist,
# so every zone the publisher lists tenants under must be refused here
# (tests/test_allowlist_blocklist_zones.py). It has no tenants today (a
# random label is NXDOMAIN, the site redirects to Hostinger, 2026-10-27).
_ALLOWLIST_TENANT_ZONES: frozenset[str] = frozenset({
    "sakura.ne.jp", "dothome.co.kr", "isweb.co.kr",
    "lojaintegrada.com.br", "lojavirtualnuvem.com.br", "shop2000.com.tw",
    "webeden.co.uk", "woobi.co.kr", "hostgator.com.br", "myzen.co.uk",
    "000webhost.com",
})

# Hosts under a newly reached compound-suffix entry that many people publish
# to by path: ISP personal pages (/~user/). Both were in the Phishing.Database
# feed of 2026-10-24 (/~dshelley/ed/zin.html, /~jhuntman@…/tt/squ.php). The
# same allowlist-only reason as above keeps them out of data/hosting_platforms.json
# user_content_hosts (ml/train_model.py filters its synthetic hosts with it).
_ALLOWLIST_PATH_SHARED_HOSTS: frozenset[str] = frozenset({
    "members.iinet.net.au", "homepage.powerup.com.au",
})

# The service label of each GOOGLE_ABUSED_SUBDOMAINS host ('translate'), so
# the guard holds under every Google domain, not only .com spellings. The
# literal list stays as it is: ml/train_model.py reads it.
_GOOGLE_ABUSED_SERVICES: frozenset[str] = frozenset(g.split(".")[0] for g in GOOGLE_ABUSED_SUBDOMAINS)


def _is_abused_google_service(domain: str, key: str) -> bool:
    """docs/forms/sites/drive/translate.google.<any Google entry>, or a name
    under one. The literal startswith() test matched google.com and
    google.com.* only; once the allowlist reached google.co.uk and
    google.co.jp (2026-10-27), translate.google.co.uk — whose /translate?u=
    proxies any site, a 302 to <site>.translate.goog — became instant-safe.
    translate.google.de was trusted before that already."""
    if domain in GOOGLE_ABUSED_SUBDOMAINS or any(domain.startswith(g) for g in GOOGLE_ABUSED_SUBDOMAINS):
        return True
    if key.split(".")[0] != "google" or not domain.endswith("." + key):
        return False
    return domain[: -(len(key) + 1)].split(".")[-1] in _GOOGLE_ABUSED_SERVICES


# Operators that run their user-content services on their country domains
# too: forms.yandex.com.tr is Yandex Forms, disk.yandex.kz, .by, .uz and
# .com.tr are Yandex Disk (checked live 2026-10-27), as script.google.co.uk
# would be Apps Script. data/hosting_platforms.json names only the .ru / .com
# spellings, so the others were instant-safe: the compound ones since the
# allowlist reached compound-suffix entries, yandex.kz and .by since always.
# Every top entry with one of these first labels is the operator's (202
# google.*; the 11 yandex.* on Yandex's name servers, but for yandex.ua,
# which has none). Not office/live/microsoft/github: office.co.uk is OFFICE, a
# UK shoe retailer, and live.net, microsoft.ai and github.blog run none of
# the services.
_CCTLD_SERVICE_OPERATORS: frozenset[str] = frozenset({"google", "yandex"})


def _user_content_services() -> Mapping[str, frozenset[str]]:
    """{operator: the labels left of its domain in USER_CONTENT_HOSTS}, for
    _CCTLD_SERVICE_OPERATORS: 'yandex' → disk, disk.360, forms; 'google' →
    docs, drive, forms, script, sites. From the curated list, so a service
    added there holds on every country domain of its operator."""
    out: dict[str, set[str]] = {}
    for host in USER_CONTENT_HOSTS:
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            if parts[i] in _CCTLD_SERVICE_OPERATORS:
                out.setdefault(parts[i], set()).add(".".join(parts[:i]))
                break
    return MappingProxyType({op: frozenset(labels) for op, labels in out.items()})


_USER_CONTENT_SERVICES: Mapping[str, frozenset[str]] = _user_content_services()


def _is_user_content_mirror(domain: str, key: str, exact: bool = False) -> bool:
    """`domain` is, or (unless `exact`) is a name under, a USER_CONTENT_HOSTS
    service on `key`, its top entry, when that entry is a domain of the
    service's operator: forms.yandex.com.tr, u.disk.yandex.kz,
    script.google.co.uk. Allowlist and fixed answer only — hosting_platforms
    stays as it is, ml/train_model.py reads is_user_content_host."""
    services = _USER_CONTENT_SERVICES.get(key.split(".")[0])
    if not services or not domain.endswith("." + key):
        return False
    left = domain[: -(len(key) + 1)]
    if exact:
        return left in services
    return any(left == s or left.endswith("." + s) for s in services)


def is_user_content_service_host(domain: str) -> bool:
    """The service host of a user-content platform, which the public check
    and the analyzer answer with the fixed "a real service; we cannot vouch
    for the page" (verdict_basis.user_content_result): a USER_CONTENT_HOSTS
    host (hosting_platforms.is_user_content_service), or the same service on
    another domain of its operator (disk.yandex.kz, docs.google.co.uk).
    Exactly that host: a page under it (u.disk.yandex.kz) is analysed."""
    d = (domain or "").lower().strip(".")
    if is_user_content_service(d):
        return True
    key = top_domain_key(d)
    return key is not None and _is_user_content_mirror(d, key, exact=True)


def _is_listed_shortener_host(domain: str) -> bool:
    """`domain` or a name it is under is in _URL_SHORTENERS, whatever its
    length. For the allowlist only: _is_url_shortener() reads the last two
    labels because it is the model's is_url_shortener feature, so it never
    matched a compound entry ('com.br' for encurtador.com.br) nor
    link.infini.fr ('infini.fr', trusted until 2026-10-27)."""
    parts = domain.split(".")
    return any(".".join(parts[i:]) in _URL_SHORTENERS for i in range(len(parts) - 1))


def is_trusted_top_domain(domain: str) -> bool:
    """The ONE rule for the instant-safe allowlist short-circuit.

    True only when the domain is a top domain (the top 100k) or a subdomain of
    one (top_domain_key) that is NOT a shared platform / public suffix / URL
    shortener / abused Google service / user-content service on any of its
    operator's domains (_is_user_content_mirror). Shared platforms include the curated
    data/hosting_platforms.json — Timeweb, Beget, SpaceWeb, Selectel, Weebly,
    WordPress staging, ScreenConnect, Yandex Forms/Disk … — whose customers'
    pages came back "safe, 99%" in production (report 2026-09-25 #7). Used by
    the public and authenticated /check routers and by the scorer's Layer 2,
    so none of them can disagree again.
    """
    d = (domain or "").lower().strip(".")
    if not d:
        return False
    key = top_domain_key(d)
    if key is None:
        return False
    if _is_url_shortener(key) or _is_listed_shortener_host(d):
        return False
    if _is_abused_google_service(d, key) or _is_user_content_mirror(d, key):
        return False
    if _is_under_shared_suffix(d) or tenant_suffix_of(d, _ALLOWLIST_TENANT_ZONES):
        return False
    if any(d == h or d.endswith("." + h) for h in _ALLOWLIST_PATH_SHARED_HOSTS):
        return False
    # A customer's name on a dynamic-DNS service in the top-100k (ns01.info).
    if _dynamic_dns_suffix_of(d):
        return False
    if _is_open_zone_above(d, key):
        return False
    return True


def _is_open_zone_above(domain: str, key: str) -> bool:
    """`key`, the top entry `domain` is under, is a public suffix above
    `domain`'s registrable name rather than its site, and nobody's government:
    go.ro, where RCS&RDS's customers pick their names (#37,317 of the top 1M),
    or.tv (no longer in DNS). The top list is folded without the ccTLD default
    (scripts/build_top_domains.py), so the zone stays an entry, and until
    2026-10-31 paypal-login.go.ro was "safe 0" without analysis. Kept: the
    zone itself and its www, and the restricted zones (gov.ro, sch.gr, gouv.bj,
    go.to), whose names their owner hands out.

    Not while the Public Suffix List or data/cctld_second_levels.json is
    missing: the fallback reading splits the one-owner zones (web.de, id.me)
    and has no open zones, so the rule would take the allowlist from
    login.web.de and give it back to paypal-login.go.ro."""
    if _public_suffix.LOAD_ERROR or not _public_suffix.CCTLD_NAMES:
        return False
    if domain in (key, "www." + key) or _is_restricted_zone(key):
        return False
    return registrable_domain(domain).endswith("." + key)


# ═══════════════════════════════════════════════════════════════
# BRAND TARGETS — loaded from external JSON (100+ brands)
# ═══════════════════════════════════════════════════════════════

def _load_typosquat_targets() -> dict[str, str]:
    """Load typosquat targets from data/typosquat_targets.json or fall back to built-in."""
    path = os.path.join(_DATA_DIR, "typosquat_targets.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
            brands = data.get("brands", data)
            if isinstance(brands, dict):
                return {k.lower(): v.lower() for k, v in brands.items() if k != "_meta"}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Failed to load typosquat_targets.json: %s — using built-in", e)

    # Minimal fallback
    return {
        "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
        "amazon": "amazon.com", "microsoft": "microsoft.com", "netflix": "netflix.com",
        "facebook": "facebook.com", "instagram": "instagram.com",
    }


# The global list exactly as loaded. brand_subdomain_abuse reads THIS one,
# not the merged list below (the ML model's max_brand_similarity reads the
# merged one since features_version 4, when the model was retrained on it,
# less the names added after the served model's training, _NOT_IN_MODEL):
# a Russian brand as a subdomain label has not had its false-positive pass —
# 'pochta' is what Russian companies call their webmail (pochta.<company>.ru),
# and marketplace seller tools put ozon./wildberries. in front of their own
# names.
GLOBAL_TYPOSQUAT_TARGETS: Mapping[str, str] = MappingProxyType(_load_typosquat_targets())

def _load_measured_global_groups() -> tuple[tuple[ru_brands.BrandGroup, ...], frozenset[str]]:
    """The global brands added with a false-positive pass, and the names the
    served ML model has not been trained with.

    data/typosquat_targets.json 'measured' holds one entry per brand owner in
    data/typosquat_targets_ru.json's format (official / unrelated /
    not_typos / shared_name, each with its evidence; api.services.ru_brands
    parses it). Its names are in 'brands' too, so every reader of the flat
    list sees them. The 2026-10-05 pass is docs/benchmarks/2026-10-05-global-brands.md.
    A malformed entry is logged and the flat list keeps working without the
    exemptions — the same failure mode as the Russian file."""
    path = os.path.join(_DATA_DIR, "typosquat_targets.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
        measured = data.get("measured", {})
        groups = tuple(ru_brands.parse_group(k, v) for k, v in measured.items() if not k.startswith("_"))
        brands = {k.lower(): v.lower() for k, v in data.get("brands", {}).items()}
        for g in groups:
            for name, domain in g.names.items():
                if brands.get(name) != domain:
                    raise ValueError(f"{g.key}: {name!r} must be in 'brands' as {domain!r}")
        not_in_model = frozenset(data.get("not_in_model", {}).get("names", ()))
        return groups, not_in_model
    except (FileNotFoundError, json.JSONDecodeError, ValueError, AttributeError) as e:
        logger.error("typosquat_targets.json 'measured' is unusable (%s); global exemptions skipped", e)
        return (), frozenset()


def _load_global_alternates() -> tuple[frozenset[str], frozenset[str]]:
    """The flat list's owners' other domains and other owners' same-shaped
    sites: data/typosquat_targets.json 'alternates' (official, unrelated),
    parsed by ru_brands.parse_alternates.

    Until 2026-10-23 the Tranco top-100k answered for googlemail.com,
    yahoo.de or hicloud.com before this rule ran; the licensed ranking does
    not carry them. Exact registrable-domain exemptions and nothing else —
    the names keep their rule ('measured' is what changes it). A malformed
    section is logged and exempts nothing, as with 'measured'."""
    path = os.path.join(_DATA_DIR, "typosquat_targets.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
        brands = {k.lower(): v.lower() for k, v in data.get("brands", {}).items()}
        return ru_brands.parse_alternates(data.get("alternates", {}), brands)
    except (FileNotFoundError, json.JSONDecodeError, ValueError, AttributeError) as e:
        logger.error("typosquat_targets.json 'alternates' is unusable (%s); its exemptions skipped", e)
        return frozenset(), frozenset()


# Russian brands (data/typosquat_targets_ru.json, see api.services.ru_brands):
# every official domain of the brand family, same-shaped sites of other
# owners, words one edit from a name, and per-brand switches for TLD
# confusion and edit distance.
RU_BRAND_GROUPS: tuple[ru_brands.BrandGroup, ...] = ru_brands.load()

# Global brands added with a measured false-positive pass (allegro, olx,
# xfinity, att …), in the Russian file's format. Their names are compared
# under the slip rule (see _rule_for), and the ML similarity feature leaves
# out _NOT_IN_MODEL until the model is retrained with them.
MEASURED_GLOBAL_GROUPS, _NOT_IN_MODEL = _load_measured_global_groups()
# Every group whose exemptions the rules honour, Russian and global.
_EXEMPTION_GROUPS: tuple[ru_brands.BrandGroup, ...] = RU_BRAND_GROUPS + MEASURED_GLOBAL_GROUPS
# The flat list's owners' other domains (googlemail.com, yahoo.de) and
# other owners' sites the rule read as a listed name (hicloud.com), verified
# one by one when the licensed ranking took them off the allowlist.
ALTERNATE_OFFICIAL_DOMAINS, ALTERNATE_UNRELATED_DOMAINS = _load_global_alternates()

# The state-service brand whose regions number their portals (gosuslugi26.ru,
# 51gosuslugi.ru): its names in data/typosquat_targets_ru.json — gosuslugi
# and госуслуги.
_STATE_SERVICE_BRAND = "gosuslugi"
_STATE_SERVICE_NAMES: frozenset[str] = frozenset(
    n for g in RU_BRAND_GROUPS if g.key == _STATE_SERVICE_BRAND for n in g.names
)
# A region's number: 01-99, or 1-9 without the leading zero.
_REGION_NUMBER = r"(?:0[1-9]|[1-9][0-9]?)"
_REGIONAL_PORTAL_NAME = re.compile(
    rf"^(?:(?:{'|'.join(map(re.escape, sorted(_STATE_SERVICE_NAMES)))}){_REGION_NUMBER}"
    rf"|{_REGION_NUMBER}(?:{'|'.join(map(re.escape, sorted(_STATE_SERVICE_NAMES)))}))$"
) if _STATE_SERVICE_NAMES else None
# The TLDs the regions register them under: .ru and .рф (wire form).
_REGIONAL_PORTAL_TLDS = frozenset({"ru", "xn--p1ai"})


def is_regional_state_portal_name(domain: str) -> bool:
    """True when the registrable domain is a state-service brand with a
    region number in front or behind and nothing else, under .ru or .рф:
    gosuslugi26.ru, 51gosuslugi.ru, госуслуги74.рф and their subdomains
    (new.gosuslugi86.ru).

    That is how Russian regions name their state-service portals — 14 are
    in tests/data/ru_heuristics_legit.txt (held out of training) and more
    in the brand's 'official' list. A brand's name plus digits reads to
    the model like sberbank24.ru, and the 2026-10-12 retrain scored all 14
    held-out ones above 0.6, so the weekly retrain's held-out Russian gate
    refused it. Only the model's weight is withheld for this shape (3.34);
    the name rules still judge it (gosuslugi77.ru is not a region's portal
    and stays a typosquat). Narrow on purpose: a lure word or hyphen
    (gosuslugi26-pay.ru), a look-alike letter (gosusiugi26.ru), three
    digits, another TLD (gosuslugi26.top, .com) or a regional zone
    (gosuslugi26.spb.ru) does not match.
    """
    if _REGIONAL_PORTAL_NAME is None:
        return False
    labels = registrable_domain(domain).split(".")
    if len(labels) != 2 or labels[1] not in _REGIONAL_PORTAL_TLDS:
        return False
    return bool(_REGIONAL_PORTAL_NAME.match(_decode_idn(labels[0])))

# What the typosquat rule compares against: global first (so an existing
# host keeps the brand it was reported under), then the Russian names.
TYPOSQUAT_TARGETS: dict[str, str] = {
    **GLOBAL_TYPOSQUAT_TARGETS,
    **{n: d for g in RU_BRAND_GROUPS for n, d in g.names.items() if n not in GLOBAL_TYPOSQUAT_TARGETS},
}
logger.info("Loaded %d typosquat brand targets (%d Russian brand groups)", len(TYPOSQUAT_TARGETS), len(RU_BRAND_GROUPS))

# Every listed brand family's own registrable domains (yandex.kz, втб.рф,
# olx.ua, googlemail.com), both spellings of an IDN.
_BRAND_OFFICIAL_DOMAINS: frozenset[str] = (
    frozenset(d for g in _EXEMPTION_GROUPS for d in g.official) | ALTERNATE_OFFICIAL_DOMAINS
)
# Registrable domains that are no one's typo: a listed brand's own sites
# and verified sites of other owners with the same shape (mts.ca —
# Manitoba's phone company).
_BRAND_LEGIT_DOMAINS: frozenset[str] = _BRAND_OFFICIAL_DOMAINS | ALTERNATE_UNRELATED_DOMAINS | frozenset(
    d for g in _EXEMPTION_GROUPS for d in g.unrelated
)
# Per name: labels one edit away that are words or other companies (ozone).
_BRAND_NOT_TYPOS: Mapping[str, frozenset[str]] = MappingProxyType(
    {n: g.not_typos for g in _EXEMPTION_GROUPS for n in g.names if g.not_typos}
)
# The Russian list's names (sberbank, втб …): see _rule_for.
_RU_NAMES: frozenset[str] = frozenset(n for g in RU_BRAND_GROUPS for n in g.names)
# Global names added with a false-positive pass (allegro, xfinity …): see
# _rule_for.
_MEASURED_GLOBAL_NAMES: frozenset[str] = frozenset(n for g in MEASURED_GLOBAL_GROUPS for n in g.names)
# Names other owners use too — abroad (Tele2 AB, T Bank N.A.), as an
# acronym (vtb) or a word (ozon): TLD confusion only under a TLD phishing
# favours, and no combos with generic words.
_SHARED_NAMES: frozenset[str] = frozenset(n for g in _EXEMPTION_GROUPS for n in g.shared_name)
# Names too few letters apart from other names for edit distance (tele2).
_NO_FUZZY: frozenset[str] = frozenset(n for g in _EXEMPTION_GROUPS for n in g.no_fuzzy)
# Per name: lure words for this brand alone — its own product's name
# (СберБанк Онлайн: sberbank-online, сбербанк-онлайн), as ru_lures skeletons.
_BRAND_LURE_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    n: frozenset(ru_lures.skeleton(w) for w in g.lure_words)
    for g in _EXEMPTION_GROUPS for n in g.names if g.lure_words
})


# ═══════════════════════════════════════════════════════════════
# ABUSED REGISTRAR LIST
# ═══════════════════════════════════════════════════════════════

def _load_abused_registrars() -> tuple[set[str], set[str]]:
    path = os.path.join(_DATA_DIR, "abused_registrars.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
            high = set(r.lower() for r in data.get("high_risk", []))
            medium = set(r.lower() for r in data.get("medium_risk", []))
            return high, medium
    except (FileNotFoundError, json.JSONDecodeError):
        return set(), set()


_ABUSED_REGISTRARS_HIGH, _ABUSED_REGISTRARS_MEDIUM = _load_abused_registrars()
# How long a registration is "recent" for the registrar rules (3.33).
_RECENT_REGISTRATION_DAYS = 90


# ═══════════════════════════════════════════════════════════════
# TLD RISK SCORING
# ═══════════════════════════════════════════════════════════════

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Free TLDs — 80%+ abuse rate
    ".xyz", ".top", ".work", ".click",        # Cheap gTLDs — heavily abused
    ".buzz", ".rest", ".surf", ".icu",        # New gTLDs — high abuse
    ".cam", ".live", ".online", ".site",      # Common phishing
    ".loan", ".racing", ".win", ".download",  # Almost exclusively spam
    ".zip", ".mov",                            # Google file-ext TLDs — 18% malicious (Netskope 2025)
    ".sbs", ".cfd",                            # Newly heavily-abused junk TLDs (cybercrimeinfocenter 2026)
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".cc", ".pw", ".ws",
    ".club", ".space", ".fun", ".monster",
    ".store", ".shop", ".stream", ".gdn", ".bid",  # .shop: abused but mainstream e-commerce, sits with .store
}


# ═══════════════════════════════════════════════════════════════
# HOMOGRAPH DETECTION — confusable Unicode characters
# ═══════════════════════════════════════════════════════════════

_CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    # Greek → Latin
    "\u03b1": "a", "\u03bf": "o", "\u0391": "A", "\u0392": "B",
    "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Latin extended
    "\u0261": "g", "\u026a": "i", "\u0299": "b",
    "\u1d0f": "o", "\u1d1c": "u",
}

# Look-alike characters and every letter each one passes for: '1' reads as
# l (paypa1) or i (1kea), '4' as a (eb4y).
_CHAR_SUBS: dict[str, str] = {
    "1": "li", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "!": "i",
}

# Multi-char ASCII glyph homoglyphs — the #1 lookalike tactic (Unit42 2025):
# "rn"->m, "vv"->w, "cl"->d survive IDN/punycode defenses AND change the label
# length, so they slip past single-char _CHAR_SUBS and Levenshtein<=2 checks.
_GLYPH_SUBS: list[tuple[str, str]] = [("rn", "m"), ("vv", "w"), ("cl", "d")]


def _glyph_skeleton(name: str) -> str:
    """Collapse multi-char glyph look-alikes so rnicrosoft->microsoft etc."""
    out = name
    for a, b in _GLYPH_SUBS:
        out = out.replace(a, b)
    return out

_SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "confirm", "secure", "account", "banking", "password",
    "reset", "suspend", "locked", "unlock", "validate", "authenticate",
    "wallet", "payment", "invoice", "billing", "refund", "recovery",
    "alert", "notification", "urgent", "expired", "reactivate",
    # Crypto-drainer lexicon (2025-2026: ledger-restore, metamask-claim, etc.)
    "connect", "restore", "sync", "migrate", "airdrop", "claim",
    "seed", "staking", "mint", "rewards", "presale",
}

# Combosquat action words are a SEPARATE, high-precision list. It must NOT be
# derived from _SUSPICIOUS_KEYWORDS: generic words like "connect"/"sync"/"rewards"/
# "restore" are common in legit brand-partner names (shopify-connect, chase-rewards)
# and would make brand+word combos false-positive as combosquats. These stay as
# standalone +10 keyword hits only.
_COMBOSQUAT_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "confirm", "secure", "account", "banking", "password",
    "reset", "suspend", "locked", "unlock", "validate", "authenticate",
    "wallet", "payment", "invoice", "billing", "refund", "recovery",
    "alert", "notification", "urgent", "expired", "reactivate",
})

# URL shorteners to detect
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "rb.gy", "cutt.ly",
    "short.io", "rebrand.ly", "tiny.cc", "surl.li", "shorturl.at",
    "v.gd", "qr.ae", "dub.sh", "link.infini.fr", "t.ly",
    "u.to", "clck.ru", "shrtco.de", "1url.cz",
    # In the licensed top 100k (2026-10-23) and absent above, so they were
    # answered instant-safe: a shortener's popularity vouches for no link.
    "s.gy", "short.gy", "l1nq.com", "bityli.com", "me2.do", "chilp.it",
    "abrir.link", "encurtador.dev", "beam.to", "jii.li", "buly.kr", "mpago.la",
    # Under a compound suffix, so the allowlist only reached them on
    # 2026-10-27 (top_domain_key): a public shortener in the top 100k; two
    # government ones, the Indonesian health ministry's abused for phishing
    # redirects (three PhishTank URLs, 2026); and universities' short-link
    # hosts that Phishing.Database lists by short code. Longer than two
    # labels, so the model's is_url_shortener (_is_url_shortener, last two
    # labels) never sees them; the allowlist does (_is_listed_shortener_host).
    "encurtador.com.br", "go.gov.sg", "s.kemkes.go.id",
    "link.uinsgd.ac.id", "link.upnyk.ac.id", "s.ecu.edu.au", "s.umj.ac.id",
}


# ═══════════════════════════════════════════════════════════════
# URL LEXICAL FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random (DGA indicator)."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _digit_ratio(s: str) -> float:
    """Ratio of digits to total characters."""
    if not s:
        return 0.0
    digits = sum(1 for c in s if c.isdigit())
    return round(digits / len(s), 3)


def _special_char_count(domain: str) -> int:
    """Count hyphens and dots beyond the minimum."""
    hyphens = domain.count("-")
    # Dots beyond TLD separator are suspicious
    extra_dots = max(0, domain.count(".") - 1)
    return hyphens + extra_dots


def _has_at_symbol(url_or_domain: str) -> bool:
    """@ in URL causes browser to ignore everything before it — classic phishing trick."""
    return "@" in url_or_domain


def _has_double_slash_redirect(url_or_domain: str) -> bool:
    """Double slash in path indicates redirect attempt."""
    # Find // after the protocol
    stripped = url_or_domain
    for prefix in ("http://", "https://"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    return "//" in stripped


def _has_hex_encoding(url_or_domain: str) -> bool:
    """Percent-encoded characters in domain part (obfuscation)."""
    return bool(re.search(r"%[0-9a-fA-F]{2}", url_or_domain))


def _has_non_standard_port(url_or_domain: str) -> bool:
    """Non-standard port number in URL."""
    match = re.search(r":(\d+)", url_or_domain)
    if match:
        port = int(match.group(1))
        if port not in (80, 443, 8080, 8443):
            return True
    return False


def _url_path_depth(url_or_domain: str) -> int:
    """Count path depth: example.com/a/b/c → depth 3."""
    if "/" in url_or_domain:
        path = url_or_domain.split("/", 1)[1] if "/" in url_or_domain else ""
        return path.count("/")
    return 0


# ── PII / token leak detection in URL parameters ─────────────────
#
# Strategy doc Top-20 #20 (impact 6, diff 7) — "Detect URLs that
# exfiltrate the user's email or session token in plain query
# parameters — a common phishing-and-tracking hybrid". Matches
# nothing in the consumer category; differentiator for a privacy-
# first product.
#
# Three patterns we look for, in descending order of suspicion:
#
#   1. JWT / bearer-token-shaped value in any query parameter. Real
#      sites never put auth tokens in the URL (the URL is logged in
#      browser history, Referer headers, web-server access logs,
#      CDN logs, and analytics-pixel destinations — every one of
#      which becomes a token exfiltration vector). When we see it,
#      it's almost certainly a phishing redirector or a poorly
#      designed tracker stealing a session.
#
#   2. Email address in any query parameter. Legitimate sites
#      occasionally use this for one-click sign-in ("magic link"),
#      but always behind a one-time token — never as the plain
#      identifier. Plain-email parameters are the canonical
#      footprint of a tracker that fingerprints the user across
#      sites OR a phishing page that prefills its own form.
#
#   3. Long high-entropy random-looking strings (≥ 28 chars, mix of
#      digits + letters). Often session IDs, sometimes UUIDs.
#      Lower confidence than the first two — many legitimate
#      systems use them too — so we score it lower.
#
# All three together cap the contribution at +25 so a URL with all
# of them at once doesn't push score over the dangerous threshold
# by themselves; they're a multiplier, not a verdict.

# The JWT and e-mail checks used to be single unanchored regexes:
#   eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+
#   [A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}
# re.search retries them from every offset, and each retry rescans the same
# run of characters, so "eyJeyJeyJ…" or "%%%%…" with no match took quadratic
# time. _has_jwt / _has_email answer the same question in one pass.
_TOKEN_DOT_RUN_RE = re.compile(r"[A-Za-z0-9_\-.]+")
_EMAIL_LOCAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-")
_EMAIL_DOMAIN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_LONG_ENTROPY_RE = re.compile(r"[A-Za-z0-9_\-]{28,}")


def _has_jwt(text: str) -> bool:
    """Whether `text` contains eyJ<tok>+.<tok>+.<tok>+ (tok = [A-Za-z0-9_-]).

    Linear: each maximal run of token characters and dots is split on the
    dots once. A match needs a segment holding "eyJ" plus at least one more
    character, followed by two non-empty segments.
    """
    for run in _TOKEN_DOT_RUN_RE.finditer(text):
        segments = run.group().split(".")
        for i in range(len(segments) - 2):
            head = segments[i]
            at = head.find("eyJ")
            if 0 <= at and at + 3 < len(head) and segments[i + 1] and segments[i + 2]:
                return True
    return False


def _has_email(text: str) -> bool:
    """Whether `text` contains <local>+@<domain>+.<letters>{2,24}.

    Linear: for each "@" preceded by a local-part character, the run of domain
    characters after it is scanned once for a "." that has at least one domain
    character before it and two letters after it. Domain characters never
    include "@", so the runs scanned for different "@"s do not overlap.
    """
    n = len(text)
    at = text.find("@")
    while at != -1:
        if at > 0 and text[at - 1] in _EMAIL_LOCAL_CHARS:
            j = at + 1
            while j < n and text[j] in _EMAIL_DOMAIN_CHARS:
                if (
                    text[j] == "."
                    and j > at + 1
                    and j + 2 < n
                    and text[j + 1] in _ASCII_LETTERS
                    and text[j + 2] in _ASCII_LETTERS
                ):
                    return True
                j += 1
        at = text.find("@", at + 1)
    return False


def _detect_url_pii_leak(url_or_domain: str) -> dict:
    """
    Return a dict with the per-pattern hits + a max-weight score.

    Shape: {
        jwt: bool,        # JWT-shaped token in the URL
        email: bool,      # Email address in the URL
        long_random: bool,# Long high-entropy string in the URL
        weight: int,      # 0–25 score contribution
    }

    URL-decoded once before matching so a `%40` doesn't hide an
    email — but we deliberately do NOT recurse into doubly-encoded
    cases (that's its own phishing pattern, _has_hex_encoding picks
    it up separately).
    """
    if "?" not in url_or_domain:
        return {"jwt": False, "email": False, "long_random": False, "weight": 0}
    try:
        from urllib.parse import unquote

        query = url_or_domain.split("?", 1)[1]
        decoded = unquote(query)
    except Exception:
        return {"jwt": False, "email": False, "long_random": False, "weight": 0}

    has_jwt = _has_jwt(decoded)
    has_email = _has_email(decoded)
    # Long random matches are noisy — only flag when the URL doesn't
    # already have JWT/email and the random part is in a value position
    # (after =). This avoids triple-counting on `?session=eyJ...`.
    has_long_random = False
    if not has_jwt and not has_email:
        for token in decoded.split("&"):
            if "=" not in token:
                continue
            value = token.split("=", 1)[1]
            if _LONG_ENTROPY_RE.search(value):
                # Require both letters AND digits to dodge pure base64
                # decorative hashes (e.g. version tokens that have only
                # letters or only hex).
                if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
                    has_long_random = True
                    break

    weight = 0
    if has_jwt:
        weight += 25
    if has_email:
        weight += 15
    if has_long_random:
        weight += 5
    # Cap at 25 — the signals stack but we don't want one URL to
    # single-handedly dominate the verdict; the rest of the analyzer
    # (blocklists, brand impersonation, etc.) still has to corroborate.
    if weight > 25:
        weight = 25
    return {
        "jwt": has_jwt,
        "email": has_email,
        "long_random": has_long_random,
        "weight": weight,
    }


_FAKE_TLD_LABELS = frozenset({"com", "org", "net", "gov", "edu", "co", "io", "me"})
# A registered NAME that spells a TLD may also spell a country's: ru.msk.ru
# turns sberbank.ru.msk.ru into "sberbank.ru". Only the registered name gets
# these two — as a subdomain label 'ru' is a language (ru.wikipedia.org).
_REGISTERED_FAKE_TLD_LABELS = _FAKE_TLD_LABELS | {"ru", "su"}


def _is_restricted_zone(suffix: str, legacy: bool = False) -> bool:
    # A known open zone is nobody's government whatever its label: FreeDNS's
    # govt.hu and mil.nf, ChangeIP's edu.si, gob.li and sch.in, RCS&RDS's
    # go.ro (data/cctld_second_levels.json 'registries'). Read as restricted,
    # paypal.com.govt.hu lost its fake-TLD signal and the extension's guard
    # took any two names there for one site. `legacy`: the reading before
    # 2026-10-31, which the served model's has_fake_tld_subdomain was trained
    # on — a new reading there is a retrain, not a side effect.
    if not legacy and suffix in CCTLD_OPEN_ZONES:
        return False
    return suffix in _RU_RESTRICTED_ZONES or suffix.split(".")[0] in _RESTRICTED_ZONE_LABELS


def _registered_tld_lookalike(domain: str, legacy: bool = False) -> Optional[str]:
    """The registered name itself, when it spells a TLD and was bought under
    a multi-label public suffix anyone can register at: 'com' of
    vk.com.msk.ru, which a reader takes for vk.com. com.msk.ru, ru.msk.ru
    and gov.msk.ru are private persons' names (whois.flexireg.net,
    2026-09-27). Not under a restricted zone — edu.gov.ru is the Ministry of
    Education — nor for REGIONAL_GOVERNMENT_DOMAINS (gov.spb.ru).

    The LEGACY registrable domain (legacy_registrable_domain): this is half
    of the model's has_fake_tld_subdomain, which asks with legacy=True
    (_is_restricted_zone)."""
    registrable = legacy_registrable_domain(domain)
    label, _, suffix = registrable.partition(".")
    if "." not in suffix or label not in _REGISTERED_FAKE_TLD_LABELS:
        return None
    if registrable in REGIONAL_GOVERNMENT_DOMAINS or _is_restricted_zone(suffix, legacy):
        return None
    return label


def _apparent_subdomain_levels(domain: str) -> int:
    """Subdomain levels as a reader counts them: the labels left of the
    registrable domain, plus the registered name when it spells a TLD —
    vk.com.msk.ru reads as two levels (vk.com) above msk.ru."""
    levels = len(_subdomain_labels(domain))
    return levels + 1 if levels and _registered_tld_lookalike(domain) else levels


def _has_fake_tld_in_subdomain(domain: str, legacy: bool = False) -> bool:
    """Detect paypal.com.evil.xyz pattern — real TLD used as subdomain.

    Only labels LEFT of the registrable domain are a subdomain. In
    kvs.gov.spb.ru the 'gov' is the registered name under the spb.ru zone,
    and in edu.gov.ru it is part of the public suffix — neither is somebody
    dressing a TLD up as a subdomain. But where the registered name itself
    spells a TLD under an open zone (vk.com.msk.ru), whatever stands to its
    left is dressed up exactly that way.

    legacy=True is the model's feature (has_fake_tld_subdomain): the reading
    it was trained on, without the open zones of 2026-10-31.
    """
    subdomain = _subdomain_labels(domain)
    if any(part in _FAKE_TLD_LABELS for part in subdomain):
        return True
    return bool(subdomain) and _registered_tld_lookalike(domain, legacy) is not None


# The tenant zones whose registrable's rank is the platform's, not its
# customers' (_platform_tenant_site): every shared suffix the scorer knows,
# PSL-derived ones included (ondigitalocean.app, altervista.org, hf.space),
# but not the operators' own suffixes (fonts.googleapis.com is Google's) nor
# a zone with a restricted label (gov.scot: its names are the Scottish
# Government's agencies, not anyone's pick).
_RANK_TENANT_SUFFIXES: frozenset[str] = frozenset(
    z for z in _SCORER_SHARED_SUFFIXES - OPERATOR_SUFFIXES
    if not _RESTRICTED_ZONE_LABELS.intersection(z.split("."))
)


def _platform_tenant_site(domain: str) -> Optional[str]:
    """The customer's own name (x.webcindario.com of a.x.webcindario.com) when
    `domain` is a site on a hosting platform or dynamic-DNS service AND its
    registrable domain is the platform's (webcindario.com, workers.dev,
    blogspot.com.br, ondigitalocean.app) — else None: for registered names,
    the platforms' own hosts and zones (www.tumblr.com, app.netlify.com,
    login.secureserver.net — hosting_platforms operator_zones), the
    operators' own suffixes (googleapis.com) and zones where the registrable
    already is the customer's name.

    The registrable's rank and its place in the top lists are then the
    PLATFORM's popularity, which says nothing about one customer's site (the
    analyzer's _name_is_vouched_for refuses it for the same reason). Unlike
    is_hosting_platform_site, the PSL-derived suffixes count. A restricted
    registry does not: registrable_domain() already reads a name under
    gov.ru or co.uk as the registrant's own, and the zones it does not know
    (gov.scot) are left out of _RANK_TENANT_SUFFIXES."""
    d = (domain or "").lower().strip(".")
    if is_operator_zone_name(d):
        return None
    suffix = _dynamic_dns_suffix_of(d) or tenant_suffix_of(d, _RANK_TENANT_SUFFIXES)
    if not suffix:
        return None
    registrable = registrable_domain(d)
    if registrable != suffix and not suffix.endswith("." + registrable):
        return None
    return ".".join(d.split(".")[-(suffix.count(".") + 2):])


def popularity_rank(signals: dict, domain: Optional[str] = None) -> Optional[int]:
    """The best top-1M rank (Redis tranco:ranks) of the host or of its
    registrable domain, from the analyzer's signals, or None. `domain`
    defaults to signals['domain']; for a tenant whose registrable is the
    hosting platform (_platform_tenant_site) only the host's own rank counts."""
    host = signals.get("domain", "") if domain is None else domain
    registrable_rank = None if _platform_tenant_site(host) else signals.get("tranco_registrable_rank")
    ranks = [r for r in (signals.get("tranco_rank") if signals.get("tranco_ranked") else None,
                         registrable_rank) if isinstance(r, int) and 0 < r <= 1_000_000]
    return min(ranks) if ranks else None


# Signals that are each about as common on real sites as on phishing, so a
# pile of them alone is a caution, never 'dangerous' (calculate_score caps it
# at DANGEROUS_ABOVE). 'dangerous' needs at least one other signal with a
# positive weight: a list or OTX, the model, a brand or look-alike rule, the
# domain's age, a high-abuse zone (.cfd, .sbs, .top …), no HTTPS or a broken
# certificate, an address trick (@, //, %xx, a port, a token in the URL). A
# signal added later is strong until it is listed here.
#
# дорожное.рф (Дорожное радио) was 'dangerous' 53 on the 2026-10-25 benchmark
# with five of them: no security headers, no MX on an alias domain, a
# renewed certificate, and two hops to dorognoe.ru, its own main site.
# Replayed on the live signals of 2026-10-26 (1,735 hosts): with the
# high-abuse zone counted weak too, 6 of the 219 dangerous fresh phishing
# hosts fell to caution — 4 of them on .cfd/.click/.sbs — so it is not. As
# listed, 2 of the 219 do (bnb-binance.ac.cn, buscarmi-icloud.app: they send
# a foreign scanner on to binance.com and google.com).
#
# OTX is not on the list: its auto-feeds (CyberHunterAutoFeed, phishdestroy)
# list fresh phishing within about a day, and with one to five reports
# counted weak, 50 of the fresh phishing hosts OTX answered for on
# 2026-10-26 fell from 'dangerous' to caution 50 (portal-canalbradesco.digital
# 74, kucoindeep.com 68). Only one to five reports whose newest is
# _OTX_STALE_DAYS or more old are weak — calculate_score marks that one.
WEAK_SIGNALS: frozenset[str] = frozenset({
    # what the probes saw on the site: hygiene, not intent
    "missing_headers", "no_mx_record", "new_certificate", "multiple_redirects",
    "excessive_redirects", "cross_domain_redirect", "low_dns_ttl", "many_a_records",
    # the shape of the name and the address
    "high_entropy", "medium_entropy", "high_digit_ratio", "excessive_special_chars",
    "many_special_chars", "long_domain_name", "unnatural_ngram", "suspicious_ngram",
    "abnormal_vowel_ratio", "consonant_cluster", "suspicious_keyword", "excessive_subdomains",
    "long_url", "very_long_url", "deep_path",
    # where it is registered or hosted
    "risky_tld_medium", "abused_registrar", "risky_registrar", "dynamic_dns_host", "url_shortener",
})
# The top of the caution band (a score above it is 'dangerous').
DANGEROUS_ABOVE = 50

# One to five OTX reports whose newest was made this many days ago or earlier
# (analyzer._otx_reports) are history, not a live campaign, and weak:
# victims and references are listed too (#284). Real OTX answers of
# 2026-10-26: the 53 fresh phishing hosts with one to five distinct reports
# had their newest 0-55 days old (auto-feeds of the day, phishdestroy's
# monthly lists); the 6 real sites with one to five that left the allowlist
# in #284 had theirs 217-1,579 days old (centralnic-dns.com, job-shop.com,
# pbsadverxo.com, webglobe.com, cmgroup.com, crcdn.org). When the age is not
# known, the reports count as current.
_OTX_STALE_DAYS = 90


def _certificate_is_a_renewal(signals: dict) -> bool:
    """Something shows the name is older than its fresh certificate:

    * it is a customer's site directly under a hosting platform's suffix
      (_platform_tenant_site is the host itself) and the certificate names it
      only through a wildcard (signals 'cert_wildcard', site_probes). A
      wildcard covers one label, so that wildcard is the platform's own
      (*.vercel.app, *.wixsite.com), renewed for every site under it at once —
      every Vercel tenant showed the same 57-day-old *.vercel.app one. One
      level down it is the tenant's: *.<account>.workers.dev,
      *.<project>.pages.dev, or a DNS-01 wildcard on the tenant's own
      dynamic-DNS zone (*.evil.duckdns.org), as old as the tenant's site: on
      fresh phishing of 2026-10-26, 10 of the 11 wildcards under a week old
      on such hosts were the tenant's (rblxcashout.swervostore.workers.dev:
      *.swervostore.workers.dev, issued that day). A wildcard
      on the site's own registered name is its registrant's too: kits put one
      on a fresh domain for all their subdomains (ferrari.info4571011.pro,
      bradesco.ne12topaz.digital, 2026-10-25);
    * the name is in the top-1M popularity ranking (popularity_rank — never a
      hosting platform's rank for its tenant): the ranking measures months of
      links and visits.

    Without either the certificate may be the site's first, as for a kit's
    fresh domain. The age of the REGISTRATION is not evidence: once RDAP
    measured it (2026-10-26), "registered 90+ days ago" took this signal from
    11 of 1,046 live phishing hosts — kits on subdomains of old names
    (klarna0001926538.sviluppo.host), fresh subdomains of them
    (portal.mykraken.exchange), aged domains (vkk.com,
    ingdirect-portal-ingreso.com), 3 of them losing a level — and from 2 of
    1,260 real sites, which stayed 'safe' with it. Limited to the registrable
    name itself and 365+ days, it still took it from 2 phishing hosts and
    spared no real site a level. (Certificate Transparency would tell a
    renewal apart directly — crt.sh lists the previous, still valid
    certificate for 13 of the 15 real sites it answered for — but on
    2026-10-26 it took 7.2 s at the median, and 31 of 96 queries failed
    (502s, timeouts): far past the 3 s analysis budget.)"""
    host = (signals.get("domain") or "").lower().strip(".")
    if signals.get("cert_wildcard") and host and _platform_tenant_site(host) == host:
        return True
    return popularity_rank(signals) is not None


def _is_url_shortener(domain: str) -> bool:
    """Check if domain is a known URL shortener."""
    # The last two labels on purpose: this is the ML feature is_url_shortener
    # too (ml_features), and the served model learned this reading. The
    # entries longer than two labels (link.infini.fr, encurtador.com.br) never
    # match here; reading them is a feature change for the next retrain. The
    # allowlist checks every ancestor instead (_is_listed_shortener_host).
    base = _extract_base_domain(domain)
    return base in _URL_SHORTENERS


# ═══════════════════════════════════════════════════════════════
# MAIN SCORING FUNCTION — 30+ SIGNALS
# ═══════════════════════════════════════════════════════════════

def calculate_score(signals: dict) -> tuple[int, RiskLevel, list[DomainReason]]:
    """
    Layered scoring pipeline with 30+ signals.

    Layer 1: Blocklist → instant dangerous
    Layer 2: Allowlist (top 100K popular domains) → instant safe
    Layer 3: Feature extraction → weighted scoring
    """
    score = 0
    reasons: list[DomainReason] = []
    # Reasons that are weak this time though their code is not in
    # WEAK_SIGNALS (old OTX reports, _OTX_STALE_DAYS).
    weak_here: list[DomainReason] = []
    domain: str = signals.get("domain", "")

    # ── IDN normalisation, done ONCE, up front ──
    #
    # An internationalised domain reaches us in its ASCII-compatible
    # (punycode) form, because that is what DNS carries. Two different
    # questions get asked about it downstream, and they need different forms:
    #
    #   ascii_domain   — the wire form. Everything that LOOKS THE NAME UP
    #                    speaks punycode: DNS/DoH, the blocklists, the popularity
    #                    tables, the PSL helpers, and the ML model (whose
    #                    training features were extracted from ASCII names —
    #                    feeding it Unicode would break feature parity).
    #   unicode_domain — the name a human reads. Everything that judges the
    #                    SHAPE of the name (hyphens, length, entropy,
    #                    n-grams) must use this, or it scores the encoder's
    #                    artefacts: xn----7sbnackuskv0m.xn--p1ai "has" six
    #                    hyphens and a 19-char label, while экзамен-пдд.рф
    #                    has one hyphen and eleven characters.
    #
    # Each heuristic below states which form it takes and why.
    ascii_domain = domain
    unicode_domain = _decode_idn(domain)

    # Name under judgement: the decoded label left of the last two labels.
    # Still the last two, not registrable_domain(): the name-shape rules below
    # never saw a name under a compound suffix ('co' of xkqzvbrtplmn.co.uk,
    # 0/safe where xkqzvbrtplmn.com is 28/caution), and reading the real name
    # is a recall change with its own cost — simulated 2026-10-27 on 93,989
    # Majestic names under multi-label suffixes outside the top 100k, 467
    # went safe→caution (0.5%). It gets its own false-positive pass, with the
    # extension's copy (local-scorer.js `name`).
    unicode_base = _extract_base_domain(unicode_domain)
    domain_name = unicode_base.split(".")[0] if "." in unicode_base else unicode_base
    # On a dynamic-DNS service or a hosting platform the name someone chose
    # is the tenant's label: the name-shape rules (3.13-3.32) read
    # 'gedivan' of gedivan.duckdns.org, not 'duckdns', which gave every
    # *.duckdns.org host +12 (a 5-consonant run, a 1:6 vowel ratio) and
    # never looked at the tenant's own name (2026-10-15).
    tenant_label = _tenant_label(ascii_domain)
    if tenant_label:
        domain_name = _decode_idn(tenant_label)

    # ════════════════════════════════════════════
    # LAYER 1: BLOCKLIST CHECK (instant block)
    # ════════════════════════════════════════════

    if signals.get("safe_browsing_hit"):
        score += 80
        reasons.append(DomainReason(
            signal="safe_browsing", weight=80,
            detail="Flagged by Google Safe Browsing as dangerous",
        ))

    if signals.get("phishtank_hit"):
        score += 70
        reasons.append(DomainReason(
            signal="phishtank", weight=70,
            detail="Listed in PhishTank phishing database",
        ))

    if signals.get("urlhaus_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="urlhaus", weight=75,
            detail="Listed in URLhaus malware URL database",
        ))

    if signals.get("phishstats_hit"):
        score += 65
        reasons.append(DomainReason(
            signal="phishstats", weight=65,
            detail="Found in PhishStats aggregated phishing database",
        ))

    if signals.get("threatfox_hit"):
        score += 70
        reasons.append(DomainReason(
            signal="threatfox", weight=70,
            detail="Listed in ThreatFox IOC database (abuse.ch)",
        ))

    if signals.get("spamhaus_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="spamhaus_dbl", weight=75,
            detail="Listed in Spamhaus Domain Block List",
        ))

    if signals.get("surbl_hit"):
        score += 65
        reasons.append(DomainReason(
            signal="surbl", weight=65,
            detail="Listed in SURBL URI blocklist",
        ))

    # Strategy doc #5 — explicit cards for the abuse.ch full bundle.
    # blocklist_hits aggregate already counts them; this adds the
    # per-source DomainReason so EVIDENCE_BOOK can render specifically.
    if signals.get("malware_bazaar_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="malware_bazaar", weight=75,
            detail="Distributing known malware samples (MalwareBazaar / abuse.ch)",
        ))

    if signals.get("feodo_hit"):
        score += 80
        reasons.append(DomainReason(
            signal="feodo", weight=80,
            detail="Active C2 server for a known botnet (Feodo Tracker / abuse.ch)",
        ))

    # Strategy doc #2 — favicon brand-clone match. Very high-confidence
    # signal: page serves a known brand's favicon but is hosted off-brand.
    if signals.get("favicon_cloned"):
        score += 35
        reasons.append(DomainReason(
            signal="favicon_brand_clone", weight=35,
            detail=signals.get("favicon_detail") or "Brand-clone favicon detected",
        ))

    # Strategy doc #17 — typosquat watchtower hit. The user (or
    # another user watching the same brand) added this brand to the
    # watchlist; the daily scan caught a cousin-domain CT entry.
    if signals.get("watchtower_matched"):
        wt_weight = signals.get("watchtower_weight", 25)
        variant = signals.get("watchtower_variant") or "typo"
        brand = signals.get("watchtower_brand") or "a watched brand"
        explanations = {
            "typo": f"Looks like a misspelling of {brand} (Levenshtein {signals.get('watchtower_distance', '?')}).",
            "tld": f"Same name as {brand}, different top-level domain — common phishing pattern.",
            "homograph": f"Uses look-alike Unicode characters mimicking {brand}.",
            "subdomain": f"Uses {brand}'s name as a subdomain on an unrelated host.",
        }
        score += wt_weight
        reasons.append(DomainReason(
            signal="watchtower_typosquat", weight=wt_weight,
            detail=explanations.get(variant, f"Flagged by Cleanway Watchtower as a cousin of {brand}."),
        ))

    # AlienVault OTX community reports — popularity-gated.
    # OTX "pulses" are community threat reports that MENTION a domain. Legit
    # popular sites appear in them constantly as impersonation TARGETS / campaign
    # victims, so a mention is NOT proof of malice. A raw +30/+60 (ungated by
    # popularity) flagged major legit sites — e.g. elfinanciero.com.mx (a national
    # newspaper, top-10k) landed at "dangerous" on 8 victim-reference pulses.
    #   - top-10k domain  → skip (an OTX mention is ~always a victim reference).
    #   - top-100k domain → discount by half.
    #   - otherwise (obscure domain in threat reports) → full weight.
    # Uses the PSL-aware registrable domain so compound ccTLDs (.com.mx/.co.uk)
    # resolve correctly, not the naive 2-label split.
    #
    # The files are the allowlist; the Redis top-1M rank of the host or its
    # registrable (tranco_rank, tranco_registrable_rank) counts as well:
    # within the first 100,000 → skip, within the 1,000,000 → skip up to 5
    # pulses and halve more. Since 2026-10-23 the allowlist holds the licensed
    # ranking, and ~45,000 names that Tranco's top 100k carried rank 100k-1M:
    # with full OTX weight rostelecom.ru, rosbank.ru, beget.ru and dream11.com
    # went from safe to caution 27 and ddos-guard.net to dangerous 67 on
    # victim-reference pulses (verifier, 2026-10-23).
    #
    # A customer's site on a hosting platform is judged by its own name, not
    # the platform's (_platform_tenant_site): OTX is asked about the full
    # host, so its pulses are about the tenant, and workers.dev or at.ua being
    # popular vouches for none of their customers (audit 2026-10-25).
    #
    # The tiers count DISTINCT reports (analyzer._otx_reports): a
    # cloned pulse is the same report again. tztu.ru's 44 pulses were one
    # malspam-header dump and 43 copies of it, and "Flagged in 44 reports"
    # (+60) plus a renewed certificate made a real plant's site 'dangerous'
    # (benchmark 2026-10-25). Without a pulse list (an older caller) the
    # count is used, as before.
    #
    # One to five reports that are all _OTX_STALE_DAYS or more old are weak
    # (WEAK_SIGNALS): they still score, but alone with other weak signals
    # they make a caution, not a 'dangerous'.
    alienvault_pulses = signals.get("alienvault_pulse_count", 0) or 0
    _distinct = signals.get("alienvault_distinct_pulses")
    otx_reports = alienvault_pulses if _distinct is None else min(_distinct, alienvault_pulses)
    if otx_reports > 0:
        # The registrable domain whose popularity counts
        # (rank_registrable_domain), with the Russian zones: until 2026-10-28
        # this read the compound-ccTLD heuristic, whose key for any x.spb.ru
        # was spb.ru (top-10k #758) — so no OTX report ever scored under
        # spb.ru or msk.ru (#2547), and under nov.ru, pp.ru and ras.ru it was
        # halved: 14 of the 186 ru_heuristics_phish hosts. Never a zone above
        # the name the old reading had: web.de (#2424) waives no report about
        # login.web.de, as it did not before.
        _reg = _platform_tenant_site(ascii_domain) or rank_registrable_domain(domain)
        _rank = popularity_rank(signals, ascii_domain)
        _top_ranked = _rank is not None and _rank <= 100_000
        _ranked = _rank is not None
        # A tombstoned name (dead_top_names) waives and halves nothing, nor
        # does a young registration's place on the lists (analyzer._young_rank).
        _dead_name = _reg in _dead.DEAD_TOP_NAMES or bool(signals.get("popularity_withheld"))
        if (_dead_name or _reg not in TOP_10K_RANKS) and not _top_ranked and not (_ranked and otx_reports <= 5):
            _discount = (_reg in TOP_100K and not _dead_name) or _ranked
            _copies = (f" ({otx_reports} distinct, the rest are copies)"
                       if otx_reports < alienvault_pulses else "")
            if otx_reports > 5:
                _wt = 30 if _discount else 60
                score += _wt
                reasons.append(DomainReason(
                    signal="alienvault_otx_high", weight=_wt,
                    detail=f"Flagged in {alienvault_pulses} AlienVault OTX threat reports{_copies}",
                ))
            else:
                _wt = 15 if _discount else 30
                score += _wt
                _newest = signals.get("alienvault_newest_report_days")
                _stale = isinstance(_newest, int) and _newest >= _OTX_STALE_DAYS
                _age = f", the newest {_newest} days old" if _stale else ""
                reasons.append(DomainReason(
                    signal="alienvault_otx", weight=_wt,
                    detail=f"Found in {alienvault_pulses} AlienVault OTX threat report(s){_copies}{_age}",
                ))
                if _stale:
                    weak_here.append(reasons[-1])

    # IPQualityScore
    if signals.get("ipqs_phishing"):
        score += 70
        reasons.append(DomainReason(
            signal="ipqs_phishing", weight=70,
            detail="Identified as phishing by IPQualityScore",
        ))
    elif signals.get("ipqs_risk_score", 0) > 75:
        score += 40
        reasons.append(DomainReason(
            signal="ipqs_high_risk", weight=40,
            detail=f"High risk score ({signals['ipqs_risk_score']}) from IPQualityScore",
        ))

    # Multi-source confirmation boost
    blocklist_count = signals.get("blocklist_hits", 0)
    if blocklist_count >= 3:
        score += 20
        reasons.append(DomainReason(
            signal="multi_blocklist", weight=20,
            detail=f"Flagged by {blocklist_count} independent blocklist sources — high confidence threat",
        ))

    # If any blocklist hit, skip allowlist and return high score
    if score >= 70:
        score = min(score, 100)
        return score, RiskLevel.dangerous, reasons

    # ════════════════════════════════════════════
    # LAYER 2: ALLOWLIST CHECK (instant safe)
    # ════════════════════════════════════════════

    # Instant-safe only for real top domains — NOT for subdomains of shared
    # platforms / public suffixes (github.io, blogspot.com, us.org, s3…),
    # URL shorteners, or abused Google services. One rule, shared with the
    # public router: is_trusted_top_domain().
    if is_trusted_top_domain(domain):
        # The entry the allowlist matched (amazon.co.uk for www.amazon.co.uk).
        top_entry = top_domain_key(ascii_domain)
        rank = TOP_10K_RANKS.get(top_entry)
        detail = f"Ranked #{rank} globally" if rank else "In global top 100K domains"
        return 0, RiskLevel.safe, [DomainReason(
            signal="known_legitimate", weight=-50,
            detail=f"Known legitimate domain: {top_entry}. {detail}",
        )]

    # ════════════════════════════════════════════
    # LAYER 3: FEATURE SCORING (30+ signals)
    # ════════════════════════════════════════════

    # ── 3.0 Popularity (Strategy doc #14; signal names keep "tranco") ──
    # Negative weight = trust. A domain in the worldwide top-1M (the
    # Majestic Million and Chrome UX Report ranking, Redis tranco:ranks) is
    # statistically unlikely to be a phishing landing page (kits churn
    # through fresh domains). The
    # tier system (top-1k / 10k / 100k / 1M) tapers the bonus — never
    # large enough to single-handedly flip a high-risk verdict, but
    # enough to dampen false positives on legitimate-but-unfamiliar
    # sites. NB: NOT a free safe-pass — subdomain takeover and
    # compromised popular sites still get scored by other rules.
    if signals.get("tranco_ranked"):
        tranco_weight = signals.get("tranco_weight", 0)
        if tranco_weight < 0:
            score += tranco_weight  # negative — pulls score down
            reasons.append(DomainReason(
                signal="tranco_popularity", weight=tranco_weight,
                detail=signals.get("tranco_label") or "Among the 1,000,000 most popular sites worldwide",
            ))

    # ── 3.1 Homograph / IDN attack ──
    # ASCII form: _check_homograph decodes internally, on purpose — it needs
    # the raw characters (and its own permissive punycode fallback) to spot
    # mixed-script look-alikes such as pаypal.com with a Cyrillic 'а'.
    homograph_target = _check_homograph(ascii_domain)
    if homograph_target:
        score += 60
        reasons.append(DomainReason(
            signal="homograph_attack", weight=60,
            detail=f"Uses look-alike Unicode characters to impersonate {homograph_target}",
        ))

    # ── 3.2 Domain age ──
    domain_age = signals.get("domain_age_days")
    if domain_age is not None:
        if domain_age < 7:
            score += 50
            reasons.append(DomainReason(
                signal="domain_very_new", weight=50,
                detail=f"Domain registered {domain_age} days ago — very suspicious",
            ))
        elif domain_age < 30:
            score += 30
            reasons.append(DomainReason(
                signal="domain_new", weight=30,
                detail=f"Domain registered {domain_age} days ago",
            ))

    # ── 3.3 IP-based URL ──
    if signals.get("is_ip_based"):
        score += 35
        reasons.append(DomainReason(
            signal="ip_based", weight=35,
            detail="Uses IP address instead of domain name",
        ))

    # ── 3.4 Typosquatting (6 methods) ──
    # Unicode form: brand comparison is meaningless against punycode gibberish
    # ('xn--pypal-4ve' resembles no brand), while on the decoded name a
    # Cyrillic look-alike sits one edit from its target — so this now
    # corroborates the homograph signal instead of missing it.
    typosquat_result = _check_typosquatting_v2(unicode_domain)
    if typosquat_result:
        legit_domain, method = typosquat_result
        score += 25
        reasons.append(DomainReason(
            signal="typosquatting", weight=25,
            detail=f"Impersonates {legit_domain} ({method})",
        ))

    # ── 3.5 Brand in subdomain: "paypal.evil.com" ──
    # ASCII form: this walks the registrable-domain boundary with the PSL
    # helper, whose compound-suffix tables are written in ASCII. Decoding
    # would change nothing anyway — the brand list it matches against is
    # Latin, so a decoded Cyrillic label can never match it.
    #
    # Or a Russian brand's name bought under an open Russian zone
    # (sberbank.spb.ru, vk.nov.ru): the same deception, one level down.
    brand_sub = _check_brand_in_subdomain(ascii_domain)
    if brand_sub and _is_self_hosted_product(ascii_domain, brand_sub, signals):
        brand_sub = None
    zone_brand = None if brand_sub else _check_brand_under_open_zone(ascii_domain)
    tenant_brand = None if (brand_sub or zone_brand) else _check_brand_on_hosting_tenant(ascii_domain)
    if brand_sub or zone_brand or tenant_brand:
        score += 30
        # Under an open zone the name may be a dealer's or a partner's
        # (cdek.msk.ru calls itself CDEK's partner): the reason says what the
        # name does to a reader, not what its owner intends.
        detail = (
            f"Uses '{brand_sub}' brand name in subdomain to deceive" if brand_sub else
            f"Uses the '{zone_brand}' brand name as its own name under a zone anyone can register in, "
            f"so it reads as the brand's site" if zone_brand else
            f"Uses the '{tenant_brand}' brand name in the name of a site on a hosting platform "
            f"anyone can publish to"
        )
        reasons.append(DomainReason(signal="brand_subdomain_abuse", weight=30, detail=detail))

    # ── 3.5b A name on a free dynamic-DNS service ──
    # gedivan.duckdns.org, havuwuzu.ipv64.net: a name that costs nothing,
    # takes a minute and points at any machine. Since features_version 5 the
    # ML model reads such a host by its own label and scores fresh malware
    # and phishing there 0.4-0.8 where it used to say 0.95 (weekly benchmark
    # 2026-10-11), so the platform itself is weighed here. Alone it does not
    # even reach 'caution'; it tips a host only where other signals agree.
    # Measured 2026-10-15: 15 and 10 catch the same fresh hosts and turn one
    # of the 21 dynamic-DNS hosts in the Tranco top-1M 'dangerous'
    # (snowflake-cortex.duckdns.org); 20 catches three more and turns three.
    dyn_suffix = _dynamic_dns_suffix_of(ascii_domain)
    if dyn_suffix:
        score += DYNAMIC_DNS_WEIGHT
        reasons.append(DomainReason(
            signal="dynamic_dns_host", weight=DYNAMIC_DNS_WEIGHT,
            detail=f"Uses a free dynamic-DNS name ({dyn_suffix}) — anyone can create one in a minute",
        ))

    # ── 3.6 Fake TLD in subdomain: "paypal.com.evil.xyz" ──
    # ASCII form: looks for literal 'com'/'org'/… labels; decoding never
    # creates or removes one.
    if _has_fake_tld_in_subdomain(ascii_domain):
        score += 35
        reasons.append(DomainReason(
            signal="fake_tld_subdomain", weight=35,
            detail="Contains a real TLD in subdomain (e.g., example.com.evil.xyz)",
        ))

    # ── 3.7 No HTTPS ──
    # True only on positive evidence: port 443 refused us or spoke no TLS,
    # AND port 80 served a page (site_probes). "Our scanner could not
    # connect" is None, never True: президент.рф, rosreestr.gov.ru and
    # bankspb.ru refuse foreign connections, and scoring that as "no HTTPS"
    # (+40) plus "no headers" (+15) alone crossed the 'dangerous' line
    # (report 2026-09-25 #1).
    if signals.get("no_https"):
        score += 40
        reasons.append(DomainReason(
            signal="no_https", weight=40,
            detail="Site does not use HTTPS encryption",
        ))

    # ── 3.7b Broken certificate ──
    # Expired, self-signed or issued for another name: every browser shows a
    # full-page warning, wherever it is opened from, so this is measured —
    # unlike a certificate from an authority we merely do not know (the
    # Russian national CA), which site_probes reports as "not reached".
    cert_problem = signals.get("certificate_problem")
    if cert_problem:
        score += 30
        reasons.append(DomainReason(
            signal="invalid_certificate", weight=30,
            detail=_CERTIFICATE_PROBLEM_TEXT.get(cert_problem, _CERTIFICATE_PROBLEM_TEXT[""]),
        ))

    # ── 3.8 Free SSL + new domain combo ──
    if signals.get("free_ssl") and domain_age is not None and domain_age < 30:
        score += 20
        reasons.append(DomainReason(
            signal="free_ssl_new_domain", weight=20,
            detail="Free SSL certificate on a new domain — common phishing pattern",
        ))

    # ── 3.9 Missing security headers ──
    # None = not measured (the scanner could not open the site over HTTPS).
    # Only a real HTTPS response that lacks the headers counts — a site that
    # refuses our foreign scanner has not shown us anything to judge.
    missing_headers = signals.get("missing_security_headers") or []
    if len(missing_headers) >= 3:
        score += 15
        reasons.append(DomainReason(
            signal="missing_headers", weight=15,
            detail=f"Missing security headers: {', '.join(missing_headers[:3])}",
        ))

    # ── 3.10 Risky TLD ──
    # ASCII form: HIGH_RISK_TLDS / MEDIUM_RISK_TLDS are spelled in ASCII, so
    # '.xn--p1ai' must stay encoded here rather than decode to '.рф'.
    tld = _extract_tld(ascii_domain)
    if tld in HIGH_RISK_TLDS:
        score += 20
        reasons.append(DomainReason(
            signal="risky_tld_high", weight=20,
            detail=f"Uses high-risk TLD '{tld}' — commonly abused in phishing",
        ))
    elif tld in MEDIUM_RISK_TLDS:
        score += 10
        reasons.append(DomainReason(
            signal="risky_tld_medium", weight=10,
            detail=f"Uses suspicious TLD '{tld}'",
        ))

    # ── 3.11 Excessive subdomains (2+ levels above the registrable domain) ──
    # Counted from the registrable domain, not from the TLD: www.shop.co.uk
    # and kvs.gov.spb.ru have ONE subdomain level each, a.b.evil.com has two
    # — and so does vk.com.msk.ru, whose registered name 'com' reads as a TLD.
    # Either form works — decoding never adds or removes a label separator.
    sub_levels = _apparent_subdomain_levels(ascii_domain)
    if sub_levels >= 2:
        below = ascii_domain.lower().strip(".").split(".", sub_levels)[-1]
        score += 15
        reasons.append(DomainReason(
            signal="excessive_subdomains", weight=15,
            detail=f"Unusually deep subdomain nesting ({sub_levels} levels above {below})",
        ))

    # ── 3.12 Suspicious keywords in domain ──
    # Unicode form: the keyword list is words a human would read in the name.
    # On a hosting platform or a dynamic-DNS service the name someone chose
    # is the tenant's label (domain_name above): this rule read 'vercel' of
    # secure-login-portal.vercel.app. Measured 2026-10-26 on brandless
    # tenants: the word is in 49 of 815 in the four licensed feeds' fresh
    # phishing (6.0%) and in 18 of 5,221 with real Chrome traffic (CrUX
    # global origins, 0.34%).
    keyword = _keyword_in_name(domain_name) if tenant_label else _check_suspicious_keywords(unicode_domain)
    if keyword:
        score += 10
        reasons.append(DomainReason(
            signal="suspicious_keyword", weight=10,
            detail=f"Contains suspicious keyword: '{keyword}'",
        ))

    # ── SCRIPT GATE for the name-shape heuristics ──
    #
    # 3.13 (entropy), 3.30 (n-gram), 3.31 (vowel ratio) and 3.32 (consonant
    # cluster) all ask "does this look like a word, or like output from a
    # generator?" — and the answer depends on WHICH LANGUAGE the name is in.
    # Asking the English model about a Russian name does not measure
    # "random", it measures "not English":
    #
    #   * bigram_score() looks names up in _ENGLISH_BIGRAMS, which has no
    #     Cyrillic pairs — so it returns 0.0 for EVERY Russian name.
    #   * vowel_consonant_ratio() and consecutive_consonants_max() count
    #     against ASCII-only _VOWELS/_CONSONANTS — a Cyrillic name has zero
    #     of each, so the ratio is 0.0 and trips the "< 0.2" anomaly.
    #
    # So each script gets the model that fits it. Cleanway is RU-first, and
    # the Russian branch exists because gating these on `isascii()` alone
    # left an all-Cyrillic name with NO lexical scrutiny whatsoever:
    # measured on the previous commit, жкшнвыапролдэъ.рф scored 0/safe with
    # an empty reasons list, and 398 of 400 synthesised Cyrillic DGA names
    # scored exactly 0. A freshly registered generated .рф domain with no
    # reputation has to look suspicious to the local rules, or the local
    # rules are not protecting the users we ship to first.
    #
    # A script we have no model for — Greek, Arabic, accented Latin — still
    # skips, because guessing with the wrong table is what caused the
    # original false positives. Mixed-script names also skip (name_script
    # returns 'other'): they are homograph attacks, and _check_homograph
    # above is the tool for them, unweakened.
    from api.services.url_features import (
        bigram_score,
        consecutive_consonants_max,
        cyrillic_consecutive_consonants_max,
        cyrillic_vowel_consonant_ratio,
        name_script,
        russian_bigram_score,
        vowel_consonant_ratio,
    )

    script = name_script(domain_name)

    # ── 3.13 Shannon entropy (DGA detection) ──
    #
    # Thresholds are per-alphabet: entropy is bounded by log2(alphabet), so
    # the same "ordinariness" reads hotter on Russian's 33 letters than on
    # English's 26. Calibrated 2026-09-20 against the 653 Cyrillic names in
    # data/top-1m.csv vs 1,000 length-matched random Cyrillic names.
    #
    # Be honest about what this signal is worth on Cyrillic: it BARELY
    # separates. Legitimate Russian domain names are long compounds that use
    # many distinct letters, so they sit right on top of the random ones —
    # перемышльский-район has entropy 3.93, HIGHER than the keyboard mash
    # жкшнвыапролдэъ at 3.81. At Latin's medium threshold (3.5) the Cyrillic
    # false-positive rate is 10.26%, so that tier is dropped entirely rather
    # than shipped with a prettier-looking number. What survives is one
    # conservative tier at the point where measured legitimate FPs hit zero
    # (> 4.0 with len > 10: 0.00% of legitimate names, 2.5% of the DGA set).
    entropy = _shannon_entropy(domain_name)
    if script == "ascii" and entropy > 4.0 and len(domain_name) > 8:
        score += 12
        reasons.append(DomainReason(
            signal="high_entropy", weight=12,
            detail=f"Domain name has unusually high randomness (entropy={entropy}) — possible auto-generated domain",
        ))
    elif script == "ascii" and entropy > 3.5 and len(domain_name) > 10:
        score += 6
        reasons.append(DomainReason(
            signal="medium_entropy", weight=6,
            detail=f"Domain name appears somewhat random (entropy={entropy})",
        ))
    elif script == "cyrillic" and entropy > 4.0 and len(domain_name) > 10:
        score += 12
        reasons.append(DomainReason(
            signal="high_entropy", weight=12,
            detail=f"Domain name has unusually high randomness (entropy={entropy}) — possible auto-generated domain",
        ))

    # ── 3.14 High digit ratio ──
    # Unicode form (via domain_name): punycode encodes non-ASCII letters into
    # a base-36 tail full of digits, so the wire form invents a digit ratio
    # the real name does not have.
    d_ratio = _digit_ratio(domain_name)
    if d_ratio > 0.4 and len(domain_name) > 5:
        score += 15
        reasons.append(DomainReason(
            signal="high_digit_ratio", weight=15,
            detail=f"Domain name is {round(d_ratio*100)}% digits — suspicious",
        ))

    # ── 3.15 Excessive special characters ──
    # Unicode form. This is the single biggest source of the RU false
    # positives: all 28 flagged punycode domains in the 2026-09-20 sample
    # tripped it, because the '----' in xn----7sb… is the ACE delimiter plus
    # the name's own hyphen, not four hyphens that anybody typed.
    special = _special_char_count(unicode_domain)
    if special >= 4:
        score += 15
        reasons.append(DomainReason(
            signal="excessive_special_chars", weight=15,
            detail=f"Excessive hyphens/dots ({special}) in domain",
        ))
    elif special >= 3:
        score += 8
        reasons.append(DomainReason(
            signal="many_special_chars", weight=8,
            detail=f"Multiple hyphens/dots ({special}) in domain",
        ))

    # ── 3.16 @ symbol in URL (browser ignores everything before @) ──
    raw_input = signals.get("raw_url", domain)
    if _has_at_symbol(raw_input):
        score += 40
        reasons.append(DomainReason(
            signal="at_symbol", weight=40,
            detail="Contains @ symbol — browser ignores everything before it (phishing trick)",
        ))

    # ── 3.17 Double-slash redirect ──
    if _has_double_slash_redirect(raw_input):
        score += 20
        reasons.append(DomainReason(
            signal="double_slash_redirect", weight=20,
            detail="Contains suspicious double-slash redirect in URL path",
        ))

    # ── 3.18 Hex/percent encoding in domain ──
    # ASCII form: percent-encoding is a property of the wire representation.
    if _has_hex_encoding(ascii_domain):
        score += 20
        reasons.append(DomainReason(
            signal="hex_encoding", weight=20,
            detail="Domain contains percent-encoded characters (obfuscation)",
        ))

    # ── 3.19 Non-standard port ──
    if _has_non_standard_port(raw_input):
        score += 15
        reasons.append(DomainReason(
            signal="non_standard_port", weight=15,
            detail="Uses non-standard port number",
        ))

    # ── 3.19b PII / token leak in URL query parameters ──
    # Strategy doc Top-20 #20. Flags URLs that exfiltrate the user's
    # email, JWT, or session token through plain query params — a
    # common phishing-and-tracking hybrid that no consumer product
    # currently detects.
    pii_hit = _detect_url_pii_leak(raw_input)
    if pii_hit["weight"] > 0:
        bits = []
        if pii_hit["jwt"]:
            bits.append("auth token")
        if pii_hit["email"]:
            bits.append("email address")
        if pii_hit["long_random"]:
            bits.append("session-id-like value")
        detail = "URL leaks " + " + ".join(bits) + " in the address"
        score += pii_hit["weight"]
        reasons.append(DomainReason(
            signal="url_pii_leak",
            weight=pii_hit["weight"],
            detail=detail,
        ))

    # ── 3.20 URL length (long URLs are suspicious) ──
    url_len = len(raw_input)
    if url_len > 100:
        score += 15
        reasons.append(DomainReason(
            signal="very_long_url", weight=15,
            detail=f"Unusually long URL ({url_len} characters)",
        ))
    elif url_len > 75:
        score += 8
        reasons.append(DomainReason(
            signal="long_url", weight=8,
            detail=f"Long URL ({url_len} characters)",
        ))

    # ── 3.21 Deep path ──
    path_depth = _url_path_depth(raw_input)
    if path_depth > 5:
        score += 10
        reasons.append(DomainReason(
            signal="deep_path", weight=10,
            detail=f"Unusually deep URL path ({path_depth} levels)",
        ))

    # ── 3.22 URL shortener ──
    # ASCII form: _URL_SHORTENERS is an ASCII lookup table.
    if _is_url_shortener(ascii_domain):
        score += 15
        reasons.append(DomainReason(
            signal="url_shortener", weight=15,
            detail="URL shortener detected — real destination is hidden",
        ))

    # ── 3.23 Domain length ──
    # Unicode form (via domain_name): punycode inflates length — перемышльский-район
    # is 19 characters, its xn---- encoding is 28.
    if len(domain_name) > 25:
        score += 10
        reasons.append(DomainReason(
            signal="long_domain_name", weight=10,
            detail=f"Unusually long domain name ({len(domain_name)} characters)",
        ))

    # ── 3.24 DNS: Very low TTL (fast-flux indicator) ──
    # Real fast-flux runs TTL <= 60s with rapid IP rotation. Ordinary CDN /
    # tracker infra sits at 60-300s (Cloudflare defaults to 300), so the old
    # `< 300` threshold flagged a huge slice of the legit web as "fast-flux".
    # Tightened to < 60 so this fires on genuinely suspicious infra only.
    dns_ttl = signals.get("dns_ttl")
    if dns_ttl is not None and dns_ttl < 60:
        score += 15
        reasons.append(DomainReason(
            signal="low_dns_ttl", weight=15,
            detail=f"Very low DNS TTL ({dns_ttl}s) — rapidly-changing infrastructure",
        ))

    # ── 3.25 DNS: No MX record (apex domains only) ──
    # MX lives on the registrable domain, never on a `track.`/`go.` subdomain,
    # so penalising a subdomain for "no MX" dinged every legit redirect/CDN
    # host. Only apply when we're actually looking at the apex. Use the
    # PSL-aware registrable domain (not the naive 2-label split) so this
    # stays correct for compound suffixes — foo.co.uk and x.my.id are apexes,
    # not subdomains, and so is herzen.spb.ru (the heuristic read before
    # 2026-10-28 had no Russian zones). Not an IP address: it is its own
    # registrable domain since then (its last two numbers before), and
    # check_dns finds no MX for any IP URL.
    # Nor in a zone only a government body or the NHS registers in
    # (_registered_in_vetted_zone): NHS trust sites often take mail elsewhere.
    if signals.get("dns_has_mx") is False and not is_ip_literal(domain or ""):
        if domain == registrable_domain(domain) and not _registered_in_vetted_zone(domain):
            score += 8
            reasons.append(DomainReason(
                signal="no_mx_record", weight=8,
                detail="No MX (email) record — unlikely to be a legitimate business",
            ))

    # ── 3.26 DNS: Many A records (fast-flux or CDN) ──
    a_count = signals.get("dns_a_count")
    if a_count is not None and a_count > 10:
        score += 10
        reasons.append(DomainReason(
            signal="many_a_records", weight=10,
            detail=f"Unusually many A records ({a_count}) — possible fast-flux network",
        ))

    # ── 3.27 SSL: New certificate (issued < 7 days ago) ──
    # A stand-in for "the site is new", so it yields to anything that shows
    # the name is older than its certificate (_certificate_is_a_renewal).
    # Let's Encrypt and the other ACME authorities issue 90-day certificates
    # that renew every ~60 days: on 2026-10-26, 17 of the 157 real Russian
    # sites with a certificate (data/benchmark_legit_ru.txt) had one under a
    # week old — tztu.ru's renewal of 2026-10-24 and дорожное.рф's of
    # 2026-10-20 among them (benchmark 2026-10-25) — against 22-29% of the
    # fresh phishing hosts: a weak signal (WEAK_SIGNALS).
    cert_age = signals.get("cert_age_days")
    if cert_age is not None and cert_age < 7 and not _certificate_is_a_renewal(signals):
        score += 15
        reasons.append(DomainReason(
            signal="new_certificate", weight=15,
            detail=f"SSL certificate issued {cert_age} days ago — very new",
        ))

    # ── 3.28 Redirect chain: Too many redirects ──
    redirect_count = signals.get("redirect_count", 0)
    if redirect_count > 3:
        score += 15
        reasons.append(DomainReason(
            signal="excessive_redirects", weight=15,
            detail=f"Suspicious redirect chain ({redirect_count} hops)",
        ))
    elif redirect_count > 1:
        score += 5
        reasons.append(DomainReason(
            signal="multiple_redirects", weight=5,
            detail=f"Multiple redirects ({redirect_count} hops)",
        ))

    # ── 3.29 Redirect: Cross-domain (landing on different domain) ──
    if signals.get("redirect_cross_domain"):
        score += 20
        reasons.append(DomainReason(
            signal="cross_domain_redirect", weight=20,
            detail="Redirects to a different domain — possible phishing redirect",
        ))

    # ── 3.30 N-gram analysis: domain name "naturalness" ──
    if script == "ascii":
        bg_score = bigram_score(domain_name)
        if bg_score < 0.15 and len(domain_name) > 7:
            score += 10
            reasons.append(DomainReason(
                signal="unnatural_ngram", weight=10,
                detail=f"Domain name has unnatural character patterns (bigram score={bg_score})",
            ))
        elif bg_score < 0.25 and len(domain_name) > 10:
            score += 5
            reasons.append(DomainReason(
                signal="suspicious_ngram", weight=5,
                detail=f"Domain name has unusual character patterns (bigram score={bg_score})",
            ))
    elif script == "cyrillic":
        # One tier only. The weak Latin tier ("suspicious_ngram", < 0.25)
        # has no Cyrillic counterpart because it earns nothing: measured, a
        # < 0.18 second tier moved the DGA caution rate by 0.00pp while
        # adding a lexical mark to 79 more legitimate Russian domains
        # (14.4% → 26.5%), including экзамен-пдд.рф and судьироссии.рф —
        # the exact names the previous commit cleared.
        bg_score = russian_bigram_score(domain_name)
        if bg_score < 0.10 and len(domain_name) > 7:
            score += 10
            reasons.append(DomainReason(
                signal="unnatural_ngram", weight=10,
                detail=f"Domain name has unnatural character patterns (bigram score={bg_score})",
            ))

    # ── 3.31 Vowel/consonant ratio anomaly ──
    #
    # The band is per-alphabet. English has 5 vowels to 21 consonants, so a
    # uniformly random Latin string lands near 5/21 = 0.24 and the "< 0.2"
    # floor catches its lower tail. Russian has 10 vowels to 21 consonants,
    # so random Cyrillic lands near 0.48 — comfortably INSIDE the Latin
    # band. Reusing 0.2 would have made random Cyrillic look more
    # pronounceable than random Latin, which is why the Cyrillic floor is
    # raised to 0.30 (measured: 1.53% of legitimate names, 20.0% of the DGA
    # set; at 0.35 it would be 3.68% / 27.2%, and the names it starts
    # touching are abbreviation-style ones like транснефть and мфц-омск).
    if script == "ascii":
        vc_ratio = vowel_consonant_ratio(domain_name)
        vc_floor = 0.2
    elif script == "cyrillic":
        vc_ratio = cyrillic_vowel_consonant_ratio(domain_name)
        vc_floor = 0.30
    else:
        vc_ratio, vc_floor = None, 0.0
    if vc_ratio is not None and len(domain_name) > 6 and (vc_ratio < vc_floor or vc_ratio > 1.5):
        score += 6
        reasons.append(DomainReason(
            signal="abnormal_vowel_ratio", weight=6,
            detail=f"Abnormal vowel/consonant ratio ({vc_ratio}) — likely auto-generated",
        ))

    # ── 3.32 Consecutive consonants (>5 = very unnatural) ──
    #
    # The >= 5 cut holds for Russian too, and the measurement is emphatic:
    # across the 653 legitimate Cyrillic names NOT ONE has a 5-consonant
    # run, while 28.1% of the DGA set does. Dropping to >= 4 would catch
    # more (44.3%) but starts hitting real institutions —
    # президентскиегранты, реестрповесток, декларации-соответствия — so it
    # stays at 5. ъ and ь break a run; see CYRILLIC_SIGNS.
    if script == "ascii":
        max_cons = consecutive_consonants_max(domain_name)
    elif script == "cyrillic":
        max_cons = cyrillic_consecutive_consonants_max(domain_name)
    else:
        max_cons = 0
    if max_cons >= 5 and len(domain_name) > 6:
        score += 6
        reasons.append(DomainReason(
            signal="consonant_cluster", weight=6,
            detail=f"Unnatural consonant cluster ({max_cons} consecutive) — possible DGA",
        ))

    # ── 3.33 Registrar reputation ──
    # data/abused_registrars.json ranks registrars by the phishing domains
    # registered through them, which are used within days of registration.
    # An old registration says nothing about its registrar: on the
    # 2026-10-26 replay, the first with RDAP data, the rule fired on 192 of
    # 376 real sites of known age (ncfr.org, 28 years at Tucows) and on 124
    # of 527 phishing hosts. So it counts only for a recent registration,
    # and only when the registry gave the date.
    registrar = signals.get("registrar", "")
    if registrar and domain_age is not None and domain_age < _RECENT_REGISTRATION_DAYS:
        registrar_lower = registrar.lower()
        if any(ar in registrar_lower for ar in _ABUSED_REGISTRARS_HIGH):
            score += 12
            reasons.append(DomainReason(
                signal="abused_registrar", weight=12,
                detail=f"Registered through high-abuse registrar: {registrar[:40]}",
            ))
        elif any(ar in registrar_lower for ar in _ABUSED_REGISTRARS_MEDIUM):
            score += 5
            reasons.append(DomainReason(
                signal="risky_registrar", weight=5,
                detail=f"Registered through frequently-abused registrar: {registrar[:40]}",
            ))

    # ── 3.34 ML Model prediction ──
    try:
        from api.services.ml_scorer import ml_predict
        # ASCII form: the model's features were extracted from ASCII domains,
        # so the wire form is what keeps inference consistent with training.
        # A known shortener's name says nothing about the destination, and the
        # url_shortener rule above already says so. The feeds are full of
        # shortened lures, so the model scores the shortener itself as phishing;
        # letting it add weight would mark every bit.ly link "caution".
        ml_result = None if _is_url_shortener(ascii_domain) else ml_predict(ascii_domain)
        if ml_result:
            ml_prob = ml_result["phishing_probability"]
            ml_confidence = ml_result["confidence"]

            if ml_prob > 0.6 and is_regional_state_portal_name(ascii_domain):
                # A region's state-service portal (gosuslugi26.ru): the
                # model reads brand + digits as a look-alike, and the
                # weekly retrain's held-out gate refused models that did.
                # Its weight is withheld; the name rules above still judge
                # the name.
                pass
            elif ml_prob > 0.85 and ml_confidence > 0.7:
                score += 35
                reasons.append(DomainReason(
                    signal="ml_high_risk", weight=35,
                    detail=f"ML model: {ml_prob*100:.0f}% phishing probability (confidence: {ml_confidence*100:.0f}%)",
                ))
            elif ml_prob > 0.6:
                score += 20
                reasons.append(DomainReason(
                    signal="ml_suspicious", weight=20,
                    detail=f"ML model: {ml_prob*100:.0f}% phishing probability",
                ))
            elif (ml_prob < 0.1 and score > 30 and not signals.get("popularity_withheld")
                  and legacy_registrable_domain(ascii_domain) not in _dead.DEAD_TOP_NAMES):
                # ML says safe but rules say risky — reduce score slightly.
                # Not for a tombstoned name: its in_top_domains feature
                # still reads 1 (the model's copy of the list), so the
                # model's "safe" is the dead name's old rank talking.
                score -= 10
                reasons.append(DomainReason(
                    signal="ml_safe_override", weight=-10,
                    detail=f"ML model: only {ml_prob*100:.0f}% phishing probability — reducing risk score",
                ))
    except Exception:
        pass  # ML is optional — don't break scoring if unavailable

    # ── Weak signals alone are a caution (WEAK_SIGNALS) ──
    # Every reason stays in the list, so the person sees what was found; only
    # the verdict stops at the top of the caution band. Not on a hosting
    # customer's site that names a brand (_tenant_brand_word): there a pile
    # of weak signals is how fresh phishing looks.
    if score > DANGEROUS_ABOVE and not any(
        r.weight > 0 and r.signal not in WEAK_SIGNALS and not any(r is w for w in weak_here)
        for r in reasons
    ) and not _tenant_brand_word(ascii_domain):
        score = DANGEROUS_ABOVE

    # ── Clamp ──
    score = max(0, min(100, score))

    # ── Determine level ──
    if score <= 20:
        level = RiskLevel.safe
    elif score <= DANGEROUS_ABOVE:
        level = RiskLevel.caution
    else:
        level = RiskLevel.dangerous

    return score, level, reasons


def calculate_confidence(
    checks_succeeded: int, total_checks: int, domain_age: Optional[int]
) -> ConfidenceLevel:
    if checks_succeeded >= 4 and domain_age is not None:
        return ConfidenceLevel.high
    elif checks_succeeded >= 3:
        return ConfidenceLevel.medium
    else:
        return ConfidenceLevel.low


def calculate_confidence_pct(
    score: int, checks_succeeded: int, total_checks: int
) -> int:
    """Strategy doc Top-20 #12 — numeric confidence band per verdict.

    The headline transparency claim ("FP rate 0.08%") is a marginal
    average. A specific verdict's confidence depends on two
    measurable factors:

      coverage  — fraction of analyzer checks that returned a real
                  answer (not the breaker fallback). A verdict
                  built on 4/18 checks is less trustworthy than
                  one built on 18/18.
      margin    — how far the final score sits from the nearest
                  decision boundary (30 = safe/caution, 70 =
                  caution/dangerous). A score of 75 is more
                  confidently 'dangerous' than a score of 71.

    The blend is weighted toward coverage (0.7) because no amount
    of margin can rescue a verdict that ran on no data. Output is
    clamped to [50, 99]; we never claim 100% — that's the conformal
    point. The categorical ConfidenceLevel is derived downstream
    from this number for backwards-compatible callers.
    """
    if total_checks <= 0:
        return 50
    coverage = max(0.0, min(checks_succeeded / total_checks, 1.0))

    score_clamped = max(0, min(score, 100))
    if score_clamped < 30:
        margin_pts = 30 - score_clamped
    elif score_clamped < 70:
        margin_pts = min(score_clamped - 30, 70 - score_clamped)
    else:
        margin_pts = score_clamped - 70
    # Normalize: a 30-point cushion = full margin = 1.0.
    margin = min(margin_pts / 30.0, 1.0)

    # Coverage is a hard gate, not a weighted term: with zero data,
    # we never claim more than the floor regardless of margin (we
    # can't see the threshold to know the margin is real). The
    # margin then refines the answer once at least some data is in.
    blended = coverage * (0.7 + 0.3 * margin)   # in [0, 1]
    pct = 50 + round(49 * blended)              # in [50, 99]
    return max(50, min(pct, 99))


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _extract_base_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _ascii_label(label: str) -> str:
    """The ASCII (punycode) spelling of one label, so a decoded name can be
    looked up in the ASCII suffix tables."""
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


def _ru_suffix_length(ascii_labels: list[str]) -> int:
    """How many trailing labels form the longest Russian PSL suffix the name
    ends with — an exact rule, or one label under a wildcard base — 0 when
    none does. Every rule has 2+ labels."""
    for k in range(len(ascii_labels), 1, -1):
        tail = ascii_labels[-k:]
        if ".".join(tail) in RU_PUBLIC_SUFFIXES or ".".join(tail[1:]) in _RU_WILDCARD_SUFFIXES:
            return k
    return 0


def _ru_registrable_domain(domain: str) -> Optional[str]:
    """The registrable domain of a host under a Russian public suffix from
    the PSL: that suffix plus one label, longest suffix first —
    kvs.gov.spb.ru → gov.spb.ru, a.b.hosting.myjino.ru → itself
    (b.hosting.myjino.ru is a suffix under '*.hosting.myjino.ru'). A bare
    suffix answers itself; None when no such suffix applies. Accepts the
    ASCII or the decoded form and answers in the same form."""
    parts = (domain or "").lower().strip(".").split(".")
    k = _ru_suffix_length([_ascii_label(p) for p in parts])
    return ".".join(parts[-(k + 1):]) if k else None


def registrable_domain(domain: str) -> str:
    """The registrable domain (eTLD+1) a host is judged by: the Public Suffix
    List's ICANN rules with the Russian zones and the ccTLD default on top
    (public_suffix.py: every generic second level of a 2-letter TLD is a
    suffix but for the named zones) — login.example.co.uk → example.co.uk,
    paypal-secure.my.id → itself, kvs.gov.spb.ru → gov.spb.ru,
    mail.confirm-lnstagram.com.de → confirm-lnstagram.com.de,
    x.paypal-login.ne.pw → paypal-login.ne.pw, login.web.de → web.de.
    The DoH gateway's _registrable_domain is the same function; whose rank
    counts for a host is rank_registrable_domain()'s question.

    Not what the phishing model's features read: see
    legacy_registrable_domain()."""
    return _psl_registrable_domain(domain)


def legacy_registrable_domain(domain: str) -> str:
    """registrable_domain() as it was until 2026-10-28: under a Russian
    public suffix _ru_registrable_domain(), elsewhere the compound-ccTLD
    heuristic (public_suffix.heuristic_registrable_domain) — x.my.id is
    under 'my.id', www.web.de is its own registrable domain.

    Pinned for the phishing model: host_shape(), shared_tenant() and the
    shape helpers below feed its features (dot_count, subdomain_depth, the
    name every lexical feature reads, in_top_domains, is_hosting_subdomain,
    has_fake_tld_subdomain), ml/train_model.py builds its corpus and split
    groups with it and scripts/build_top_domains.py folds the popularity
    list with a copy of it. A model is served with the feature data it was
    trained on (model_meta.json feature_data); reading the PSL here would
    have changed the feature vector of 643 top-100k names and 5,463 of the
    699,287 hosts of the 2026-10-24 feed snapshot without a retrain
    (measured 2026-10-27). Move it with a retrain, not before."""
    dom = (domain or "").lower().strip(".")
    return _ru_registrable_domain(dom) or heuristic_registrable_domain(dom)


def rank_registrable_domain(domain: str) -> str:
    """The name whose top-1M rank may speak for `domain` as its registrable
    domain's: registrable_domain(), but never shorter than
    legacy_registrable_domain() — under a zone public_suffix names as one
    owner's (login.web.de), the name the reading before 2026-10-28 kept
    apart from it. Everywhere else registrable_domain() is never shorter
    than that reading by itself (tests/test_public_suffix.py).

    Read by tranco._registrable_rank (the signals' tranco_registrable_rank:
    the OTX gate, the fresh-certificate exemption, self-hosted products),
    the OTX gate's own top-10k/100k key and the analyzer's vouch for an
    unreachable site. Not by SURBL (dnsbl_checks.check_surbl): SURBL keys a
    name under a named zone by the zone (none of them is on its
    two-level-tlds list, 2026-10-28), as registrable_domain() does; the two
    differ nowhere else. A zone's rank is everyone's under it: the
    2026-10-28 review found 59 feed phishing hosts taking one (co.ua
    #278,678, co.nl #284,346, info.gf #270,247 on the Tranco top-1M) before
    those zones were split again. The cost is the old reading's for the
    named zones: login.web.de is not vouched for by web.de's rank, as it
    was not before."""
    new = registrable_domain(domain)
    old = legacy_registrable_domain(domain)
    return old if len(old) > len(new) and old.endswith("." + new) else new


def _subdomain_labels(domain: str) -> list[str]:
    """Labels strictly LEFT of the registrable domain ([] for an apex) — the
    LEGACY one (legacy_registrable_domain): the model's subdomain_depth and
    dot_count count them, and so do the excessive-subdomains and fake-TLD
    rules, which stay with the feature they share this helper with. On the
    PSL's reading they would have lost 2,496 and gained 28 'excessive
    subdomains' on the 2026-10-24 feed hosts (03316951.zi-xz.my.id has one
    level under the ICANN suffix my.id, not two) — a rule version of its
    own, measured on its own, at the next retrain."""
    dom = (domain or "").lower().strip(".")
    registrable = legacy_registrable_domain(dom)
    if dom == registrable or not dom.endswith("." + registrable):
        return []
    return dom[: -(len(registrable) + 1)].split(".")


def _extract_tld(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return "." + parts[-1] if parts else ""


# ── IDN / punycode normalisation ──

# RFC 1035 §2.3.4. _DOMAIN_PATTERN already caps labels at 63 on the request
# path, so this is defence in depth for callers that reach the scorer some
# other way (tests, scripts, future entry points).
_MAX_DNS_LABEL = 63


def _decode_idn(domain: str) -> str:
    """Return the Unicode form of an internationalised domain.

    `xn----7sbnackuskv0m.xn--p1ai` → `экзамен-пдд.рф`.

    Punycode is an ENCODING, not a name. That ASCII form has six hyphens and
    a 19-character label; the name it actually spells has one hyphen and
    eleven characters. Any heuristic that judges the SHAPE of a name — hyphen
    counts, label length, entropy, n-grams — is reading the encoder's output
    unless it decodes first, and scores the artefacts instead of the name.
    (Measured 2026-09-20: 28 of the 29 punycode domains in a 2,000-domain
    sample of the .ru/.рф/.su Tranco tail came back 'caution' this way.)

    Callers keep the ASCII form for everything that legitimately speaks
    punycode — DNS lookups, blocklists, the popularity tables and the ML model,
    all of which are keyed on the wire form.

    Decoding is per-label and never raises: a label that is not valid
    punycode keeps its ASCII spelling, so malformed input degrades to the
    previous behaviour rather than erroring. The stdlib `idna` codec is
    tried first and the raw `punycode` codec second — the latter skips
    IDNA validation, so a deliberately malformed attack label still decodes
    to the characters it encodes instead of being waved through as ASCII.

    That permissive second codec is why the length bound below exists. It
    will happily "decode" anything, and punycode is expansive, so a label
    longer than a DNS label may legally be ('xn--' + 'a' * 120) comes back
    as a run of U+0080 control characters — not a name, and not something
    any downstream heuristic should be handed. A label over
    _MAX_DNS_LABEL keeps its ASCII spelling instead.
    """
    if "xn--" not in domain.lower():
        return domain

    out: list[str] = []
    for label in domain.split("."):
        if not label.lower().startswith("xn--"):
            out.append(label)
            continue
        # RFC 1035 §2.3.4: a label is at most 63 octets. Anything longer is
        # malformed input, not a name — decoding it yields control
        # characters, so keep the ASCII form.
        if len(label) > _MAX_DNS_LABEL:
            out.append(label)
            continue
        decoded = ""
        try:
            decoded = label.encode("ascii").decode("idna")
        except Exception:
            try:
                decoded = label[4:].encode("ascii").decode("punycode")
            except Exception:
                decoded = ""
        # The permissive codec can also emit UNPAIRED SURROGATES (U+D800-
        # U+DFFF) — 'xn--zi0c0o6s' is one. Python keeps them in a str, but the
        # first component that ENCODES the name (a log line, the JSON
        # response, a cache key) raises UnicodeEncodeError, turning a hostile
        # domain into a 500. Keep the ASCII spelling unless the decoded label
        # survives a UTF-8 round trip.
        if decoded:
            try:
                decoded.encode("utf-8")
            except UnicodeEncodeError:
                decoded = ""
        out.append(decoded or label)
    return ".".join(out)


# ── Homograph detection ──

def _check_homograph(domain: str, top_domains: Optional[AbstractSet[str]] = None) -> Optional[str]:
    # `top_domains`: the brands whose look-alikes count (default TOP_DOMAINS;
    # the ML feature is_homograph passes the served model's own copy).
    # IDN homograph attacks appear in DNS/URLs as ASCII punycode (xn--…), so a
    # raw ascii check misses them entirely. Decode any xn-- label back to
    # Unicode FIRST, then look for confusable characters on the decoded form.
    # Shares _decode_idn with the scorer so the two cannot drift apart: this
    # check is the reason a decode failure falls back to the raw punycode
    # codec rather than giving up, and the reason callers hand it the ASCII
    # form instead of a pre-decoded one.
    decoded = _decode_idn(domain)

    try:
        decoded.encode("ascii")
        return None  # pure ASCII after decoding — no confusables possible
    except UnicodeEncodeError:
        pass

    ascii_version = ""
    has_confusable = False
    for char in decoded:
        if char in _CONFUSABLES:
            ascii_version += _CONFUSABLES[char]
            has_confusable = True
        else:
            ascii_version += char

    if not has_confusable:
        return None

    # Outside Russian zones the last two labels, here and below, not
    # registrable_domain(): this function IS the model's is_homograph feature
    # (ml_features), and the served model learned this reading. So a look-alike
    # of a compound-suffix top name (xn--mazon-3ve.co.uk, 'аmazon.co.uk') is
    # not caught yet; reading the registrable name needs a rule version like
    # TYPOSQUAT_RULE_VERSION and a retrain (measured 2026-10-27: it would add
    # the signal on 0 of 93,989 Majestic names under compound suffixes).
    # A brand family's own site (втб.рф) and verified same-shaped sites of
    # other owners are nobody's disguise, whatever script they are in.
    if (_ru_registrable_domain(decoded) or _extract_base_domain(decoded)) in _BRAND_LEGIT_DOMAINS:
        return None

    ascii_base = _extract_base_domain(ascii_version)
    if ascii_base in (TOP_DOMAINS if top_domains is None else top_domains):
        return ascii_base

    # A brand only when the look-alikes are IN the name and turn it into a
    # Latin one (раураl → paypal). The 'р' of the .рф TLD is Cyrillic, not a
    # disguise: втб.рф has no look-alike in its name, which maps to itself —
    # and to 'втб', VTB's own Cyrillic name on the target list, so VTB's own
    # domain came back 'dangerous 60' before this.
    decoded_name = _extract_base_domain(decoded).split(".")[0]
    ascii_name = ascii_base.split(".")[0]
    if ascii_name != decoded_name and ascii_name.isascii() and ascii_name in TYPOSQUAT_TARGETS:
        return TYPOSQUAT_TARGETS[ascii_name]

    return None


# ── Typosquatting v2 ──

# How long the registrable label has to be before it is compared at all:
# the shortest brands (aws, ups, n26). A 3-letter name is only compared for
# an EXACT match — the brand's own name under another TLD (dhl.top) or
# spelled with look-alike characters (up5, dh1). Edit distance means nothing
# there: every 3-letter string sits within two edits of some 3-letter brand
# — 'ako' (the Kemerovo region, ako.ru) is two substitutions from 'aws',
# 'spb' from 'ups', both 'caution' or worse in production on 2026-09-27.
_TYPOSQUAT_MIN_LABEL = 3
# Swaps, doubled letters (dhll), hyphens, combos and multi-char glyphs from 4.
_SHAPE_MIN_LABEL = 4
# Edit-distance matches (substitutions, the similarity ratio) need a longer
# label still: 4-letter names are too dense — etsp.ru is one letter from
# 'etsy', ikar.ru two from 'ikea'. Exact look-alikes (1kea, ub3r) still count.
_FUZZY_MIN_LABEL = 5
# Below this length a name may differ from the brand in ONE position: two
# substitutions in seven letters (ngpedia → expedia) is a different word.
_TWO_EDIT_MIN_LABEL = 8


# Words a brand ends with that other names end with too. sberbank and
# swedbank differ only in 'sber' / 'swed', tbank and mbank in one letter,
# rustore and upstore in 'ru' / 'up': compared whole, every 'bank' and 'store'
# of the right length is a "typo" (tbank alone matched 55 of the Tranco
# 100k-1M names). When a name ends with the same word, only the parts before
# it are compared, under the same length rules as a whole name: 'sber',
# 'alfa', 't' and 'ru' get look-alikes and shapes only (altabank and oberbank
# are other banks), 'gazprom' and 'sovcom' one edit. A typo INSIDE the word
# (sberbamk, tbamk) leaves a name that no longer ends with it, and that name
# is compared whole, as before.
_GENERIC_TAILS: tuple[str, ...] = ("bank", "store", "банк")


def _generic_tail(name: str, brand: str) -> int:
    """Length of a _GENERIC_TAILS word both end with, each with letters
    before it; 0 when there is none."""
    for tail in _GENERIC_TAILS:
        if name.endswith(tail) and brand.endswith(tail) and len(name) > len(tail) and len(brand) > len(tail):
            return len(tail)
    return 0


def _edit_distance_at_most(a: str, b: str, limit: int) -> bool:
    """True when a becomes b in at most `limit` single-letter insertions,
    deletions, substitutions or swaps of neighbours (optimal string
    alignment distance)."""
    if abs(len(a) - len(b)) > limit:
        return False
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return False
        prev2, prev = prev, cur
    return prev[-1] <= limit


# ── What counts as a slip of the hand ──
#
# Under 8 letters a Russian brand's name sits among ordinary Russian company
# names one letter away. Of the 1,322 registered .ru names one edit from a
# Russian brand on 2026-09-27, the rule flagged 1,081, and the live sites
# among them included megafox.ru (a fur factory), megason.ru (mattresses),
# tirkoff.ru (furniture repair), avico.ru, aviko.ru, avido.ru, avits.ru,
# beelink.ru and uralgib.ru. A typosquat is made the way a typo is: a key
# next to the right one (yandez, gazorombank), a letter that looks like it
# (sberbamk, timkoff), a vowel for a vowel (magafon), or the other Latin
# spelling of one Russian sound (sovkombank: к as k or c). A substitution that
# is none of these — n→x, f→s, t→c — makes another word. Under 8 letters a
# Russian name's substitution has to be a slip; insertions, omissions, swaps
# and doubled letters count as before, and so does everything from 8 letters
# and every global brand (their neighbourhoods have not been measured this
# way). scripts/eval_typo_variants.py measures random substitutions, so this
# shows there as lost 'substitution_1' variants.
_KEYBOARD_ROWS: tuple[tuple[str, ...], ...] = (
    ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
    ("йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю"),
)
_KEY_POSITIONS: Mapping[str, tuple[int, int, int]] = MappingProxyType({
    ch: (layout, row, col)
    for layout, rows in enumerate(_KEYBOARD_ROWS)
    for row, keys in enumerate(rows)
    for col, ch in enumerate(keys)
})
_VOWELS = frozenset("aeiouyаеёиоуыэюя")
# Letters that look alike in an address bar (i/l, m/n, u/v, c/e, b/d …), and
# the two Latin spellings of one Russian sound: к as c/k, с as s/c, з as z/s,
# й as j/y/i, х as h/x, ф/в as f/v.
_SIMILAR_LETTERS = frozenset(frozenset(pair) for pair in (
    "il", "ij", "lj", "mn", "uv", "vw", "ce", "bd", "pq", "gq",
    "ck", "cs", "sz", "iy", "jy", "hx", "fv",
    "шщ", "её", "ий", "ьъ",
))


def _keyboard_neighbours(a: str, b: str) -> bool:
    """a and b are next to each other on the same keyboard (QWERTY or
    ЙЦУКЕН), in a row or diagonally across the stagger."""
    pa, pb = _KEY_POSITIONS.get(a), _KEY_POSITIONS.get(b)
    if not pa or not pb or pa[0] != pb[0]:
        return False
    (_, row_a, col_a), (_, row_b, col_b) = pa, pb
    if row_a == row_b:
        return abs(col_a - col_b) == 1
    if abs(row_a - row_b) != 1:
        return False
    upper, lower = (col_a, col_b) if row_a < row_b else (col_b, col_a)
    return lower in (upper - 1, upper)


def _is_slip(typed: str, letter: str) -> bool:
    """`typed` where `letter` belongs is a slip, not another word: a
    look-alike, a similar letter, a vowel for a vowel, or a neighbouring key."""
    return (
        _imitates(typed, letter)
        or frozenset((typed, letter)) in _SIMILAR_LETTERS
        or (typed in _VOWELS and letter in _VOWELS)
        or _keyboard_neighbours(typed, letter)
    )


def _one_odd_substitution(name: str, brand: str) -> bool:
    """name differs from brand in exactly one position, and not by a slip."""
    if len(name) != len(brand):
        return False
    diffs = [(a, b) for a, b in zip(name, brand) if a != b]
    return len(diffs) == 1 and not _is_slip(*diffs[0])


class _NameRule(NamedTuple):
    """How one listed name is compared. _rule_for() builds it."""

    # Edit distance at all: substitutions and the similarity ratio (no_fuzzy
    # turns it off: ozon + a letter is ozone).
    fuzzy: bool = True
    # Under _TWO_EDIT_MIN_LABEL a substitution has to be a slip (_is_slip).
    slips_only: bool = False
    # The name glued to a generic word (paypalhelp, trybeeline, ozonweb).
    generic_combos: bool = True
    # A generic or country word counts only across a hyphen (mts-help, not
    # mtshelp); a lure keyword counts either way (dhllogin).
    hyphen_combos_only: bool = False
    # The name plus its own country (avito-ru, sberbankru).
    country_combos: bool = False
    # The name plus a Russian lure word (ru_lures), glued or among several
    # words: sberbank-bonus, ozonpriz, lk-gosuslugi, yandex-pay-login.
    lure_words: bool = False


_DEFAULT_NAME_RULE = _NameRule()


def _rule_for(name: str, at_home: bool = False) -> _NameRule:
    """How `name` is compared; `at_home` when the host is under a Russian TLD.

    Names under 4 letters (vk, mts, vtb, dhl, ups) combine with a generic
    word only across a hyphen: glued, they are other words — mtscom.ru makes
    food machinery, vkweb.ru is a web studio, thevk.net a blog, gomts.com
    and usemts.com other firms, and main already flagged dhlweb.com and
    upshelp.com. A lure keyword still counts glued (dhllogin). A shared name (see ru_brands) does not combine with generic
    words abroad either — thebeeline.ca is a Chicago cleaning firm,
    ozonweb.com a fashion magazine, trymegafon.com Megafon Productions,
    mts-team.com a Düsseldorf trainer — but under .ru the name means the
    Russian brand, and vtb-team.ru (a copy of VTB's page), theozon.ru (a
    log-in page) and tbankapp.ru ('T-Bank — Ввод ключа') are its imitators.
    Russian names get slips only under 8 letters, their country as a combo
    word (avito-ru.com), and Russian lure words (sberbank-bonus) under every
    TLD, shared names included. The global names added with a measured
    false-positive pass (MEASURED_GLOBAL_GROUPS) get slips only under 8
    letters too: one free substitution made nfinity.com, ufinity.jp,
    myway.com and comcash.com look-alikes of xfinity, mbway and comcast
    (docs/benchmarks/2026-10-05-global-brands.md)."""
    short = len(name) < _SHAPE_MIN_LABEL
    russian = name in _RU_NAMES and name not in GLOBAL_TYPOSQUAT_TARGETS
    if short:
        generic = not russian or at_home
    else:
        generic = name not in _SHARED_NAMES or at_home
    return _NameRule(
        fuzzy=name not in _NO_FUZZY,
        slips_only=russian or name in _MEASURED_GLOBAL_NAMES,
        generic_combos=generic,
        hyphen_combos_only=short,
        country_combos=russian,
        lure_words=russian,
    )


# Russian TLDs, in both spellings of the IDN ones: see _rule_for.
_RU_TLDS = frozenset({".ru", ".su", ".рф", ".xn--p1ai", ".рус", ".xn--p1acf"})
# Built once: _check_typosquatting_v2 looks every listed name's rule up.
_NAME_RULES: Mapping[str, _NameRule] = MappingProxyType({n: _rule_for(n) for n in TYPOSQUAT_TARGETS})
_NAME_RULES_AT_HOME: Mapping[str, _NameRule] = MappingProxyType(
    {n: _rule_for(n, at_home=True) for n in TYPOSQUAT_TARGETS}
)


# The definitions of the typosquat rule an ML model may have learned its
# is_typosquat feature from. model_meta.json records the one a model was
# trained on (feature_data.typosquat_rule, written by
# ml_features.feature_data_record; no record = 1), and ml_scorer gives the
# served model that rule's answer, as it gives it the data files it learned
# (ml_features.resolve_feature_data). The scorer's own signal is always the
# live rule.
#   1  until 2026-10-23: a combo needs the brand's own string, glued or
#      hyphened to one word (a global brand) or among several hyphenated
#      words with a Russian or English lure word (a Russian brand,
#      _check_lure_combo_v1).
#   2  2026-10-23: a look-alike spelling of the brand counts as the brand in
#      a combo (g00glemail, micr0soft-login, 5berbank-bonus), and a global
#      brand as one hyphenated word with an English lure keyword among the
#      others is a combo (outlook-de-login, apple-id-verify).
TYPOSQUAT_RULE_VERSION = 2


def _imitation(name: str, brand: str, rule: _NameRule = _DEFAULT_NAME_RULE,
               rule_version: int = TYPOSQUAT_RULE_VERSION) -> Optional[str]:
    """How `name` imitates `brand` (a different string), or None.

    Look-alike characters count as the letter they imitate at any length.
    Swaps, doubled letters, hyphens, combos and multi-char glyphs from
    _SHAPE_MIN_LABEL. Edit distance — one substitution, the similarity ratio
    — from _FUZZY_MIN_LABEL, and not at all when `rule.fuzzy` is False. Two
    edits only when both are _TWO_EDIT_MIN_LABEL long. `rule` (see
    _rule_for) narrows combos and substitutions for some names.
    `rule_version`: see TYPOSQUAT_RULE_VERSION.
    """
    tail = _generic_tail(name, brand)
    if tail:
        if "-" in name and name.replace("-", "") == brand:
            return "hyphen injection"
        if _check_combosquat(name, brand, rule, rule_version):
            return "combosquatting"
        # `slips_only` is about names under 8 letters; gazprombank's stem is
        # short, the name is not.
        if min(len(name), len(brand)) >= _TWO_EDIT_MIN_LABEL:
            rule = rule._replace(slips_only=False)
        return _imitation(name[:-tail].rstrip("-"), brand[:-tail], rule, rule_version)

    # Character substitution
    if _check_char_substitution(name, brand, rule.fuzzy, rule.slips_only):
        return "character substitution"

    if len(name) < _SHAPE_MIN_LABEL:
        return None

    # Multi-char ASCII glyph homoglyph (rn->m, vv->w, cl->d) — #1 tactic,
    # not covered by single-char subs or Levenshtein<=2. When a glyph
    # substitution actually happened (skel != name), the corruption itself
    # signals intent, so we look past an exact match to the brand surfacing
    # as a delimited label (rnicrosoft-login), a combosquat, or a close
    # variant (rnicrosofts). The len(brand)>=6 guard prevents the short-name
    # over-collapse that false-matched legit domains (clax->wix, clara->...).
    # >=5 verified to add zero FPs on 20k legit while catching 5-char targets
    # (gmail, apple, yahoo, venmo, zelle).
    skel = _glyph_skeleton(name)
    if skel != name:
        if skel == brand:
            return "glyph homoglyph"
        if len(brand) >= 5 and (
            brand in re.split(r"[-.]", skel)
            or _check_combosquat(skel, brand, rule, rule_version)
            or SequenceMatcher(None, skel, brand).ratio() >= 0.90
        ):
            return "glyph homoglyph"

    # Transposition
    if _check_transposition(name, brand):
        return "character swap"

    # Hyphen injection
    if name.replace("-", "") == brand and "-" in name:
        return "hyphen injection"

    # Combosquatting
    if _check_combosquat(name, brand, rule, rule_version):
        return "combosquatting"
    # ...with the brand in look-alike characters: g00glemail, micr0soft-login,
    # secure-paypa1. The look-alike test above needs the brand's length, the
    # combo test the brand's string; neither read these until 2026-10-23.
    spelled = _with_brand_spelled_out(name, brand) if rule_version >= 2 else None
    if spelled and _check_combosquat(spelled, brand, rule, rule_version):
        return "combosquatting"

    # SequenceMatcher fallback. The ratio alone let two edits through at any
    # length — aviator ~ avito, kontakt ~ vkontakte, rutor ~ rustore — which
    # _TWO_EDIT_MIN_LABEL forbids for substitutions; the edit budget holds it
    # to the same rule, and a substitution it lets through to `slips_only`.
    if rule.fuzzy and len(name) >= _FUZZY_MIN_LABEL and SequenceMatcher(None, name, brand).ratio() >= 0.82:
        two_edits = min(len(name), len(brand)) >= _TWO_EDIT_MIN_LABEL
        if _edit_distance_at_most(name, brand, 2 if two_edits else 1) and not (
            rule.slips_only and not two_edits and _one_odd_substitution(name, brand)
        ):
            return "high similarity"

    # One letter typed twice — what the ratio above catches from 5
    # letters, for the 3-letter brands (dhll, upss).
    if _check_doubled_letter(name, brand):
        return "doubled letter"

    return None


# Zones sold like TLDs whose first label is the Russian ccTLD: a name
# registered under ru.com reads as the brand's .ru address with '.com'
# appended (yandex.ru.com, behind a Cloudflare phishing interstitial on
# 2026-09-27). Both are PSL private suffixes, in public_suffixes_in_top.json.
_RU_LOOKALIKE_ZONES = frozenset({"ru.com", "ru.net"})

# TLDs phishing favours, where a shared name (see ru_brands) is still
# reported as TLD confusion: the scorer's own risk lists, and .pro, which F6
# found under 10% of phishing domains in H1 2026 (.shop 22%, .com 19%; .com
# is everyone's and stays out).
_LURE_TLDS: frozenset[str] = frozenset(HIGH_RISK_TLDS | MEDIUM_RISK_TLDS | {".pro"})


def _lookalike_zone_name(domain: str) -> Optional[str]:
    """'yandex.ru.com' for any host under a _RU_LOOKALIKE_ZONES zone, the
    name registered there plus the zone; None elsewhere."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _RU_LOOKALIKE_ZONES:
        return ".".join(parts[-3:])
    return None


def _check_typosquatting_v2(domain: str, rule_version: int = TYPOSQUAT_RULE_VERSION) -> Optional[tuple[str, str]]:
    # `rule_version`: an older definition, for a model trained on it (see
    # TYPOSQUAT_RULE_VERSION); everything else reads the live rule.
    #
    # Under a Russian public suffix, the REGISTRABLE label — never the zone
    # label ('spb' of kvs.gov.spb.ru was "ups", 'nov' of adm.nov.ru "n26").
    # Under ru.com / ru.net, the name registered there ('yandex' of
    # yandex.ru.com, which was read as 'ru').
    # Elsewhere the last two labels, as before: on a compound ccTLD that is
    # the zone label ('co' of co.uk), too short to match anything, so
    # paypa1.co.uk goes uncaught. Comparing the real label there is right in
    # principle, and since 2026-10-27 the allowlist reaches compound-suffix
    # top names (top_domain_key), which absorbs the top-100k hits it makes on
    # the server (23 of the 10,645 compound-ccTLD names that day:
    # telegraph.co.uk → "telegram", paypay.ne.jp → "paypal"). It is still a
    # rule change of its own: the served model reads rule 2 (it needs
    # TYPOSQUAT_RULE_VERSION 3), the extension's offline port has no allowlist
    # (name-rules.js typosquat would put those 23 at 'caution'), and
    # _check_brand_on_hosting_tenant, lookalike_generator.comparison_base and
    # eval_typo_variants read this same base.
    zone_name = _lookalike_zone_name(domain)
    base = zone_name or _ru_registrable_domain(domain) or _extract_base_domain(domain)
    # A brand family's own site, or a verified site of another owner with the
    # same shape (data/typosquat_targets_ru.json), imitates no one.
    if base in _BRAND_LEGIT_DOMAINS:
        return None
    name = base.split(".")[0].lower()
    # A brand's own .ru address with .com after it: yandex.ru.com,
    # mail.ru.com, vk.ru.com (vk: too short for the rest of the rule). Reported
    # when the name imitates no brand itself — yandx.ru is Yandex's typo
    # registration, and yandx.ru.com a typo of yandex.ru.
    zone_site = (f"{name}.ru", "TLD confusion") if zone_name and f"{name}.ru" in _BRAND_OFFICIAL_DOMAINS else None
    if len(name) < _TYPOSQUAT_MIN_LABEL:
        return zone_site
    tld = _extract_tld(domain)
    # TLD confusion is the brand's own name directly under another TLD
    # (paypal.co). A brand name registered under a Russian zone
    # (paypal.spb.ru) was — and still is — brand_subdomain_abuse's to report:
    # that check reads spb.ru as the registrable domain.
    directly_under_tld = base.count(".") == 1
    rules = _NAME_RULES_AT_HOME if tld in _RU_TLDS else _NAME_RULES

    for brand, legit_domain in TYPOSQUAT_TARGETS.items():
        if domain == legit_domain or base == legit_domain:
            continue
        if name in _BRAND_NOT_TYPOS.get(brand, ()):
            continue

        if name == brand:
            # TLD confusion (paypal.co vs paypal.com). A shared name under a
            # country's or a legacy TLD is someone's own name (ozon.pl is a
            # cloud provider, tbank.com a Dallas bank); under a TLD phishing
            # favours it is still reported (ozon.shop, vtb.top).
            legit_tld = _extract_tld(legit_domain)
            if directly_under_tld and tld != legit_tld and (brand not in _SHARED_NAMES or tld in _LURE_TLDS):
                return (legit_domain, "TLD confusion")
            continue

        method = _imitation(name, brand, rules.get(brand, _DEFAULT_NAME_RULE), rule_version)
        if method:
            return (legit_domain, method)

    return zone_site


def _imitates(ch: str, letter: str) -> bool:
    """ch is the letter, or a look-alike of it: a digit (paypa1) or a
    Unicode confusable (the Cyrillic 'р' and 'а' of раypal)."""
    return ch == letter or letter in _CHAR_SUBS.get(ch, "") or _CONFUSABLES.get(ch) == letter


def _check_char_substitution(s1: str, s2: str, fuzzy: bool = True, slips_only: bool = False) -> bool:
    if len(s1) != len(s2):
        return False
    # Look-alike characters read as the letter they imitate: they are the
    # attack, not a difference. Compared position by position, so a brand's
    # own digits (office365) stay digits.
    diffs = [(a, b) for a, b in zip(s1, s2) if not _imitates(a, b)]
    if len(s1) < _FUZZY_MIN_LABEL or not fuzzy:
        return not diffs
    if len(s1) >= _TWO_EDIT_MIN_LABEL:
        return len(diffs) <= 2
    return not diffs or (len(diffs) == 1 and (not slips_only or _is_slip(*diffs[0])))


def _check_doubled_letter(s1: str, s2: str) -> bool:
    """s1 is s2 with one of its letters typed twice."""
    if len(s1) != len(s2) + 1:
        return False
    return any(s1[i] == s1[i + 1] and s1[:i] + s1[i + 1:] == s2 for i in range(len(s1) - 1))


def _check_transposition(s1: str, s2: str) -> bool:
    if len(s1) != len(s2):
        return False
    for i in range(len(s2) - 1):
        swapped = s2[:i] + s2[i + 1] + s2[i] + s2[i + 2:]
        if s1 == swapped:
            return True
    return False


_COMBO_GENERIC_SUFFIXES = frozenset({"com", "net", "org", "official", "support", "help", "app", "web", "mail", "team"})
_COMBO_GENERIC_PREFIXES = frozenset({"my", "the", "get", "go", "try", "use", "new", "real", "true"})
# A Russian brand's name with its country after it reads as its .ru address:
# avito-ru.com, ozon-ru.com, sberbank-ru.com (missed until 2026-09-27).
_COMBO_COUNTRY_SUFFIXES = frozenset({"ru", "rus", "rf", "russia"})


def _combo_parts(name: str, brand: str) -> list[tuple[str, bool, bool]]:
    """(word, hyphenated, word_is_after_brand) for each way `name` is
    `brand` with a word before or after it."""
    parts = []
    if len(name) > len(brand) and name.startswith(brand):
        rest = name[len(brand):]
        parts.append((rest.lstrip("-"), rest.startswith("-"), True))
    if len(name) > len(brand) and name.endswith(brand):
        rest = name[: len(name) - len(brand)]
        parts.append((rest.rstrip("-"), rest.endswith("-"), False))
    return parts


def _check_combosquat(name: str, brand: str, rule: _NameRule = _DEFAULT_NAME_RULE,
                      rule_version: int = TYPOSQUAT_RULE_VERSION) -> bool:
    for word, hyphenated, after in _combo_parts(name, brand):
        if word in _COMBOSQUAT_KEYWORDS:
            return True
        if rule.hyphen_combos_only and not hyphenated:
            continue
        if rule.generic_combos and word in (_COMBO_GENERIC_SUFFIXES if after else _COMBO_GENERIC_PREFIXES):
            return True
        if rule.country_combos and after and word in _COMBO_COUNTRY_SUFFIXES:
            return True
    if rule_version < 2:
        return rule.lure_words and _check_lure_combo_v1(name, brand)
    return _check_lure_combo(name, brand, rule)


# A brand spelled in look-alike characters counts as the brand in a combo
# from this length: g00gle, micr0soft, paypa1, 0zon. Shorter, a digit makes
# another word — '72' is t2 in digits and '0k' is ok, but 72-bonus and
# 0k-shop are someone else's names.
_LOOKALIKE_COMBO_MIN = _SHAPE_MIN_LABEL


def _spells_brand(word: str, brand: str) -> bool:
    """`word` is `brand` written with look-alike characters: as long as it,
    every character the letter or a look-alike of it (_imitates), at least
    one of them a look-alike, and the brand _LOOKALIKE_COMBO_MIN long."""
    return (
        len(word) == len(brand) >= _LOOKALIKE_COMBO_MIN and word != brand
        and all(_imitates(a, b) for a, b in zip(word, brand))
    )


def _with_brand_spelled_out(name: str, brand: str) -> Optional[str]:
    """`name` with a look-alike spelling of `brand` at its start or end
    written as the brand (g00glemail → googlemail, secure-paypa1 →
    secure-paypal), or None when it has none."""
    n = len(brand)
    if len(name) > n:
        if _spells_brand(name[:n], brand):
            return brand + name[n:]
        if _spells_brand(name[-n:], brand):
            return name[:-n] + brand
    return None


def _is_brand_word(word: str, brand: str, rule: Optional[_NameRule]) -> bool:
    """One hyphenated word that stands for the brand: the brand, the brand
    in look-alike characters (5berbank, micr0soft), or — where `rule` allows
    glued generic combos — the brand glued to a generic word (googlemail,
    mypaypal)."""
    if word == brand or _spells_brand(word, brand):
        return True
    if rule is None or not rule.generic_combos or rule.hyphen_combos_only:
        return False
    return any(part in (_COMBO_GENERIC_SUFFIXES if after else _COMBO_GENERIC_PREFIXES)
               for part, _hyphenated, after in _combo_parts(word, brand))


def _is_lure_word(word: str, brand: str) -> bool:
    """An English lure keyword (login), a Russian one in any spelling
    (бонус, bonusy, doctavka: see ru_lures), or one that lures next to this
    brand alone (sberbank-online)."""
    return (
        word in _COMBOSQUAT_KEYWORDS
        or ru_lures.is_lure(word)
        or ru_lures.skeleton(word) in _BRAND_LURE_WORDS.get(brand, ())
    )


# Keywords that are no lure next to one brand in the combos of several words
# or a word glued to the brand (_check_lure_combo). 'Secure booking' is what
# hotel and airport booking engines call their checkout: of the six names
# the 2026-10-23 combos added on the licensed 1M ranking, four were booking
# engines (secure-direct-hotel-booking.com, rank 216,459, which went to
# 'dangerous'; securebooking-belfastairport.com, Belfast International
# Airport's parking and fast-track, run by Rezcomm; secure-booking-engine.com,
# Djubo's hotel sales platform; secure-hotel-booking.com, allowlisted), and
# live unranked ones read the same (hotel-booking-secure.net,
# secure-online-booking.com). The brand and that one word stay a combo, as
# they were before (securebooking.com, secure-booking.com: _check_combosquat),
# and any other lure among the words still counts (booking-secure-login,
# secure-booking-verify).
_NOT_LURE_NEXT_TO: Mapping[str, frozenset[str]] = MappingProxyType({
    "booking": frozenset({"secure"}),
})


def _check_lure_combo(name: str, brand: str, rule: Optional[_NameRule] = None) -> bool:
    """`name` is `brand` and a lure word: glued to it (ozonpriz, lkgosuslugi)
    or among the hyphenated words around it (sberbank-bonus, lk-gosuslugi,
    yandex-pay-login, vk-login-verify, госуслуги-лк). The brand has to be one
    whole word (_is_brand_word): vkusvill-bonus is VkusVill's, not VK's.

    The lure words: Russian and English (_is_lure_word) for a name whose rule
    has lure_words, or with no rule (the Russian names' callers); the
    English keywords alone (_COMBOSQUAT_KEYWORDS) for every other name —
    outlook-de-login, paypal-secure-login, apple-id-verify, which the global
    names' one-word combo test read as 'de-login' and missed until
    2026-10-23. A keyword written with a hyphen (sign-in, log-in) counts as
    one word. _NOT_LURE_NEXT_TO takes a word out next to its brand."""
    russian = rule is None or rule.lure_words
    not_lures = _NOT_LURE_NEXT_TO.get(brand, frozenset())

    def is_lure(word: str) -> bool:
        if word in not_lures:
            return False
        return _is_lure_word(word, brand) if russian else word in _COMBOSQUAT_KEYWORDS

    words = name.split("-")
    for i, word in enumerate(words):
        if _is_brand_word(word, brand, rule):
            others = words[:i] + words[i + 1:]
            pairs = [f"{a}-{b}" for k, (a, b) in enumerate(zip(words, words[1:])) if i not in (k, k + 1)]
            if any(is_lure(w) for w in others + pairs):
                return True
        if len(word) > len(brand):
            spelled = _with_brand_spelled_out(word, brand) or word
            glued = (spelled[len(brand):] if spelled.startswith(brand)
                     else spelled[:-len(brand)] if spelled.endswith(brand) else "")
            if glued and is_lure(glued):
                return True
    return False


def _check_lure_combo_v1(name: str, brand: str) -> bool:
    """_check_lure_combo as typosquat rule 1 had it (TYPOSQUAT_RULE_VERSION),
    for a model that learned is_typosquat from it: the brand's own string as
    one whole hyphenated word or glued, next to a Russian or English lure
    word. Delete it with the last model_meta.json that records rule 1 (or
    none)."""
    words = name.split("-")
    for i, word in enumerate(words):
        if word == brand:
            if any(_is_lure_word(w, brand) for w in words[:i] + words[i + 1:]):
                return True
        elif len(word) > len(brand):
            glued = word[len(brand):] if word.startswith(brand) else word[:-len(brand)] if word.endswith(brand) else ""
            if glued and _is_lure_word(glued, brand):
                return True
    return False


# ── Brand subdomain abuse ──

def _check_brand_in_subdomain(domain: str) -> Optional[str]:
    dom = domain.lower().strip(".")
    # The compound-ccTLD heuristic, not registrable_domain(): this is the
    # model's brand_in_subdomain feature as well as the +30 rule, and its
    # input stays the one the model learned (legacy_registrable_domain says
    # why). On the PSL's reading the rule would also lose 23 feed phishing
    # hosts of 2026-10-24 (accounts.google.sn.cn, allegro.gsm.pl: under the
    # ICANN suffixes sn.cn and gsm.pl the brand becomes the registered
    # name, which the typosquat rule's last-two-labels base does not reach).
    reg = heuristic_registrable_domain(dom)
    # Only labels strictly BEFORE the registrable domain are real subdomains.
    # Naive parts[:-2] misfires on multi-part suffixes (barclays.co.uk would
    # treat "barclays" as a spoof subdomain).
    if not reg or dom == reg:
        return None
    sub = dom[: -(len(reg) + 1)]
    # The global brands only (GLOBAL_TYPOSQUAT_TARGETS explains why); Russian
    # ones are checked under open Russian zones by _check_brand_under_open_zone.
    for part in sub.split("."):
        part_clean = part.replace("-", "")
        if part_clean in GLOBAL_TYPOSQUAT_TARGETS and reg != GLOBAL_TYPOSQUAT_TARGETS[part_clean]:
            return part_clean
    return None


# Products companies run on their own servers under the product's name:
# gitlab.tcsbank.ru, jira.rambler-co.ru, confluence.vk.team. As a whole
# subdomain label of a registrable domain in the top 1M, the name says which
# tool the company runs, not whose site it is. Until 2026-10-23 Tranco's top
# 100k allowlisted most such parents; with the licensed list ~95 of these
# hosts in CrUX Russia's top 50,000 drew brand_subdomain_abuse (+30) and 19
# went 'dangerous' (verifier, 2026-10-23).
_SELF_HOSTED_PRODUCTS = frozenset({"gitlab", "jira", "confluence", "bitbucket"})


def _is_self_hosted_product(domain: str, brand: str, signals: dict) -> bool:
    """`brand` is a self-hosted product, it is a whole subdomain label of
    `domain` (gitlab.x.ru, not gitlab-login.x.ru) and the registrable domain
    is in the top 1M (signals: tranco_registrable_rank) — and it is the
    owner's own: on a hosting platform the registrable is the platform's
    (bitbucket.<account>.workers.dev), whose rank says nothing about who
    named the Worker (_platform_tenant_site)."""
    if brand not in _SELF_HOSTED_PRODUCTS or _platform_tenant_site(domain):
        return False
    rank = signals.get("tranco_registrable_rank")
    if not (isinstance(rank, int) and 0 < rank <= 1_000_000):
        return False
    reg = registrable_domain(domain)
    labels = domain[: -(len(reg) + 1)].split(".") if domain.endswith("." + reg) else []
    return brand in labels


# Russian brands for ONE narrow check: the brand's name bought under an open
# Russian zone (see _RU_RESTRICTED_ZONES), where a reader takes spb.ru or
# nov.ru for the site and the brand for a section of it. The CT log for
# nov.ru alone lists vk.nov.ru, mts.nov.ru, ok.nov.ru and kinopoisk.nov.ru.
# Separate from the typosquat targets: vk, ok and t2 are too short to be
# compared there, and a name bought as-is needs no edit distance. The Latin
# names of data/typosquat_targets_ru.json are here too. None of the Tranco
# top-1M names under a Russian zone (40) matches.
_RU_ZONE_BRANDS = frozenset({
    "sber", "sberbank", "gosuslugi", "tinkoff", "tbank", "vtb", "alfabank",
    "ozon", "wildberries", "avito", "mts", "tele2", "t2", "yandex", "vk",
    "ok", "kinopoisk", "mailru",
    "uralsib", "gazprombank", "pochtabank", "sovcombank", "beeline", "megafon",
    "cdek", "russianpost", "rustore", "vkontakte", "odnoklassniki",
})
# Shorter brands match only as a whole label or a hyphenated keyword combo
# (vk-login): as one part of a name (ok-stroy) or glued to a word (gook) they
# are too common.
_RU_ZONE_BRAND_PART_MIN = 4
# A keyword combo there is an English or a Russian lure word (vk-login,
# mts-bonus, ok-podarok): see ru_lures.
_ZONE_NAME_RULE = _NameRule(lure_words=True)
_RU_ZONE_BRANDS_LONGEST_FIRST = tuple(sorted(_RU_ZONE_BRANDS, key=lambda b: (-len(b), b)))
# Brands looked for in a hosting customer's name: the Russian ones above and
# the global typosquat targets, longest first (sberbank before sber).
_HOSTING_TENANT_BRANDS = tuple(sorted(_RU_ZONE_BRANDS | set(GLOBAL_TYPOSQUAT_TARGETS), key=lambda b: (-len(b), b)))
# Zones only a licensed bank may register in: sber.bank.in is Sberbank's
# Indian branch, not a customer of a hosting platform.
_REGISTRY_ONLY_ZONES = frozenset({"bank.in"})


def _check_brand_under_open_zone(domain: str) -> Optional[str]:
    """A Russian brand in any label left of an open Russian zone — as the
    whole label (sberbank.spb.ru, v-k.nov.ru), one hyphen-separated part of
    it (gosuslugi-lk.spb.ru) or a keyword combo (vk-login.nov.ru). None
    under restricted zones, REGIONAL_GOVERNMENT_DOMAINS and anywhere else."""
    parts = (domain or "").lower().strip(".").split(".")
    ascii_parts = [_ascii_label(p) for p in parts]
    k = _ru_suffix_length(ascii_parts)
    if not k or k == len(parts) or ".".join(ascii_parts[-k:]) in _RU_RESTRICTED_ZONES:
        return None
    if is_regional_government_domain(domain):
        return None
    # A name data/typosquat_targets_ru.json lists as the brand's own or as
    # another owner's. Dealers and partners are not listed: 'официальный
    # партнёр' on a page is the site's own claim, and lead-generation and
    # scam pages make it too (cdek.msk.ru, beeline.com.ru stay caution).
    if ".".join(parts[-(k + 1):]) in _BRAND_LEGIT_DOMAINS:
        return None
    for label in parts[:-k]:
        whole = label.replace("-", "")
        if whole in _RU_ZONE_BRANDS:
            return whole
        pieces = label.split("-")
        for brand in _RU_ZONE_BRANDS_LONGEST_FIRST:
            if len(brand) >= _RU_ZONE_BRAND_PART_MIN:
                if brand in pieces or _check_combosquat(label, brand, _ZONE_NAME_RULE):
                    return brand
            elif brand in pieces and _check_combosquat(label, brand, _ZONE_NAME_RULE):
                return brand
    return None


def _check_brand_on_hosting_tenant(domain: str) -> Optional[str]:
    """A brand in the name a customer gave its site on a hosting platform:
    sberbank-online.pages.dev, gosuslugi-vhod.netlify.app,
    paypal-login.netlify.app, sberbank.tw1.ru.

    The typosquat rule reads the registrable domain, which for these hosts is
    the platform (pages.dev), so the customer's own name was never compared.
    Fresh phishing lives exactly here (docs/EVALUATION_2026-10.md §1.2), and
    so do student clones and fan pages (netflix-clone.vercel.app,
    sber-hackathon.github.io). So the rule is narrow: a Russian brand of four
    letters or more as the whole name, or any brand next to a lure word — an
    English combo keyword or a Russian lure (ru_lures), hyphenated, or glued
    for brands of four letters or more. The brand may be written in
    look-alike characters, as in a registered name (_spells_brand:
    paypa1-login.ngrok-free.app, 5berbank-bonus.pages.dev; since
    2026-10-23). Russian zones (spb.ru) are _check_brand_under_open_zone's;
    a name directly under a country's zone (paypal-login.com.br) is the
    typosquat rule's."""
    from api.services.hosting_platforms import tenant_suffix_of

    d = (domain or "").lower().strip(".")
    suffix = tenant_suffix_of(d, _SCORER_SHARED_SUFFIXES)
    if not suffix or suffix in RU_PUBLIC_SUFFIXES or suffix in _RU_RESTRICTED_ZONES:
        return None
    # ru.com / ru.net names are the typosquat rule's (yandex.ru.com), and a
    # registry zone only banks may register in is not a hosting platform.
    if suffix in _RU_LOOKALIKE_ZONES or suffix in _REGISTRY_ONLY_ZONES:
        return None
    # The typosquat rule's own base (last two labels), not registrable_domain():
    # this rule covers exactly the hosts where that base is the platform. For
    # com.de, com.se and biz.ua tenants the two readings differ, and a base the
    # typosquat rule does not use would drop them from both rules.
    base = _extract_base_domain(d)
    # Only where the typosquat rule read the platform, not the customer's name.
    if not (suffix == base or suffix.endswith("." + base)):
        return None
    if d in _BRAND_LEGIT_DOMAINS:
        return None
    for label in d[: -(len(suffix) + 1)].split("."):
        whole = label.replace("-", "")
        if len(whole) >= _RU_ZONE_BRAND_PART_MIN and whole in _RU_ZONE_BRANDS:
            return whole
        words = label.split("-")
        # Two-word lures written with a hyphen: sign-in, log-in.
        pairs = [a + b for a, b in zip(words, words[1:])]
        for brand in _HOSTING_TENANT_BRANDS:
            named = [w for w in words if w == brand or _spells_brand(w, brand)]
            if named:
                if any(_is_tenant_lure(w, brand) for w in words + pairs if w not in named):
                    return brand
            elif len(brand) >= _RU_ZONE_BRAND_PART_MIN:
                for w in words:
                    w = _with_brand_spelled_out(w, brand) or w
                    glued = w[len(brand):] if w.startswith(brand) else w[: -len(brand)] if w.endswith(brand) else ""
                    if glued and glued != w and _is_tenant_lure(glued, brand):
                        return brand
    return None


# Brands looked for as a whole word of a hosting customer's own name by
# _tenant_brand_word: the global typosquat targets and the Russian brands of
# four letters or more (vk, ok, mts are words of too many names).
_TENANT_BRAND_WORDS = frozenset(
    set(GLOBAL_TYPOSQUAT_TARGETS) | {b for b in _RU_ZONE_BRANDS if len(b) >= _RU_ZONE_BRAND_PART_MIN})


def _tenant_brand_word(domain: str) -> Optional[str]:
    """A brand (_TENANT_BRAND_WORDS) as one word, between hyphens or
    underscores, of the labels a hosting or dynamic-DNS customer chose
    (_platform_tenant_site): coinbase-com-08739.lclarkpz.workers.dev,
    dashboard.booking-com-waedubai-hotels.webflow.io — else None, also for
    registered names, whose brand rules read the whole name.

    calculate_score lets such a host's weak signals add up past caution
    (WEAK_SIGNALS). The brand rules miss these names: the brand is no whole
    label (_check_brand_in_subdomain) and has no lure word beside it
    (_check_brand_on_hosting_tenant). Measured 2026-10-26 on fresh phishing
    the weak-signal cap held at caution 50: it gives back 5 of the 18
    hosting-tenant subdomains probed live and 7 of the 55 in the address-only
    samples of four licensed feeds and Phishing.Database (six of these on
    booking-com*.webflow.io). On real sites it made nothing 'dangerous': not
    one of the 44 hosting customers with a brand word and real Chrome
    traffic (CrUX global, probed live) nor of the 119,306 in the
    address-only sets."""
    d = (domain or "").lower().strip(".")
    site = _platform_tenant_site(d)
    if not site:
        return None
    suffix = site.split(".", 1)[1]
    for label in d[: -(len(suffix) + 1)].split("."):
        for word in label.replace("_", "-").split("-"):
            if word in _TENANT_BRAND_WORDS:
                return word
    return None


# Lure words a site builder's free name carries that a brand's own campaign
# page or a fan page does not: facebook-supports.blogspot.com,
# gmail-support.netlify.app, facebook-new-security.blogspot.com (OpenPhish /
# phishunt, 2026-10-15). Only next to a brand, only on a hosting tenant.
_TENANT_EXTRA_LURES = frozenset({"support", "supports", "security", "helpdesk", "customer"})
# English lure words long enough to be read as the START of a glued run:
# facebookloginuser, facebookloginguidance, instagramverifyaccount.
_TENANT_GLUED_LURES = tuple(sorted((w for w in _COMBOSQUAT_KEYWORDS | _TENANT_EXTRA_LURES
                                    if len(w) >= 5 and "-" not in w), key=lambda w: (-len(w), w)))


def _is_tenant_lure(word: str, brand: str) -> bool:
    """_is_lure_word, as a hosting customer writes it: with a counter on the
    end (login0, login17, login99999 — free names are taken, so the kits
    number them), glued to more letters after it (loginuser), or one of
    _TENANT_EXTRA_LURES."""
    w = word.rstrip("0123456789")
    if not w:
        return False
    if _is_lure_word(w, brand) or w in _TENANT_EXTRA_LURES:
        return True
    return any(w.startswith(lure) for lure in _TENANT_GLUED_LURES)


# ── Suspicious keywords ──

# PSL ICANN zones whose names only a health service, a police force or a
# government network gets, though no restricted label says so.
_VETTED_ICANN_ZONES = frozenset({"nhs.uk", "police.uk", "nic.in"})


def _registered_in_vetted_zone(domain: str) -> bool:
    """The registrable domain sits in a zone only a government body, a health
    service or a police force registers in: a Russian restricted zone, or a
    zone the PSL's ICANN section lists with a restricted label (gov.uk,
    sa.gov.au, pi.gov.br, ac.uk) or on _VETTED_ICANN_ZONES. Not a zone that
    is a suffix only by the ccTLD default: sch.in, govt.hu and mil.nf carry a
    restricted label but are ChangeIP's and FreeDNS's free zones.

    With the PSL, login.nhs.uk's registered name is 'login' and every NHS
    trust site is an apex; the differential check of 2026-10-31 found the
    keyword and no-MX rules taking auth.login.nhs.uk, account.sa.gov.au,
    login.pi.gov.br and 17 trust sites without MX to caution, two NHS
    services to dangerous. Names there are not anyone's pick."""
    suffix = registrable_domain(domain).partition(".")[2]
    if not suffix:
        return False
    if suffix in _RU_RESTRICTED_ZONES:
        return True
    zone = ascii_name(suffix)
    if not is_icann_rule(zone):
        return False
    return zone in _VETTED_ICANN_ZONES or bool(_RESTRICTED_ZONE_LABELS.intersection(zone.split(".")))


def _check_suspicious_keywords(domain: str) -> Optional[str]:
    # The registered name. The last two labels were read until 2026-10-27:
    # 'co' of secure-login.co.uk and 'spb' of paypal-login.spb.ru, never a
    # keyword. Measured that day, name-only, on hosts outside the allowlist
    # that the two readings differ for: the word is newly found on 124 of
    # 21,561 feed hosts (alert-newlogin.co.uk, cba-secure.com.au; 11 go
    # safe→caution, 8 caution→dangerous) and on 91 of 214,671 Majestic
    # Million / Chrome UX Report hosts (6 caution→dangerous, the
    # vnpt-invoice.com.vn ones among them, before any popularity discount).
    if _registered_in_vetted_zone(domain):
        return None
    base = registrable_domain(domain)
    return _keyword_in_name(base.split(".")[0])


def _keyword_in_name(name: str) -> Optional[str]:
    """The first word of `name` (split at '-' and '_') on _SUSPICIOUS_KEYWORDS."""
    for part in name.lower().replace("_", "-").split("-"):
        if part in _SUSPICIOUS_KEYWORDS:
            return part
    return None
