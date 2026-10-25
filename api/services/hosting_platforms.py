"""Shared hosting / user-content platforms — curated in data/hosting_platforms.json.

A site on Timeweb (`abc.tw1.ru`), Weebly (`x.weeblysite.com`) or a Yandex form
(`forms.yandex.ru/u/<id>`) belongs to whoever made it, not to the platform. The
platform being popular therefore says nothing about the page, and the
"known legitimate → safe, 99%" short-circuit must not fire for it. It did, on
the live /public/check on 2026-09-25, for two tw1.ru phishing pages, a Weebly
one, a WordPress.com staging one and a ScreenConnect one — and for 2,885 of
41,889 active PhishTank URLs (6.9%).

Two shapes, two sets, and two exception lists:

  TENANT_SUFFIXES     every SUBDOMAIN is a separate customer's site; the apex
                      itself (tw1.ru) is still the platform's own name.
  USER_CONTENT_HOSTS  one hostname serves many users' pages at different paths;
                      the host (and anything under it) is never vouched for.
  OPERATOR_HOSTS      subdomains of a tenant suffix that the platform runs
                      itself (app.netlify.com is Netlify's dashboard, not a
                      customer's site). `www.<suffix>` is always the operator's.
  OPERATOR_ZONES      the same, but a whole subzone with every name under it
                      (prod.iad2.secureserver.net: GoDaddy's shared cPanel
                      servers), and never vouched for: several serve every
                      customer's pages at a path (form.typeform.com/to/<id>).
                      The blocklist never lists them and the platform's rank
                      counts for them; they stay tenants for tenant_suffix_of.

And OPERATOR_SUFFIXES, the opposite of a shared platform: suffixes where
every name is the operator's own (googleapis.com).

This module only answers "is this a shared platform?". What to do about it is
the caller's job (scoring.is_trusted_top_domain, the analyzer's informational
reason).
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger("cleanway.hosting_platforms")

_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "hosting_platforms.json"
)


def _flatten(groups: object) -> frozenset[str]:
    """A list, or a dict of named lists, as one lowercase set."""
    if isinstance(groups, dict):
        names = [n for group in groups.values() if isinstance(group, list) for n in group]
    elif isinstance(groups, list):
        names = list(groups)
    else:
        names = []
    return frozenset(
        n.strip().lower().strip(".") for n in names if isinstance(n, str) and n.strip()
    )


def _load(path: str = _DATA_PATH) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """(tenant suffixes, user-content hosts, operator hosts)."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        # Degrade to the scorer's hand list rather than failing import: a
        # missing file must not take the API down, only weaken this guard.
        logger.warning("hosting_platforms.json not loaded (%s) — hand list only", e)
        return frozenset(), frozenset(), frozenset()
    return (
        _flatten(data.get("tenant_suffixes")),
        _flatten(data.get("user_content_hosts")),
        _flatten(data.get("operator_hosts")),
    )


TENANT_SUFFIXES, USER_CONTENT_HOSTS, OPERATOR_HOSTS = _load()


def _load_dynamic_dns(path: str = _DATA_PATH) -> frozenset[str]:
    """Free dynamic-DNS services (duckdns.org, ipv64.de, ns01.info …), where a
    name costs nothing and points anywhere: the 'dynamic_dns_services' list
    plus the tenant_suffixes 'dynamic_dns' group. The scorer weighs a name
    there (dynamic_dns_host) and never trusts one as a top domain. The list is
    deliberately not a tenant suffix: those are ML model features."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return frozenset()
    groups = data.get("tenant_suffixes") or {}
    group = groups.get("dynamic_dns", []) if isinstance(groups, dict) else []
    return _flatten(data.get("dynamic_dns_services", [])) | _flatten(group)


DYNAMIC_DNS_SUFFIXES = _load_dynamic_dns()


def _load_operator_zones(path: str = _DATA_PATH) -> frozenset[str]:
    """The 'operator_zones' list (see OPERATOR_ZONES in the module docstring)."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return frozenset()
    return _flatten(data.get("operator_zones", []))


OPERATOR_ZONES = _load_operator_zones()

# Suffixes where EVERY label belongs to the platform operator — there are no
# tenants under them, only the operator's own infrastructure. The blocklist's
# tenant rule must never fire here: on 2026-08-19 it put
# media.githubusercontent.com (GitHub's own media CDN, one URLhaus entry) into
# production, so every phone and every DoH user got NXDOMAIN for it. Nor does
# the scorer read a name here as a hosting tenant: fonts.googleapis.com is in
# the sandbox report of every phishing kit that loads a Google font, and its
# registrable's rank is Google's. Here (stdlib only) so the API and
# scripts/blocklist_shared_zones.py read one list.
OPERATOR_SUFFIXES = frozenset({
    "githubusercontent.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "ggpht.com", "usercontent.goog", "withgoogle.com",
    "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net",
    "fbcdn.net", "cdninstagram.com", "licdn.com", "twimg.com",
    "wp.com", "gravatar.com", "shopifycdn.com", "cloudflarestorage.com",
    "linodeusercontent.com", "digitaloceanspaces.com", "oaiusercontent.com",
})


def _clean(domain: str) -> str:
    return (domain or "").lower().strip(".")


def is_user_content_host(domain: str) -> bool:
    """True for a path-shared host (forms.yandex.ru) or any name under it."""
    d = _clean(domain)
    return any(d == h or d.endswith("." + h) for h in USER_CONTENT_HOSTS)


def is_user_content_service(domain: str) -> bool:
    """True for the service host ITSELF (disk.yandex.ru, onedrive.live.com).

    Its name belongs to the platform, so judging that name — brand in a
    subdomain, the ML model, typosquatting — judges Microsoft or Yandex, not
    the page someone published there. It put onedrive.live.com, gist.github.com
    and forms.office.com at 'dangerous' once they lost the allowlist. The
    public check only sees the host, so the one honest answer is "a real
    service; we cannot vouch for the page" (verdict_basis.user_content_result).
    """
    return _clean(domain) in USER_CONTENT_HOSTS


def is_operator_zone_name(domain: str) -> bool:
    """True for an OPERATOR_ZONES name or any name under it
    (email.m.teachable.com, a2plcpnl0019.prod.iad2.secureserver.net)."""
    d = _clean(domain)
    parts = d.split(".")
    return any(".".join(parts[i:]) in OPERATOR_ZONES for i in range(len(parts) - 1))


def _is_operator_host(domain: str, suffix: str) -> bool:
    return domain == "www." + suffix or domain in OPERATOR_HOSTS


def tenant_suffix_of(domain: str, extra_suffixes: frozenset[str] = frozenset()) -> str | None:
    """The shared suffix `domain` is a strict subdomain of, or None.

    Checks every proper suffix of at least two labels, longest first, so
    `a.b.my.canva.site` finds `my.canva.site`. `extra_suffixes` lets the scorer
    add its own hand list and the PSL-derived set without this module
    importing the scorer. The platform's own hosts (www.tumblr.com,
    app.netlify.com — see OPERATOR_HOSTS) are not tenants.
    """
    d = _clean(domain)
    parts = d.split(".")
    for k in range(len(parts) - 1, 1, -1):
        suffix = ".".join(parts[-k:])
        if suffix in TENANT_SUFFIXES or suffix in extra_suffixes:
            return None if _is_operator_host(d, suffix) else suffix
    return None


def dynamic_dns_suffix_of(domain: str) -> str | None:
    """The dynamic-DNS service `domain` is a name under (gedivan.duckdns.org →
    duckdns.org), or None — also for the service's own hosts (www.duckdns.org)."""
    d = _clean(domain)
    parts = d.split(".")
    for k in range(len(parts) - 1, 1, -1):
        suffix = ".".join(parts[-k:])
        if suffix in DYNAMIC_DNS_SUFFIXES:
            return None if _is_operator_host(d, suffix) else suffix
    return None


def is_shared_platform_site(domain: str, extra_suffixes: frozenset[str] = frozenset()) -> bool:
    """A tenant of a hosting platform, or a page on a user-content host."""
    return is_user_content_host(domain) or tenant_suffix_of(domain, extra_suffixes) is not None
