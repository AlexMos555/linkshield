"""The phone's popular veto never cancels a tenant entry the publisher blocks.

The Android shield decides on the phone (BlockList.kt): a listed name is
dropped when its registrable is in assets/popular_veto.txt, unless the name
sits under a suffix of assets/shared_suffixes.txt — then it is one tenant's
site and the platform's popularity says nothing about it. The VPN resolves
upstream through public resolvers, so this veto has the last word.

#284 widened the publisher's shared set (the curated
data/hosting_platforms.json, dynamic DNS and UNRANKED_SHARED_DOMAINS) and the
phone's copy stayed the public suffixes plus a hand list: the publisher listed
evil-login.tilda.ws, x.blogspot.com.br, paypal-auth.godaddysites.com, DoH users
got NXDOMAIN, and the phone vetoed them because tilda.ws, blogspot.com.br and
godaddysites.com are top-10k — 66 zones in all (audit F1, 2026-10-25).

Copying the publisher's set took the veto off the platforms' own names under
those zones too, which main's phone had vetoed by the platform's rank:
GoDaddy's sign-in (login.secureserver.net) and shared cPanel servers,
Teachable's e-mail links, Thinkific's file CDN, Typeform's form host. A live
feed lists each of them once; DoH blocks them since #284 (review of #336). So
the publisher never lists them (data/hosting_platforms.json operator_zones and
operator_hosts, www.<zone>), and the phone keeps them under the veto: they
are the '!' lines of shared_suffixes.txt.

The port below follows BlockList.isVetoed and RegistrableDomain.of; the
Kotlin sets are read from the Kotlin source, because the Kotlin tests do not
run in CI (.github/workflows/ci.yml, job mobile).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_mobile_assets  # noqa: E402
import refresh_dangerous_domains as rdd  # noqa: E402

from api.services import hosting_platforms as hp  # noqa: E402

ANDROID = ROOT / "mobile" / "modules" / "cleanway-vpn" / "android" / "src" / "main"
ASSETS = ANDROID / "assets"
KOTLIN = (ANDROID / "java" / "ai" / "cleanway" / "app" / "BlockList.kt").read_text()


def _kotlin_set(name: str) -> frozenset[str]:
    body = re.search(rf"private val {name} = setOf\((.*?)\)", KOTLIN, re.S)
    assert body, f"{name} not found in BlockList.kt"
    return frozenset(re.findall(r'"([^"]+)"', body.group(1)))


COMPOUND = _kotlin_set("COMPOUND")
CCTLD_SLD = _kotlin_set("CCTLD_SLD")


def _asset(name: str) -> set[str]:
    """CleanwayVpnService.loadAsset: one name per line, '#' comments."""
    lines = (ASSETS / name).read_text().splitlines()
    return {s.strip().lower() for s in lines if s.strip() and not s.startswith("#")}


VETO = _asset("popular_veto.txt")
SHARED = {s for s in _asset("shared_suffixes.txt") if not s.startswith("!")}
PLATFORM_OWN = {s[1:] for s in _asset("shared_suffixes.txt") if s.startswith("!")}


def _registrable(host: str) -> str:
    """RegistrableDomain.of."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in COMPOUND:
        return ".".join(parts[-3:])
    if len(parts[-1]) == 2 and parts[-2] in CCTLD_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _tenant_suffix(name: str) -> str | None:
    """BlockList.tenantSuffixOf: the longest shared suffix strictly shorter than the name."""
    parts = name.split(".")
    for k in range(len(parts) - 1, 1, -1):
        suffix = ".".join(parts[-k:])
        if suffix in SHARED:
            return suffix
    return None


def _platform_own(name: str, suffix: str) -> bool:
    """BlockList.isPlatformOwn: www.<suffix>, or at or under a '!' line."""
    if name == "www." + suffix:
        return True
    parts = name.split(".")
    return any(".".join(parts[-k:]) in PLATFORM_OWN for k in range(len(parts), suffix.count(".") + 1, -1))


def phone_vetoes(name: str) -> bool:
    """BlockList.isVetoed."""
    suffix = _tenant_suffix(name)
    if suffix is not None and not _platform_own(name, suffix):
        return False
    return _registrable(name) in VETO


def test_the_port_reads_the_kotlin_sets():
    assert {"co.uk", "com.br", "com.tr"} <= COMPOUND
    assert {"com", "org", "net", "gov"} <= CCTLD_SLD


def test_the_phone_carries_the_publishers_shared_set():
    assert SHARED == rdd.default_shared_suffixes()
    assert {s for s in build_mobile_assets.build_shared() if not s.startswith("!")} == rdd.default_shared_suffixes()


def test_the_phone_carries_the_platforms_own_names():
    assert PLATFORM_OWN == hp.OPERATOR_HOSTS | hp.OPERATOR_ZONES
    for name in PLATFORM_OWN:
        # An exception to a tenant rule, so under a zone of the phone's set and not one itself.
        assert _tenant_suffix(name) is not None and name not in SHARED, name


@pytest.mark.parametrize("host", [
    "evil-login.tilda.ws", "secure-verify.blogspot.com.br", "konto-pl.webnode.page",
    "paypal-auth.godaddysites.com", "pochta-bonus.narod.ru", "wallet-sync.at.ua", "bank-login.ucoz.ru",
    "contoso-files.sharepoint.com", "a.b.mystrikingly.com",
])
def test_the_audit_examples_are_published_and_blocked_on_the_phone(host):
    assert rdd.build_blockset([host], rdd.load_popular_guard(), brand_owned=frozenset()) == {host}
    assert not phone_vetoes(host), host


def test_no_tenant_entry_the_publisher_blocks_is_vetoed_on_the_phone():
    shared = sorted(rdd.default_shared_suffixes())
    hosts = [f"evil-login.{zone}" for zone in shared]
    published = rdd.build_blockset(hosts, rdd.load_popular_guard(), brand_owned=frozenset())
    # Everything but the names under an operator's own suffix (x.storage.googleapis.com).
    assert len(published) > 0.9 * len(shared)
    assert sorted(h for h in published if phone_vetoes(h)) == []


def test_a_popular_organisations_own_name_is_still_vetoed():
    for host in ("paypal.com", "login.paypal.com", "tilda.ws", "tumblr.com", "netlify.com", "sharepoint.com"):
        assert phone_vetoes(host), host


def test_operator_infrastructure_is_vetoed_on_the_phone():
    """The publisher never lists a name under an operator's suffix (GitHub's
    media CDN was NXDOMAIN on 2026-08-19); the phone holds the same line, so a
    bad publish cannot darken it either."""
    names = set(build_mobile_assets.build_names())
    operator = sorted(z for z in rdd.OPERATOR_SUFFIXES if z in names)
    assert {"githubusercontent.com", "googleapis.com", "cloudfront.net"} <= set(operator)
    for zone in operator:
        assert zone not in SHARED, zone
        assert phone_vetoes(f"media.{zone}"), zone


@pytest.mark.parametrize("host", [
    "www.tumblr.com", "www.tilda.ws", "www.netlify.com", "app.netlify.com", "microsoft.sharepoint.com",
    "my.wpengine.com", "api.typeform.com", "email.secureserver.net", "www.blogspot.com.br", "www.duckdns.org",
])
def test_the_platforms_own_hosts_are_never_published(host):
    """www.<zone> and data/hosting_platforms.json operator_hosts are the
    platform's (hosting_platforms.tenant_suffix_of), not a customer's site: the
    publisher does not list them, and the phone vetoes them by the platform's
    rank, as main's phone did (duckdns.org is not top-10k, so there is no veto
    to keep)."""
    assert rdd.build_blockset([host], rdd.load_popular_guard(), brand_owned=frozenset()) == set()
    tenant = "evil-login." + host.split(".", 1)[1]
    assert rdd.build_blockset([tenant], rdd.load_popular_guard(), brand_owned=frozenset()) == {tenant}
    assert phone_vetoes(host) == (_registrable(host) in VETO)
    assert phone_vetoes(host) or host == "www.duckdns.org", host


# Platform-run names under the zones the phone took over, each listed in
# Phishing.Database ACTIVE (2026-10-24 snapshot) below SHARED_URL_THRESHOLD:
# GoDaddy's sign-in, its Nebula API and shared cPanel servers, Teachable's
# Mailgun click tracking and Leadpages site, Thinkific's file CDN, Typeform's
# form host and image CDN.
PLATFORM_RUN = [
    "login.secureserver.net", "cache.nebula.phx3.secureserver.net",
    "a2plcpnl0019.prod.iad2.secureserver.net", "a2plvcpnl348923.prod.iad2.secureserver.net",
    "n3plcpnl0019.prod.ams3.secureserver.net", "p3plcpnl0663.prod.phx3.secureserver.net",
    "email.m.teachable.com", "email.em.teachable.com", "pages.teachable.com",
    "files.cdn.thinkific.com", "form.typeform.com", "images.typeform.com",
]


@pytest.mark.parametrize("host", PLATFORM_RUN)
def test_a_platform_run_name_is_never_published_and_the_phone_vetoes_it(host):
    guard = rdd.load_popular_guard()
    assert rdd.build_blockset([host], guard) == set(), host
    assert rdd.build_blockset([host] * 3, guard, brand_owned=frozenset()) == set(), host
    # Retained (exact) or listed together with the zone above it: still nothing.
    zone = host.split(".", 1)[1]
    assert rdd.build_blockset([host], guard, exact_only=frozenset({host})) == set(), host
    if hp.is_operator_zone_name(zone):
        assert rdd.build_blockset([host, zone], guard) == set(), host
    # A bad publish (or an older list, or the APK's seed) still holds it: the
    # platform's rank vetoes it, as on main.
    assert phone_vetoes(host), host
    assert phone_vetoes(zone) or not hp.is_operator_zone_name(zone), zone


@pytest.mark.parametrize("host", [
    "exodus-help.teachable.com", "assurance2.thinkific.com", "admin318.typeform.com",
    "0.232.205.92.host.secureserver.net", "ip-107-180-2-159.ip.secureserver.net",
    "1295505.eu15.myftpupload.com",
])
def test_the_customers_next_to_them_are_still_published_and_blocked(host):
    """A school on Teachable, a form account on Typeform, a GoDaddy customer's
    own server (its reverse-DNS name): one tenant's, blocked exactly."""
    assert rdd.build_blockset([host], rdd.load_popular_guard(), brand_owned=frozenset()) == {host}
    assert not phone_vetoes(host), host
