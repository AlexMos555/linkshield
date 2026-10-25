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
    lines = (ASSETS / name).read_text().splitlines()
    return {s.strip().lower() for s in lines if s.strip() and not s.startswith("#")}


VETO = _asset("popular_veto.txt")
SHARED = _asset("shared_suffixes.txt")


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


def phone_vetoes(name: str) -> bool:
    """BlockList.isVetoed."""
    if _tenant_suffix(name) is not None:
        return False
    return _registrable(name) in VETO


def test_the_port_reads_the_kotlin_sets():
    assert {"co.uk", "com.br", "com.tr"} <= COMPOUND
    assert {"com", "org", "net", "gov"} <= CCTLD_SLD


def test_the_phone_carries_the_publishers_shared_set():
    assert SHARED == rdd.default_shared_suffixes()
    assert set(build_mobile_assets.build_shared()) == rdd.default_shared_suffixes()


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
    platform's (hosting_platforms.tenant_suffix_of), not a customer's site. The
    phone no longer vetoes them by the platform's rank, so the publisher must
    not list them."""
    assert rdd.build_blockset([host], rdd.load_popular_guard(), brand_owned=frozenset()) == set()
    tenant = "evil-login." + host.split(".", 1)[1]
    assert rdd.build_blockset([tenant], rdd.load_popular_guard(), brand_owned=frozenset()) == {tenant}
