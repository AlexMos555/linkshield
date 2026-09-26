"""Hosting and user-content platforms never get the instant 'safe, 99%'.

On 2026-09-25 the live /public/check called five phishing pages "safe, 99%"
without analysing them: two on Timeweb (tw1.ru), one each on Weebly,
WordPress.com staging and ScreenConnect — because the platform's own domain
is popular (report #7). 2,885 of 41,889 active PhishTank URLs (6.9%) got the
same free pass. The curated data/hosting_platforms.json closes it for the
public check, the authenticated check and the scorer alike.
"""
from __future__ import annotations

import json
import os

import pytest

from api.routers.check import _quick_allowlist_check
from api.services import hosting_platforms as hp
from api.services.scoring import (
    TOP_DOMAINS,
    calculate_score,
    is_hosting_platform_site,
    is_trusted_top_domain,
)

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "hosting_platforms.json")

# Tenant hosts shaped like the report's confirmed phishing pages, plus the
# Russian platforms and page services named in the task.
TENANTS = [
    "a0295959.xsph.ru", "321da.tw1.ru", "sberbank-bonus.tmweb.ru", "cabinet.beget.tech",
    "527715.selcdn.ru", "gosuslugi-pay.swtest.ru", "abc.bget.ru",
    "secure-login.weeblysite.com", "wallet-restore.wpcomstaging.com", "support.screenconnect.com",
    "evil.github.io", "ledgerwaletpages.pages.dev", "x.vercel.app", "x.netlify.app",
    "bank.blogspot.com", "bank.blogspot.ru", "project123.tilda.ws", "shop.ucoz.ru",
]
PAGE_HOSTS = ["forms.yandex.ru", "disk.yandex.ru", "sites.google.com", "docs.google.com", "telegra.ph"]


def test_data_file_is_well_formed():
    with open(DATA) as f:
        data = json.load(f)
    assert set(data) == {"_meta", "tenant_suffixes", "user_content_hosts"}
    assert hp.TENANT_SUFFIXES and hp.USER_CONTENT_HOSTS
    for name in hp.TENANT_SUFFIXES | hp.USER_CONTENT_HOSTS:
        assert name == name.lower().strip(".") and "." in name, name
        assert " " not in name and "/" not in name, name


def test_data_file_never_names_a_big_org_as_a_platform():
    """A platform entry disables the instant-safe path for every SUBDOMAIN of
    it. Listing an organisation's own registrable here would push all of its
    services through the analyzer for nothing."""
    own_services = {"yandex.ru", "google.com", "mail.ru", "vk.com", "sberbank.ru", "gosuslugi.ru",
                    "microsoft.com", "apple.com", "tinkoff.ru", "ozon.ru", "wildberries.ru"}
    assert not (hp.TENANT_SUFFIXES & own_services)


@pytest.mark.parametrize("host", TENANTS + PAGE_HOSTS)
def test_platform_pages_are_not_instant_safe(host):
    assert is_trusted_top_domain(host) is False


def test_the_report_cases_were_popular_bases():
    """The regression is real only if these bases are top-100k (that is what
    granted the free pass) — pin it, so the test above keeps its meaning."""
    for base in ("tw1.ru", "weeblysite.com", "wpcomstaging.com", "screenconnect.com"):
        assert base in TOP_DOMAINS, base


@pytest.mark.parametrize("apex", ["tw1.ru", "timeweb.ru", "beget.com", "weebly.com", "yandex.ru", "google.com"])
def test_platform_apex_itself_stays_trusted(apex):
    if apex not in TOP_DOMAINS:
        pytest.skip(f"{apex} not in this top-100k snapshot")
    assert is_trusted_top_domain(apex) is True


@pytest.mark.parametrize("host", ["mail.yandex.ru", "market.yandex.ru", "online.sberbank.ru", "www.gosuslugi.ru"])
def test_big_orgs_own_services_are_unaffected(host):
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize("host", TENANTS + PAGE_HOSTS)
def test_scorer_does_not_short_circuit_platform_pages(host):
    _, _, reasons = calculate_score({"domain": host, "raw_url": host})
    assert "known_legitimate" not in {r.signal for r in reasons}


@pytest.mark.parametrize("host", ["321da.tw1.ru", "gwcu.us.org", "secure-login.weeblysite.com"])
def test_authenticated_check_uses_the_same_rule(host):
    """/api/v1/check kept its own shorter list and still waved these through."""
    assert _quick_allowlist_check(host) is None


def test_authenticated_check_still_fast_paths_real_top_sites():
    out = _quick_allowlist_check("www.google.com")
    assert out is not None and out.verdict_basis == "allowlist"


def test_informational_reason_only_for_curated_platforms():
    """'Anyone can publish here' is said for real platforms only — never for
    a restricted registry like gov.ru that merely sits in the PSL."""
    assert is_hosting_platform_site("321da.tw1.ru")
    assert is_hosting_platform_site("forms.yandex.ru")
    assert not is_hosting_platform_site("rosreestr.gov.ru")
    assert not is_hosting_platform_site("sberbank.ru")


def test_missing_data_file_degrades_to_hand_list(tmp_path):
    assert hp._load(str(tmp_path / "absent.json")) == (frozenset(), frozenset())


def test_tenant_suffix_is_longest_match():
    assert hp.tenant_suffix_of("a.b.my.canva.site", frozenset({"canva.site", "my.canva.site"})) == "my.canva.site"
    assert hp.tenant_suffix_of("tw1.ru") is None  # the apex is not its own tenant
