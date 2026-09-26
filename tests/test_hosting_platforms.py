"""Hosting and user-content platforms never get the instant 'safe, 99%'.

On 2026-09-25 the live /public/check called five phishing pages "safe, 99%"
without analysing them: two on Timeweb (tw1.ru), one each on Weebly,
WordPress.com staging and ScreenConnect — because the platform's own domain
is popular (report #7). 2,885 of 41,889 active PhishTank URLs (6.9%) got the
same free pass. The curated data/hosting_platforms.json closes it for the
public check, the authenticated check and the scorer alike.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest
from fastapi.testclient import TestClient

from api.main import app  # imported before any asyncio.run(): see watchtower._throttle_lock
from api.models.schemas import RiskLevel
from api.routers.check import _quick_allowlist_check
from api.services import hosting_platforms as hp
from api.services import verdict_basis as vb
from api.services.analyzer import analyze_domain
from api.services.hosting_platforms import is_user_content_service
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
    assert set(data) == {"_meta", "tenant_suffixes", "user_content_hosts", "operator_hosts"}
    assert hp.TENANT_SUFFIXES and hp.USER_CONTENT_HOSTS and hp.OPERATOR_HOSTS
    for name in hp.TENANT_SUFFIXES | hp.USER_CONTENT_HOSTS | hp.OPERATOR_HOSTS:
        assert name == name.lower().strip(".") and "." in name, name
        assert " " not in name and "/" not in name, name


def test_every_operator_host_sits_under_a_tenant_suffix():
    """An operator entry only makes sense as an exception to a tenant rule;
    anywhere else it would be dead weight, or a typo hiding one."""
    for host in hp.OPERATOR_HOSTS:
        assert any(host.endswith("." + s) for s in hp.TENANT_SUFFIXES), host


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
    assert hp._load(str(tmp_path / "absent.json")) == (frozenset(), frozenset(), frozenset())


# ── The platforms' OWN hosts (review 2026-09-27) ──
#
# "Every subdomain is a customer" also swept up the operators' own
# dashboards, webmail and sites: they lost the instant-safe path, were told
# "anyone can publish pages on this service", and the ML model put several
# at caution 35 — typeform's at dangerous 60.

OPERATOR_OWN = [
    "www.timeweb.cloud", "app.netlify.com", "email.secureserver.net", "www.odoo.com",
    "www.tumblr.com", "www.typeform.com", "admin.typeform.com", "my.wpengine.com",
    "microsoft.sharepoint.com",
]


@pytest.mark.parametrize("host", OPERATOR_OWN)
def test_platform_operators_own_hosts_are_not_tenants(host):
    assert hp.tenant_suffix_of(host) is None
    assert not is_hosting_platform_site(host)
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize("host", ["www.abc.tw1.ru", "wwwx.tumblr.com", "evil.netlify.com", "contoso.sharepoint.com"])
def test_operator_exception_is_exact(host):
    """Only the exact operator host is excepted — never a customer's www, a
    look-alike label, or another tenant of the same suffix."""
    assert is_trusted_top_domain(host) is False


# ── The user-content SERVICE host itself (review 2026-09-27) ──
#
# Once these lost the allowlist, the full analyzer judged the platform's own
# name: onedrive.live.com 'dangerous 100' ("uses the onedrive brand name in a
# subdomain to deceive"), gist.github.com 100, forms.office.com 85,
# disk.yandex.ru caution ("ML: 97% phishing"). Android 1.0.1 DNS-blocks any
# host whose check says 'dangerous' — one tapped OneDrive link would have cut
# OneDrive off.

USER_CONTENT_SERVICES = [
    "onedrive.live.com", "forms.office.com", "gist.github.com", "disk.yandex.ru",
    "forms.yandex.ru", "sites.google.com", "docs.google.com", "telegra.ph",
    "disk.360.yandex.ru", "yadi.sk", "raw.githubusercontent.com",
]


@pytest.mark.parametrize("host", USER_CONTENT_SERVICES)
def test_user_content_service_gets_a_fixed_honest_answer(host, offline_analyzer):
    # A reachable site "registered yesterday": none of it may matter — the
    # name belongs to the platform, and the page is unknown.
    offline_analyzer(site="reachable", values={"whois": {"age_days": 1}})
    result = asyncio.run(analyze_domain(host, budget_s=5.0))
    assert (result.level, result.score) == (RiskLevel.caution, 25)
    assert result.verdict_basis == "user_content"
    assert [r.signal for r in result.reasons] == ["user_content_platform"]


@pytest.mark.parametrize("host", USER_CONTENT_SERVICES)
def test_user_content_service_is_never_blocking(host):
    result = vb.user_content_result(host)
    assert result.level != RiskLevel.dangerous
    assert vb.basis_of(result) not in vb.BLOCKING_BASES


def test_public_check_answers_user_content_without_analysis(monkeypatch, fake_redis):
    from api.services import analyzer as analyzer_mod

    async def _boom(*a, **k):
        raise AssertionError("a user-content service host must not be analysed")

    monkeypatch.setattr(analyzer_mod, "analyze_domain", _boom)
    body = TestClient(app).get("/api/v1/public/check/onedrive.live.com").json()
    assert body["level"] == "caution" and body["verdict_basis"] == "user_content"
    assert "real service" in body["verdict"]
    assert body["reason_codes"] == ["user_content_platform"]


@pytest.mark.parametrize("host", ["321da.tw1.ru", "secure-login.weeblysite.com", "x.forms.yandex.ru"])
def test_tenant_pages_are_still_analysed(host):
    """Only the service host itself gets the fixed answer; a customer's site
    (or anything under the service host) is still judged on its evidence."""
    assert not is_user_content_service(host)


def test_tenant_suffix_is_longest_match():
    assert hp.tenant_suffix_of("a.b.my.canva.site", frozenset({"canva.site", "my.canva.site"})) == "my.canva.site"
    assert hp.tenant_suffix_of("tw1.ru") is None  # the apex is not its own tenant
