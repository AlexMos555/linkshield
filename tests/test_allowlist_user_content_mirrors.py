"""User-content services on their operator's country domains.

Final review of #353 (2026-10-27): forms.yandex.com.tr is Yandex Forms
(/admin/), disk.yandex.kz, .by, .uz and .com.tr are Yandex Disk, all checked
live that day. data/hosting_platforms.json user_content_hosts names only the
.ru / .com spellings, so on the others the allowlist answered "safe" before
any check: the compound ones (yandex.com.tr, .com.am, .com.ge) since the
allowlist reached compound-suffix entries, the two-label ones (yandex.kz,
.by, .uz, .ua) since always. On forms.yandex.ru the same service gets the
fixed "a real service; we cannot vouch for the page" answer.
"""
from __future__ import annotations

import asyncio

import pytest

from api.models.schemas import RiskLevel
from api.services import scoring
from api.services.analyzer import analyze_domain
from api.services.scoring import is_trusted_top_domain


SERVICE_HOSTS_ON_COUNTRY_DOMAINS = [
    "forms.yandex.com.tr", "disk.yandex.com.tr", "forms.yandex.kz", "disk.yandex.kz",
    "forms.yandex.by", "disk.yandex.by", "disk.yandex.uz", "disk.yandex.com.am",
    "disk.yandex.com.ge", "disk.yandex.ua", "disk.360.yandex.kz",
    # Apps Script web apps (script.google.com is user content too).
    "script.google.co.uk", "script.google.de",
    # Already refused before this review (_is_abused_google_service); the
    # fixed answer is new for them.
    "docs.google.co.uk", "sites.google.co.jp", "drive.google.de",
]


@pytest.mark.parametrize("host", SERVICE_HOSTS_ON_COUNTRY_DOMAINS + [
    # A page under the service host, like x.forms.yandex.ru.
    "u.forms.yandex.com.tr", "d.disk.yandex.kz",
])
def test_user_content_services_are_not_trusted_on_country_domains(host):
    assert is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", [
    "yandex.com.tr", "www.yandex.kz", "yandex.by", "market.yandex.kz", "maps.yandex.com.tr",
    # A label that only contains the service name is another host.
    "myforms.yandex.kz", "disk-help.yandex.by",
    "www.google.co.uk", "maps.google.de",
    # OFFICE, a UK shoe retailer, owns office.co.uk: forms.office.com is
    # Microsoft's, a name under office.co.uk is OFFICE's own.
    "forms.office.co.uk",
])
def test_the_operators_other_hosts_stay_trusted(host):
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize("host", SERVICE_HOSTS_ON_COUNTRY_DOMAINS)
def test_a_service_host_on_a_country_domain_gets_the_fixed_answer(host, offline_analyzer):
    # Judging the name judges Yandex or Google: disk.yandex.ru was "ML: 97%
    # phishing" once it lost the allowlist (review 2026-09-27).
    offline_analyzer(site="reachable", values={"whois": {"age_days": 1}})
    result = asyncio.run(analyze_domain(host, budget_s=5.0))
    assert (result.level, result.score) == (RiskLevel.caution, 25), host
    assert result.verdict_basis == "user_content"
    assert [r.signal for r in result.reasons] == ["user_content_platform"]


@pytest.mark.parametrize("host", [
    # Pages under the service host, the platform's other hosts, look-alikes.
    "u.forms.yandex.com.tr", "market.yandex.kz", "myforms.yandex.kz",
    "forms.yandex.com.tr.evil.example", "translate.google.co.uk", "forms.office.co.uk",
])
def test_only_the_service_host_itself_gets_the_fixed_answer(host):
    assert scoring.is_user_content_service_host(host) is False


def test_the_canonical_service_hosts_keep_the_fixed_answer():
    for host in ["forms.yandex.ru", "disk.yandex.com", "docs.google.com", "onedrive.live.com", "telegra.ph"]:
        assert scoring.is_user_content_service_host(host) is True, host


def test_public_check_answers_a_country_service_host_without_analysis(monkeypatch, fake_redis):
    from fastapi.testclient import TestClient

    from api.main import app
    from api.services import analyzer as analyzer_mod

    async def _boom(*a, **k):
        raise AssertionError("a user-content service host must not be analysed")

    monkeypatch.setattr(analyzer_mod, "analyze_domain", _boom)
    body = TestClient(app).get("/api/v1/public/check/disk.yandex.kz").json()
    assert body["level"] == "caution" and body["verdict_basis"] == "user_content", body
    assert body["reason_codes"] == ["user_content_platform"]
