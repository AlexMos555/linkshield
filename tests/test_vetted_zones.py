"""Zones only a government, health service or police force registers in.

With the PSL (PR #357) a name under nhs.uk, sa.gov.au or pi.gov.br is its
own registrable domain, so its registered name meets the keyword rule
('login' of auth.login.nhs.uk) and its apex the no-MX rule (NHS trust sites
without MX). The differential check of 2026-10-31 found these as the PR's
only regressions: legit hosts going safe→caution, two NHS services
caution→dangerous. Names in such zones are not anyone's pick, so neither
rule applies there — but only where the PSL's ICANN section lists the zone:
sch.in, govt.hu and mil.nf carry a restricted label yet are ChangeIP's and
FreeDNS's free zones, suffixes only by the ccTLD default.
"""
from __future__ import annotations

import pytest

from api.services.public_suffix import is_ip_literal
from api.services.scoring import _check_suspicious_keywords, _registered_in_vetted_zone, calculate_score


@pytest.mark.parametrize("host", [
    "auth.login.nhs.uk", "settings.login.nhs.uk", "login.nhs.uk",
    "account.sa.gov.au", "login.pi.gov.br", "login.police.uk", "secure.gov.uk",
])
def test_no_keyword_in_a_vetted_zone(host):
    assert _registered_in_vetted_zone(host)
    assert _check_suspicious_keywords(host) is None


@pytest.mark.parametrize("host", [
    "paypal-login.sch.in", "secure-login.govt.hu", "login.mil.nf", "account-verify.edu.si",
    "secure-login.co.uk", "paypal-login.ne.pw", "login-verify.com",
])
def test_open_zones_keep_the_keyword(host):
    assert not _registered_in_vetted_zone(host)
    assert _check_suspicious_keywords(host) is not None


def _no_mx(domain):
    _, _, reasons = calculate_score({
        "domain": domain, "raw_url": domain, "dns_has_mx": False,
        "checks_succeeded": 18, "total_checks": 18,
    })
    return any(r.signal == "no_mx_record" for r in reasons)


@pytest.mark.parametrize("host", [
    "bedfordshirehospitals.nhs.uk", "manage-vaccinations-in-schools.nhs.uk", "account.sa.gov.au",
])
def test_no_mx_is_not_held_against_a_vetted_zone(host):
    assert not _no_mx(host)


@pytest.mark.parametrize("host", ["paypal-login.sch.in", "secure-verify.co.uk", "paypal-login.ne.pw"])
def test_no_mx_still_counts_in_open_zones(host):
    assert _no_mx(host)


@pytest.mark.parametrize("dom, expected", [
    ("1.2.3.4", True), ("1.2.3.4:443", True), ("[::1]", True), ("2001:db8::1", True),
    ("[2001:db8::1]", True), ("example.com", False), ("example.com:8080", False),
    # A malformed Tranco-subdomain entry: a scheme is not an IPv6 address
    # (it made the name its own site and dropped mail.ru's vouch).
    ("https://alt-aj-https.mail.ru", False),
])
def test_ip_literal(dom, expected):
    assert is_ip_literal(dom) is expected
