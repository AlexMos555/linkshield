"""The weekly benchmark of 2026-10-25: two real Russian sites called "dangerous".

tztu.ru (Туймазытехуглерод) — dangerous 65:
  * alienvault_otx_high, "Flagged in 44 AlienVault OTX threat reports". The 44
    are one 12,732-indicator malspam-header dump (created 2021) and 43 copies
    of it ("test", "test CREATED 1 YEAR AGO by testivk1 clone", "Network
    IOCs"): same tags, same indicator count. A copy is not a second report.
  * new_certificate, "issued 0 days ago": Let's Encrypt's 90-day renewal of
    2026-10-24. crt.sh still holds the previous certificate, 2026-08-25.

дорожное.рф (xn--d1acc2adacm.xn--p1ai, Дорожное радио) — dangerous 53, on
signals that are each as common on real sites as on phishing:
  missing_headers 15 + no_mx_record 8 + new_certificate 15 (renewed
  2026-10-20) + multiple_redirects 5 + cross_domain_redirect 20 (to
  dorognoe.ru, the station's own site) − ml_safe_override 10.

What changed:
  * OTX is tiered on distinct reports, not copies: OTX marks a clone
    (`cloned_from`), and the analyzer counts originals.
  * new_certificate is not raised when something shows the name is older than
    its certificate: on a hosting platform, the platform's own wildcard
    (*.vercel.app, renewed for every site under it — not a tenant's
    *.x.workers.dev); a top-1M popularity rank; a domain age of 90+ days.
  * Weak signals alone cannot make a verdict 'dangerous' (scoring.WEAK_SIGNALS).
    OTX is not one of them: its auto-feeds list fresh phishing within a day.
    Only one to five reports that are all 90+ days old are weak. On a hosting
    customer's site that names a brand (coinbase-com-08739.x.workers.dev)
    the pile counts.
  * The suspicious-keyword rule reads a hosting tenant's own label.
"""
from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest

from api.models.schemas import RiskLevel
from api.services import analyzer, ml_scorer, reason_codes, scoring, site_probes


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 13, "total_checks": 13, **extra}


def _codes(reasons) -> dict[str, int]:
    return {r.signal: r.weight for r in reasons}


@pytest.fixture
def ml_off(monkeypatch):
    """The model's answer pinned to 'nothing to say' (0.3), so a test is about the rules."""
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda d: {"phishing_probability": 0.3, "confidence": 0.4})


@pytest.fixture
def ml_says(monkeypatch):
    def _set(prob: float, confidence: float = 0.9):
        monkeypatch.setattr(ml_scorer, "ml_predict",
                            lambda d: {"phishing_probability": prob, "confidence": confidence})
    return _set


# ── The two rows, replayed through the analyzer's own signal builder ──

def _clone_pulses() -> list[dict]:
    """tztu.ru's pulse list as OTX answered it on 2026-10-26 (ids shortened).

    One original, a 2021 malspam-header dump by cnoscsoc@att.com (d4ec91), and
    43 copies: 4 OctoSeek clones of it (2023), 22 testivk1 clones of one of
    those (2024; one with 12,733 indicators) and 17 msudosos clones of one of
    the testivk1 ones (2026-05). Tags and indicator counts are the
    original's."""
    tags = ["msi file", "tuesday", "malspam email", "headers", "anna paula", "utf8"]

    def pulse(pid, cloned_from, created, name, size=12732, modified=None):
        return {"id": pid, "cloned_from": cloned_from, "name": name, "tags": list(tags),
                "indicator_count": size, "created": f"{created}T10:00:00.000000",
                "modified": f"{modified or created}T10:00:00.000000"}

    rows = [pulse("d4ec91", None, "2021-09-24", "Network IOCs", modified="2023-05-11")]
    rows += [pulse(f"octo{i}", "d4ec91", "2023-09-15", "Network IOCs (Pulse Created by cnoscsoc@att.com)")
             for i in range(4)]
    rows += [pulse("f6a190", "octo0", "2024-11-27", "test")]
    rows += [pulse(f"tv{i}", "octo0", "2024-11-27", "test") for i in range(18)]
    rows += [pulse("bf71e3", "octo0", "2024-11-27", "test")]
    rows += [pulse("fc3446", "f6a190", "2024-11-27", "test", size=12733),
             pulse("3923c4", "f6a190", "2024-11-27", "test")]
    rows += [pulse(f"ms{i}", "bf71e3", "2026-05-08", "test CREATED 1 YEAR AGO by testivk1 clone")
             for i in range(17)]
    assert len(rows) == 44
    return rows


def _otx_payload(pulses: list[dict], count: int | None = None) -> dict:
    return {"pulse_info": {"count": len(pulses) if count is None else count, "pulses": pulses},
            "reputation": 0}


def _otx_answers(monkeypatch, payload: dict) -> None:
    real = httpx.AsyncClient

    def _handler(request):
        return httpx.Response(200, json=payload)

    monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))


def _score(host: str, outcomes: dict):
    outcomes = {"tranco": ({"ranked": False, "rank": None, "weight": 0, "label": "",
                            "registrable_rank": None}, True), **outcomes}
    sig = analyzer._build_signals(host, host, False, outcomes, 13)
    sig["checks_succeeded"] = 13
    return scoring.calculate_score(sig)


def test_tztu_ru_44_copies_of_one_otx_dump_and_a_renewal_are_not_dangerous(monkeypatch):
    _otx_answers(monkeypatch, _otx_payload(_clone_pulses()))
    otx = asyncio.run(analyzer.check_alienvault_otx("tztu.ru"))
    assert otx["pulse_count"] == 44 and otx["distinct_pulses"] == 1
    assert otx["newest_report_days"] > 365    # the original, made in 2021
    score, level, reasons = _score("tztu.ru", {
        "alienvault": (otx, True),
        "ssl": ({"reachable": True, "has_ssl": True, "issuer": "Let's Encrypt", "is_free_ssl": True,
                 "cert_age_days": 0, "cert_wildcard": False}, True),
        "headers": ({"reachable": True, "present": ["strict-transport-security", "x-frame-options",
                                                    "x-content-type-options"],
                     "missing": ["content-security-policy", "referrer-policy"]}, True),
        "dns": ({"a_count": 1, "ttl": 3376, "ns_count": 2, "has_mx": True}, True),
        "redirect": ({"reachable": True, "count": 1, "cross_domain": False}, True),
        "whois": ({}, True),
    })
    codes = _codes(reasons)
    assert level != RiskLevel.dangerous, (score, codes)
    assert "alienvault_otx_high" not in codes and codes["alienvault_otx"] == 30
    otx_reason = next(r for r in reasons if r.signal == "alienvault_otx")
    assert "44" in otx_reason.detail and "1 distinct" in otx_reason.detail


def test_dorozhnoe_rf_weak_signals_alone_stop_at_caution():
    score, level, reasons = _score("xn--d1acc2adacm.xn--p1ai", {
        "ssl": ({"reachable": True, "has_ssl": True, "issuer": "Let's Encrypt", "is_free_ssl": True,
                 "cert_age_days": 5, "cert_wildcard": False}, True),
        "headers": ({"reachable": True, "present": [],
                     "missing": list(site_probes._SECURITY_HEADERS)}, True),
        "dns": ({"a_count": 1, "ttl": 86178, "ns_count": 2, "has_mx": False}, True),
        "redirect": ({"reachable": True, "count": 2, "cross_domain": True,
                      "domains_visited": ["dorognoe.ru"]}, True),
        "whois": ({}, True),
    })
    codes = _codes(reasons)
    # Every signal it had is still reported…
    assert {"missing_headers", "no_mx_record", "new_certificate", "multiple_redirects",
            "cross_domain_redirect"} <= set(codes)
    # …but together they are a caution, not a 'dangerous'.
    assert level == RiskLevel.caution and score <= 50, (score, codes)


# ── OTX: copies are not reports ──

_TODAY = date(2026, 10, 26)


def _pulse(pid: str, *, cloned_from: str | None = None, created: str = "2026-10-20",
           modified: str | None = None, tags=("phishing",), size: int = 2000) -> dict:
    """A pulse as OTX lists it (the fields the analyzer reads)."""
    return {"id": pid, "cloned_from": cloned_from, "tags": list(tags), "indicator_count": size,
            "created": f"{created}T08:00:00.000000", "modified": f"{modified or created}T08:00:00.000000"}


def test_clones_traced_back_to_one_original_are_one_report():
    # tztu.ru: an original, clones of it, clones of the clones.
    assert analyzer._otx_reports(_clone_pulses(), 44, today=_TODAY)[0] == 1


def test_a_daily_feed_is_a_report_a_day_though_tags_and_size_repeat():
    # spotifypremiumapk.pk (phishing): LTNA-Australia's "Phishing | <date> | Part n/566",
    # one pulse a day (50 of them, June to October 2026), each tagged
    # 'phishing' with 2,000 indicators, none a clone.
    feed = [_pulse(f"day{i}", created=f"2026-{6 + i // 28:02d}-{1 + i % 28:02d}") for i in range(50)]
    distinct, newest = analyzer._otx_reports(feed, 50, today=_TODAY)
    assert distinct == 50
    assert newest == (_TODAY - date(2026, 7, 22)).days     # day49: the latest of the feed


def test_clones_of_a_pulse_otx_did_not_list_are_one_report():
    pulses = [_pulse("a", cloned_from="gone"), _pulse("b", cloned_from="gone"), _pulse("c")]
    assert analyzer._otx_reports(pulses, 3, today=_TODAY)[0] == 2


def test_a_clone_cycle_does_not_hang():
    pulses = [_pulse("a", cloned_from="b"), _pulse("b", cloned_from="a")]
    assert analyzer._otx_reports(pulses, 2, today=_TODAY)[0] >= 1


def test_without_the_clone_field_copies_are_told_by_content():
    # Older answers carry no `cloned_from`: a copy keeps the original's tags and size.
    pulses = [{"id": "a", "tags": ["phishing"], "indicator_count": 356},
              {"id": "b", "tags": ["Phishing"], "indicator_count": 356},       # a copy (tag case aside)
              {"id": "c", "tags": ["phishing"], "indicator_count": 143},       # another day's list
              {"id": "d", "tags": [], "indicator_count": 14}]
    assert analyzer._otx_reports(pulses, 4)[0] == 3


def test_reports_without_tags_or_size_are_never_merged():
    pulses = [{"id": "a", "name": "x"}, {"id": "b", "name": "y"}, {"id": "c"}]
    assert analyzer._otx_reports(pulses, 3)[0] == 3


def test_reports_otx_did_not_list_count_as_distinct():
    copies = [{"id": str(i), "tags": ["dump"], "indicator_count": 9000} for i in range(50)]
    # OTX listed 50 of 60: the 10 unseen ones are not assumed to be copies.
    assert analyzer._otx_reports(copies, 60)[0] == 11
    assert analyzer._otx_reports([], 7)[0] == 7


# ── OTX: how old the newest report is ──

def test_newest_report_age_is_when_the_newest_report_was_made():
    pulses = [_pulse("a", created="2025-12-20"), _pulse("b", created="2024-01-02")]
    assert analyzer._otx_reports(pulses, 2, today=_TODAY) == (2, (_TODAY - date(2025, 12, 20)).days)


def test_a_pulse_kept_up_to_date_is_as_old_as_it_was_made():
    # centralnic-dns.com (2026-10-26): on phishdestroy's "(Live)" lists, made in
    # 2026-03 and modified that morning, and on a 2023 pulse.
    pulses = [_pulse("live1", created="2026-03-23", modified="2026-10-26"),
              _pulse("live2", created="2026-03-22", modified="2026-10-26"),
              _pulse("old", created="2023-08-22", modified="2023-09-24")]
    assert analyzer._otx_reports(pulses, 3, today=_TODAY) == (3, (_TODAY - date(2026, 3, 23)).days)


def test_only_a_modified_date_is_used_when_created_is_missing():
    pulses = [{"id": "a", "cloned_from": None, "tags": [], "indicator_count": 1,
               "modified": "2026-10-20T00:00:00"}]
    assert analyzer._otx_reports(pulses, 1, today=_TODAY) == (1, 6)


def test_a_copy_does_not_make_an_old_report_new():
    # tztu.ru: the newest copies are from 2026-05, the original from 2021.
    _, newest = analyzer._otx_reports(_clone_pulses(), 44, today=_TODAY)
    assert newest == (_TODAY - date(2021, 9, 24)).days


@pytest.mark.parametrize("pulses,count", [
    ([{"id": "a", "cloned_from": None, "tags": ["x"], "indicator_count": 3}], 1),   # no dates
    ([_pulse("a", created="2024-01-01")], 2),                                      # one not listed
    ([_pulse("a", cloned_from="gone", created="2024-01-01")], 1),                  # original not listed
    ([], 3),
])
def test_newest_report_age_is_unknown_unless_every_report_is_dated(pulses, count):
    assert analyzer._otx_reports(pulses, count, today=_TODAY)[1] is None


def test_otx_answer_carries_the_distinct_count_and_the_newest_age(monkeypatch):
    pulses = [_pulse(str(i), tags=[f"campaign-{i}"], size=10 + i, created=f"2026-10-{20 + i}")
              for i in range(3)]
    _otx_answers(monkeypatch, _otx_payload(pulses))
    out = asyncio.run(analyzer.check_alienvault_otx("example.net"))
    newest = (datetime.now(timezone.utc).date() - date(2026, 10, 22)).days
    assert out == {"pulse_count": 3, "distinct_pulses": 3, "newest_report_days": newest,
                   "reputation": 0, "hit": True}


def test_build_signals_passes_the_otx_summary_and_the_wildcard_flag():
    sig = analyzer._build_signals("example.net", "example.net", False, {
        "alienvault": ({"pulse_count": 44, "distinct_pulses": 2, "newest_report_days": 1264, "hit": True}, True),
        "ssl": ({"reachable": True, "has_ssl": True, "cert_age_days": 1, "cert_wildcard": True}, True),
    }, 13)
    assert sig["alienvault_pulse_count"] == 44 and sig["alienvault_distinct_pulses"] == 2
    assert sig["alienvault_newest_report_days"] == 1264
    assert sig["cert_wildcard"] is True


@pytest.mark.parametrize("pulses,distinct,expected", [
    (44, 2, {"alienvault_otx": 30}),          # tztu.ru: copies of one dump
    (10, 10, {"alienvault_otx_high": 60}),    # ten separate reports: as before
    (10, None, {"alienvault_otx_high": 60}),  # no list (older callers): the count, as before
    (3, 3, {"alienvault_otx": 30}),
    (3, 9, {"alienvault_otx": 30}),           # never more than the count
])
def test_otx_tier_follows_distinct_reports(ml_off, pulses, distinct, expected):
    extra = {"alienvault_pulse_count": pulses}
    if distinct is not None:
        extra["alienvault_distinct_pulses"] = distinct
    _, _, reasons = scoring.calculate_score(_signals("otx-copies-example.net", **extra))
    assert {k: v for k, v in _codes(reasons).items() if k.startswith("alienvault")} == expected


def test_ranked_name_with_few_distinct_reports_is_still_a_victim_reference(ml_off):
    _, _, reasons = scoring.calculate_score(_signals(
        "otx-copies-example.net", alienvault_pulse_count=30, alienvault_distinct_pulses=3,
        tranco_ranked=True, tranco_rank=432_973, tranco_weight=-3, tranco_registrable_rank=432_973))
    assert not any(r.signal.startswith("alienvault") for r in reasons)


# ── new_certificate: a renewal is not a new site ──

def test_fresh_certificate_on_an_unknown_name_still_counts(ml_off):
    _, _, reasons = scoring.calculate_score(_signals("newcert-example.xyz", cert_age_days=2))
    assert _codes(reasons).get("new_certificate") == 15


@pytest.mark.parametrize("extra", [
    {"tranco_ranked": True, "tranco_rank": 500_000, "tranco_weight": -3},
    {"tranco_registrable_rank": 300_000},                             # www./shop. of a ranked name
    {"domain_age_days": 400},
    {"domain_age_days": 90},
])
def test_fresh_certificate_is_a_renewal_when_the_name_is_older(ml_off, extra):
    _, _, reasons = scoring.calculate_score(_signals("shop.renewal-example.net", cert_age_days=1, **extra))
    assert "new_certificate" not in _codes(reasons)


@pytest.mark.parametrize("host", ["verifiedbadgehub.vercel.app", "fduno60.wixsite.com", "x.pages.dev"])
def test_platform_wildcard_certificate_is_not_the_tenants(ml_off, host):
    # *.vercel.app is renewed for every customer at once.
    _, _, reasons = scoring.calculate_score(_signals(host, cert_age_days=1, cert_wildcard=True))
    assert "new_certificate" not in _codes(reasons)


@pytest.mark.parametrize("host", ["ferrari.info4571011.pro", "bradesco.ne12topaz.digital",
                                  "shop.renewal-example.net"])
def test_a_wildcard_on_the_sites_own_name_still_counts(ml_off, host):
    # A kit's fresh domain with one wildcard for all its subdomains (2026-10-25).
    _, _, reasons = scoring.calculate_score(_signals(host, cert_age_days=1, cert_wildcard=True))
    assert _codes(reasons).get("new_certificate") == 15


@pytest.mark.parametrize("host", [
    "rblxcashout.swervostore.workers.dev",   # *.swervostore.workers.dev, issued 0 days ago (2026-10-26)
    "a.x.workers.dev",                       # *.x.workers.dev: the account's
    "a.x.pages.dev",                         # *.x.pages.dev: the project's
    "login.evil.duckdns.org",                # *.evil.duckdns.org: DNS-01 on the tenant's own zone
    "a.x.duckdns.org",
])
def test_a_tenants_own_wildcard_one_level_down_still_counts(ml_off, host):
    # A wildcard covers one label, so it is the platform's (*.workers.dev)
    # only for a host directly under the platform; deeper, the parent is the
    # tenant's own name and the certificate is as old as the tenant's site.
    _, _, reasons = scoring.calculate_score(_signals(host, cert_age_days=1, cert_wildcard=True))
    assert _codes(reasons).get("new_certificate") == 15


def test_young_domain_keeps_its_fresh_certificate(ml_off):
    _, _, reasons = scoring.calculate_score(_signals("young-example.xyz", cert_age_days=1, domain_age_days=3))
    codes = _codes(reasons)
    assert codes["domain_very_new"] == 50 and codes["new_certificate"] == 15


def test_hosting_platform_rank_does_not_vouch_for_a_tenant_certificate(ml_off):
    # vercel.app is popular; this customer's own name is not.
    _, _, reasons = scoring.calculate_score(_signals(
        "fresh-tenant.vercel.app", cert_age_days=1, tranco_registrable_rank=244))
    assert _codes(reasons).get("new_certificate") == 15


# ── Weak signals alone stop at caution ──

def test_weak_signals_are_codes_the_scorer_emits():
    assert scoring.WEAK_SIGNALS <= reason_codes.KNOWN_REASON_CODES
    # The model, the brand rules, the age, the zone and the lists are what make 'dangerous'.
    assert not scoring.WEAK_SIGNALS & {
        "ml_high_risk", "ml_suspicious", "typosquatting", "homograph_attack", "brand_subdomain_abuse",
        "domain_new", "domain_very_new", "alienvault_otx", "alienvault_otx_high", "no_https",
        "invalid_certificate",
        "safe_browsing", "phishstats", "ipqs_phishing", "favicon_brand_clone", "risky_tld_high",
    }


def test_a_high_abuse_zone_lets_the_pile_count(ml_off):
    # krelthis.cfd (phishing, 2026-10-25): headers, .cfd, no MX, a fresh certificate.
    score, level, _ = scoring.calculate_score(_signals(
        "krelthis.cfd", missing_security_headers=list(site_probes._SECURITY_HEADERS), dns_has_mx=False,
        cert_age_days=2))
    assert level == RiskLevel.dangerous and score > 50


_WEAK_PILE = dict(missing_security_headers=list(site_probes._SECURITY_HEADERS), dns_has_mx=False,
                  cert_age_days=1, redirect_count=4, redirect_cross_domain=True, dns_ttl=30)


def test_a_pile_of_weak_signals_is_capped_at_caution(ml_off):
    score, level, reasons = scoring.calculate_score(_signals("weak-pile-example.ru", **_WEAK_PILE))
    assert sum(r.weight for r in reasons) > 50          # the signals are all still there
    assert score == 50 and level == RiskLevel.caution


def test_one_strong_signal_lets_the_pile_count(ml_says):
    ml_says(0.95)
    score, level, reasons = scoring.calculate_score(_signals("weak-pile-example.ru", **_WEAK_PILE))
    assert "ml_high_risk" in _codes(reasons)
    assert score > 50 and level == RiskLevel.dangerous


def test_a_young_domain_is_a_strong_signal(ml_off):
    score, level, _ = scoring.calculate_score(_signals(
        "weak-pile-example.ru", domain_age_days=10, **_WEAK_PILE))
    assert level == RiskLevel.dangerous and score > 50


_OTX_PILE = dict(missing_security_headers=list(site_probes._SECURITY_HEADERS), dns_has_mx=False,
                 cert_age_days=1)


@pytest.mark.parametrize("reports,newest", [
    (1, 0),        # CyberHunterAutoFeed's list of the day (portal-canalbradesco.digital 74, 2026-10-26)
    (4, 23),       # phishdestroy, 2026-10-03 (ingdirect-accesoweb-login.com)
    (5, 89),
    (3, None),     # how old is not known: as before
    (8, 2000),     # six or more reports, however old
])
def test_otx_reports_let_the_pile_count(ml_off, reports, newest):
    extra = dict(alienvault_pulse_count=reports, alienvault_distinct_pulses=reports, **_OTX_PILE)
    if newest is not None:
        extra["alienvault_newest_report_days"] = newest
    score, level, reasons = scoring.calculate_score(_signals("otx-pile-example.net", **extra))
    assert any(r.signal.startswith("alienvault") for r in reasons)
    assert level == RiskLevel.dangerous and score > 50, (score, _codes(reasons))


@pytest.mark.parametrize("reports,newest", [(1, 310), (2, 1264), (5, 90)])
def test_few_old_otx_reports_need_corroboration(ml_off, reports, newest):
    # job-shop.com: one pulse of 2025-12-20; crcdn.org, webglobe.com: two of 2022-2023
    # (sites that left the allowlist in #284, 2026-10-26).
    score, level, reasons = scoring.calculate_score(_signals(
        "otx-pile-example.net", alienvault_pulse_count=reports, alienvault_distinct_pulses=reports,
        alienvault_newest_report_days=newest, **_OTX_PILE))
    otx = next(r for r in reasons if r.signal == "alienvault_otx")
    assert otx.weight == 30 and f"{newest} days" in otx.detail
    assert level == RiskLevel.caution and score == 50


def test_old_otx_reports_still_count_with_a_strong_signal(ml_says):
    ml_says(0.95)
    score, level, _ = scoring.calculate_score(_signals(
        "otx-pile-example.net", alienvault_pulse_count=2, alienvault_distinct_pulses=2,
        alienvault_newest_report_days=500, **_OTX_PILE))
    assert level == RiskLevel.dangerous and score > 50


# ── A brand word in a hosting customer's own name lets the pile count ──

# What the probes saw on such hosts (2026-10-26): no security headers and the
# platform's subdomain depth; with a fresh certificate the pile passes 50.
_TENANT_PILE = dict(missing_security_headers=list(site_probes._SECURITY_HEADERS), cert_age_days=1,
                    redirect_count=2, redirect_cross_domain=True)


@pytest.mark.parametrize("host", [
    "coinbase-com-08739.lclarkpz.workers.dev",                  # phishing, 61 -> 50 under the cap
    "dashboard.booking-com-waedubai-hotels.webflow.io",          # one of six booking-com*.webflow.io
    "d4d5qr1cpoos73dg9ntg.booking-dubai-desert-safaria.webflow.io",
    "ozon-777.x.workers.dev",                                   # a Russian brand of four letters or more
])
def test_a_brand_word_in_a_tenants_name_lets_weak_signals_count(ml_off, host):
    score, level, reasons = scoring.calculate_score(_signals(host, **_TENANT_PILE))
    assert sum(r.weight for r in reasons) > 50
    assert level == RiskLevel.dangerous and score > 50, (score, _codes(reasons))


@pytest.mark.parametrize("host", [
    "polished-hall-486c.brandaq.workers.dev",       # a real Worker (CrUX), brandless
    "blog.aebooking-com-dubai-hotels.webflow.io",   # glued to other letters: not the word
    "coinbase-com-08739.weak-pile-example.ru",      # a registered name: the brand rules' business
    "vk-club.x.workers.dev",                        # Russian brands under four letters are too common
])
def test_without_a_tenant_brand_word_the_pile_stops_at_caution(ml_off, host):
    score, level, reasons = scoring.calculate_score(_signals(host, **_TENANT_PILE))
    assert sum(r.weight for r in reasons) > 50, _codes(reasons)
    assert level == RiskLevel.caution and score == 50, (score, _codes(reasons))


@pytest.mark.parametrize("host,word", [
    ("coinbase-com-08739.lclarkpz.workers.dev", "coinbase"),
    ("bradesco-login.zaka25.duckdns.org", None),         # not a typosquat target
    ("dhl_express.pro.typeform.com", "dhl"),
    ("kitpanelas-tiktok.vercel.app", "tiktok"),
    ("verifiedbadgehub.vercel.app", None),
    ("ozon-skidki.netlify.app", "ozon"),
    ("www.coinbase.com", None),                         # not on a hosting platform
])
def test_tenant_brand_word(host, word):
    assert scoring._tenant_brand_word(host) == word


def test_blocklist_verdicts_are_untouched():
    score, level, _ = scoring.calculate_score(_signals("listed-example.net", phishstats_hit=True,
                                                       dns_has_mx=False))
    assert level == RiskLevel.dangerous and score >= 65


# ── The keyword rule reads a hosting tenant's own name ──

@pytest.mark.parametrize("host,word", [
    ("secure-login-portal.vercel.app", "secure"),
    ("wallet-restore.pages.dev", "wallet"),
    ("my-invoice.netlify.app", "invoice"),
])
def test_keyword_in_a_tenant_label_counts(ml_off, host, word):
    _, _, reasons = scoring.calculate_score(_signals(host))
    kw = next(r for r in reasons if r.signal == "suspicious_keyword")
    assert f"'{word}'" in kw.detail


@pytest.mark.parametrize("host", ["my-blog.vercel.app", "docs.vercel.app", "login.example.com"])
def test_no_keyword_no_signal(ml_off, host):
    _, _, reasons = scoring.calculate_score(_signals(host))
    assert "suspicious_keyword" not in _codes(reasons)


# ── The TLS probe says when the certificate is the operator's wildcard ──

def _not_before(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%b %d %H:%M:%S %Y GMT")


@pytest.mark.parametrize("host,san,wildcard", [
    ("verifiedbadgehub.vercel.app", ["*.vercel.app"], True),
    ("videopius.bolt.host", ["bolt.host", "*.bolt.host"], True),
    ("tztu.ru", ["tztu.ru", "www.tztu.ru"], False),
    ("shop.example.com", ["*.example.com", "shop.example.com"], False),   # issued for this name too
    ("a.b.example.com", ["*.example.com"], False),                      # a wildcard covers one label
    ("Shop.Example.com", ["*.EXAMPLE.com"], True),
    ("example.com", [], False),
])
def test_certificate_wildcard_flag(host, san, wildcard):
    cert = {"issuer": ((("organizationName", "Let's Encrypt"),),), "notBefore": _not_before(1),
            "subjectAltName": tuple(("DNS", s) for s in san)}
    out = site_probes._describe_certificate(cert, host)
    assert out["cert_wildcard"] is wildcard and out["cert_age_days"] == 1
