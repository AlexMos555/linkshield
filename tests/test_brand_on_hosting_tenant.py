"""A brand's name with a lure word as a customer's site on a hosting platform.

Fresh phishing lives on free hosting (docs/EVALUATION_2026-10.md §1.2: the
whole ML gain on the PhishTank week was *.vercel.app, *.netlify.app,
*.pages.dev …). The name rules looked at the platform's registrable domain
(pages.dev) and never at the name the customer chose, so
sberbank-online.pages.dev and paypal-login.netlify.app scored 0 on the name.

The rule is narrow on purpose: a brand mentioned on a hosting platform is
mostly a student clone or a fan page (netflix-clone.vercel.app). It fires on
a Russian brand as the whole name, or any brand next to a lure word.
"""
from __future__ import annotations

import pytest

import api.services.ml_scorer as ml_scorer
from api.services import scoring


@pytest.fixture(autouse=True)
def _rules_only(monkeypatch):
    # The name rules alone: the model's opinion moves with each retrain.
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _signals(domain: str) -> set[str]:
    _, _, reasons = scoring.calculate_score({"domain": domain})
    return {r.signal for r in reasons}


@pytest.mark.parametrize("host", [
    # Russian brands with a Russian or transliterated lure word
    "sberbank-online.pages.dev",      # 'online' lures for Sber alone
    "gosuslugi-vhod.netlify.app",
    "ozon-priz.vercel.app",
    "lk-gosuslugi.web.app",
    "avito-dostavka.netlify.app",
    "sberbank-bonus.tw1.ru",
    "tinkoff-kompensaciya.github.io",
    "wildberries-vozvrat.vercel.app",
    "vtb-login.pages.dev",            # a short brand, hyphenated
    # a global brand with an English lure word
    "paypal-login.netlify.app",
    "apple-id-verify.web.app",
    "microsoft-account-recovery.pages.dev",
    "secure-paypal.vercel.app",
    "zoom-sign-in.vercel.app",        # a two-word lure with a hyphen
    "adobesignin.netlify.app",        # glued
    # a Russian brand as the whole name
    "sberbank.tw1.ru",
    "gosuslugi.netlify.app",
])
def test_a_brand_with_a_lure_on_a_hosting_platform_is_brand_abuse(host):
    assert "brand_subdomain_abuse" in _signals(host), host


@pytest.mark.parametrize("host", [
    "netflix-clone.vercel.app",       # the student project on every platform
    "amazon-clone.netlify.app",
    "google-maps-demo.github.io",
    "sber-hackathon.github.io",       # a brand mentioned, no lure
    "vkusvill-bonus.netlify.app",     # VkusVill, not VK: the brand is a whole word
    "ozonelayer.pages.dev",           # 'ozone', not Ozon
    "mtsdelivery.vercel.app",         # glued to a short brand: too common
    "vk.github.io",                   # a short brand alone
    "my-portfolio.github.io",
    "blog.wordpress.com",
    "sber.bank.in",                   # a bank-only registry zone
    "yandex.ru.com",                  # the typosquat rule's (TLD confusion), not counted twice
])
def test_a_brand_mentioned_without_a_lure_is_not_flagged(host):
    assert "brand_subdomain_abuse" not in _signals(host), host


def test_the_platform_itself_and_its_operator_hosts_are_not_tenants():
    for host in ("netlify.app", "app.netlify.com", "pages.dev", "github.io"):
        assert "brand_subdomain_abuse" not in _signals(host), host


def test_one_signal_not_two_for_a_global_brand_alone():
    # paypal.netlify.app was already brand_subdomain_abuse; it stays one reason.
    _, _, reasons = scoring.calculate_score({"domain": "paypal.netlify.app"})
    assert [r.signal for r in reasons].count("brand_subdomain_abuse") == 1
