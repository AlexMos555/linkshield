"""The name-shape rules (entropy, digits, n-grams, vowels, consonant runs,
length — scoring.py 3.13-3.32) judge the name someone chose.

On a dynamic-DNS service or a hosting platform that is the tenant's label
(gedivan in gedivan.duckdns.org), not the platform's own name. Until
2026-10-15 they read the last two labels, so every *.duckdns.org host got
+12 for 'duckdns' (a 5-consonant run and a 1:6 vowel ratio) whatever its
own name was, and a generated tenant name was never looked at.
"""
import pytest

from api.services import ml_scorer
from api.services.hosting_platforms import DYNAMIC_DNS_SUFFIXES
from api.services.scoring import DYNAMIC_DNS_WEIGHT, calculate_score

LEXICAL = {
    "high_entropy", "medium_entropy", "high_digit_ratio", "long_domain_name",
    "unnatural_ngram", "suspicious_ngram", "abnormal_vowel_ratio", "consonant_cluster",
}


@pytest.fixture(autouse=True)
def no_ml(monkeypatch):
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _score(host: str):
    score, level, reasons = calculate_score({"domain": host, "raw_url": host})
    return score, level.value, {r.signal: r.weight for r in reasons}


def _lexical(host: str) -> set[str]:
    return set(_score(host)[2]) & LEXICAL


@pytest.mark.parametrize("host", [
    "gedivan.duckdns.org", "foo.duckdns.org", "nas.duckdns.org", "home.ddns.net",
    "printer.ipv64.net", "mb-way.ns01.info",
])
def test_the_platform_name_is_not_scored(host):
    assert _lexical(host) == set()


def test_a_plain_duckdns_name_carries_only_the_dynamic_dns_weight():
    score, level, signals = _score("gedivan.duckdns.org")
    assert signals == {"dynamic_dns_host": DYNAMIC_DNS_WEIGHT}
    assert score == DYNAMIC_DNS_WEIGHT and level == "safe"


@pytest.mark.parametrize("suffix", sorted(DYNAMIC_DNS_SUFFIXES))
def test_no_dynamic_dns_service_lends_its_name(suffix):
    assert _lexical(f"garden.{suffix}") == set()


@pytest.mark.parametrize("host, signal", [
    # a generated tenant name is now what gets judged
    ("xkqzvbnmwrtp.duckdns.org", "consonant_cluster"),
    ("q7x9k2m4p8z1.ddns.net", "high_digit_ratio"),
    ("wxkqzvbnmtrplkjh.tw1.ru", "consonant_cluster"),
    ("a1b2c3d4e5f6g7h8.vercel.app", "high_digit_ratio"),
])
def test_the_tenant_label_is_judged(host, signal):
    assert signal in _lexical(host)


@pytest.mark.parametrize("host, signal", [
    # registered names and subdomains of registered names: unchanged
    ("xkqzvbnmwrtp.com", "consonant_cluster"),
    ("shop.xkqzvbnmwrtp.com", "consonant_cluster"),
])
def test_registered_names_are_read_as_before(host, signal):
    assert signal in _lexical(host)


@pytest.mark.parametrize("host", [
    "kvs.gov.spb.ru", "www.example.com", "malsup.github.io", "blog.wordpress.com",
    "duckdns.org", "www.duckdns.org",
])
def test_ordinary_names_stay_clean(host):
    assert _lexical(host) == set()
