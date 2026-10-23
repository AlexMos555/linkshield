"""Brand-owned alternates the licensed ranking dropped from the allowlist
(data/typosquat_targets.json 'alternates').

Until PR #284 the Tranco top-100k answered "safe" for googlemail.com,
outlook.de, yahoo.de or cloud.ru before the typosquat rule ran. The
Majestic Million + CrUX ranking does not carry them, so the rule called
them look-alikes of google.com, outlook.com, yahoo.com and icloud.com. On
2026-10-23 every name the rule flagged among the 44,736 that left the
allowlist (190) was checked by RDAP / registry WHOIS, DNS over HTTPS, the
TLS certificate and a plain homepage GET; the ones whose owner is proven
are listed with that evidence. These tests pin:

  - the section's format: every domain with its dated evidence, never a
    listed brand's own domain, never in two places;
  - a malformed section exempts nothing and breaks nothing else;
  - the listed names are no one's look-alike now, and nothing else moved:
    the brands keep their rule, close look-alikes of the listed names are
    still flagged;
  - what the review left out on purpose: tenant zones (an exemption
    covers every host under the registrable: cloud.ru is Cloud.ru's, but
    *.s3.cloud.ru is its customers' buckets) and names without proof.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from api.services import ml_features, scoring
from api.services.scoring import (
    ALTERNATE_OFFICIAL_DOMAINS,
    ALTERNATE_UNRELATED_DOMAINS,
    GLOBAL_TYPOSQUAT_TARGETS,
    _check_typosquatting_v2,
    calculate_score,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "typosquat_targets.json"
_EVIDENCE = re.compile(r"^Verified \d{4}-\d{2}-\d{2}: \S")


@pytest.fixture
def no_ml(monkeypatch):
    import api.services.ml_scorer as ml_scorer
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _section() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))["alternates"]


def _entries() -> dict:
    return {k: v for k, v in _section().items() if not k.startswith("_")}


def _listed(field: str) -> set[str]:
    return {d for e in _entries().values() for d in e.get(field, {})}


# ── The data file ──

def test_the_section_loads_into_the_exemptions():
    assert _listed("official") and _listed("unrelated")
    assert _listed("official") <= ALTERNATE_OFFICIAL_DOMAINS <= scoring._BRAND_OFFICIAL_DOMAINS
    assert _listed("unrelated") <= ALTERNATE_UNRELATED_DOMAINS
    assert ALTERNATE_UNRELATED_DOMAINS <= scoring._BRAND_LEGIT_DOMAINS - scoring._BRAND_OFFICIAL_DOMAINS
    # Both spellings of an IDN only; nothing the file does not list.
    assert {d for d in ALTERNATE_OFFICIAL_DOMAINS if d.isascii()} == _listed("official")
    assert {d for d in ALTERNATE_UNRELATED_DOMAINS if d.isascii()} == _listed("unrelated")


def test_every_entry_names_listed_brands_and_dates_its_evidence():
    for key, entry in _entries().items():
        assert entry["owner"].strip(), key
        assert entry["names"] and set(entry["names"]) <= set(GLOBAL_TYPOSQUAT_TARGETS), key
        assert set(entry) <= {"owner", "names", "official", "unrelated"}, key
        for field in ("official", "unrelated"):
            for domain, why in entry.get(field, {}).items():
                assert _EVIDENCE.match(why), (key, domain, why)


def test_every_domain_is_the_name_the_rule_reads_and_no_listed_brands():
    listed = set(GLOBAL_TYPOSQUAT_TARGETS.values())
    groups = scoring.RU_BRAND_GROUPS + scoring.MEASURED_GLOBAL_GROUPS
    elsewhere = {d for g in groups for d in g.official | g.unrelated}
    seen: set[str] = set()
    for domain in _listed("official") | _listed("unrelated"):
        assert domain not in listed, domain
        assert domain not in elsewhere, f"{domain} is already in the Russian file or 'measured'"
        # The typosquat rule compares the last two labels (the Russian
        # registrable under a Russian zone): an exemption must be that name.
        base = scoring._ru_registrable_domain(domain) or scoring._extract_base_domain(domain)
        assert base == domain, domain
        assert domain not in seen
        seen.add(domain)
    assert not _listed("official") & _listed("unrelated")


@pytest.mark.parametrize("mutate, why", [
    (lambda s: s["google"]["official"].update({"google.com": "Verified 2026-10-23: x"}), "a listed domain"),
    (lambda s: s["google"].update({"names": ["gogle"]}), "a name 'brands' does not have"),
    (lambda s: s["google"].update({"not_typos": {"goggle": "a word"}}), "a switch only 'measured' may set"),
    (lambda s: s["google"]["official"].update({"googlemail.com": ""}), "no evidence"),
    (lambda s: s["apple"]["unrelated"].update({"googlemail.com": "Verified 2026-10-23: x"}), "in two places"),
])
def test_a_malformed_section_exempts_nothing_and_breaks_nothing_else(tmp_path, monkeypatch, mutate, why):
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    mutate(raw["alternates"])
    (tmp_path / "typosquat_targets.json").write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(scoring, "_DATA_DIR", str(tmp_path))
    assert scoring._load_global_alternates() == (frozenset(), frozenset()), why
    assert scoring._load_typosquat_targets()["google"] == "google.com"
    assert scoring._load_measured_global_groups() == (scoring.MEASURED_GLOBAL_GROUPS, scoring._NOT_IN_MODEL)


def test_no_section_exempts_nothing(tmp_path, monkeypatch):
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    del raw["alternates"]
    (tmp_path / "typosquat_targets.json").write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(scoring, "_DATA_DIR", str(tmp_path))
    assert scoring._load_global_alternates() == (frozenset(), frozenset())


def test_the_brands_keep_their_rule():
    # 'measured' puts a name under the slip rule; this section must not.
    for entry in _entries().values():
        for name in entry["names"]:
            assert name not in scoring._MEASURED_GLOBAL_NAMES, name
            assert not scoring._NAME_RULES[name].slips_only, name


# ── What the listed names do now ──

# Listed names, with the brand the rule told readers each imitated.
_WAS = {
    "googlemail.com": "google.com", "googl.com": "google.com", "google.us": "google.com", "google.hk": "google.com",
    "cloud.google": "icloud.com", "youtube.ru": "youtube.com",
    "microsoft.us": "microsoft.com", "office365.us": "office.com", "onedrive.us": "onedrive.live.com",
    "apple.cn": "apple.com", "cloud.us": "icloud.com", "hicloud.com": "icloud.com",
    "facebook.net": "facebook.com", "whatsapp.net": "whatsapp.com",
    "yahoo.de": "yahoo.com", "ymail.com": "gmail.com",
    "adobelogin.com": "adobe.com", "hsbcnet.com": "hsbc.com", "nintendo.fr": "nintendo.com",
    "protonmail.ch": "proton.me", "santander.pl": "santander.com", "twitter.biz": "twitter.com",
    "tiktokv.com": "tiktok.com",
    "esignal.com": "signal.org", "loves.com": "lowes.com",
}


def test_every_listed_name_is_no_ones_look_alike():
    for domain in sorted(_listed("official") | _listed("unrelated")):
        assert _check_typosquatting_v2(domain) is None, domain
        assert _check_typosquatting_v2("www." + domain) is None, domain
        # The model's is_typosquat feature reads the same rule.
        assert ml_features.extract_ml_features(domain)["is_typosquat"] == 0.0, domain


@pytest.mark.parametrize("domain, was", sorted(_WAS.items()))
def test_a_reviewed_name_is_safe_on_the_name_rules(no_ml, monkeypatch, domain, was):
    _, level, reasons = calculate_score({"domain": domain})
    assert level.value == "safe", (domain, [(r.signal, r.weight) for r in reasons])
    assert "typosquatting" not in {r.signal for r in reasons}
    # Without its line the rule flags it again, as it did after PR #284.
    monkeypatch.setattr(scoring, "_BRAND_LEGIT_DOMAINS", scoring._BRAND_LEGIT_DOMAINS - {domain})
    assert _check_typosquatting_v2(domain)[0] == was


@pytest.mark.parametrize("host, legit", [
    # A letter, a glyph, a word or a TLD away from a listed name: still the rule's.
    ("googlemail.top", "google.com"),
    ("googl.top", "google.com"),
    ("y0utube.ru", "youtube.com"),
    ("micros0ft.us", "microsoft.com"),
    ("rnicrosoft.us", "microsoft.com"),
    ("icloud.ru", "icloud.com"),
    ("icl0ud.ru", "icloud.com"),
    ("whatsap.net", "whatsapp.com"),
    ("whatsapp-net.com", "whatsapp.com"),
    ("yah00.de", "yahoo.com"),
    ("yahooo.de", "yahoo.com"),
    ("ymai1.com", "gmail.com"),
    ("adobe-login.com", "adobe.com"),
    ("adobelogin.top", "adobe.com"),
    ("hsbc-net.com", "hsbc.com"),
    ("nlntendo.fr", "nintendo.com"),
    ("pr0tonmail.ch", "proton.me"),
    ("protonmail.cc", "proton.me"),
    ("santamder.pl", "santander.com"),
    ("tw1tter.biz", "twitter.com"),
    ("rob1ox.us", "roblox.com"),
    ("capital0ne.ca", "capitalone.com"),
    ("stearn.tv", "store.steampowered.com"),
    ("lovves.com", "lowes.com"),
    # An official .ru alternate's name under ru.com reads as that site now.
    ("youtube.ru.com", "youtube.ru"),
])
def test_close_look_alikes_are_still_flagged(host, legit):
    assert _check_typosquatting_v2(host)[0] == legit


def test_the_exemption_is_the_typosquat_rules_only():
    # A brand in a subdomain of a listed name is still brand_subdomain_abuse.
    assert scoring._check_brand_in_subdomain("paypal.googlemail.com") == "paypal"


# ── What the review left out ──

@pytest.mark.parametrize("domain", [
    # The owner's, but anyone can get a name under them: an exemption would
    # cover every tunnel, codespace, tenant and Azure resource.
    "trycloudflare.com", "cloudflare.net", "github.dev", "onmicrosoft.com", "azure.net", "azure.cn",
    "signalr.net", "cloud.goog",
    # Cloud.ru's own, but its S3 storage serves every customer's bucket at
    # <bucket>.s3.cloud.ru (wildcard DNS, a *.s3.cloud.ru certificate).
    "cloud.ru",
    # Not proven: privacy-proxied and not Google's (goole.com); no registrant
    # anywhere and shared DNS (outlook.de, myoffice.ru, nintendo.ru); a
    # brand-protection registrar but neither the owner's DNS nor a
    # certificate naming it (amazon.eu, aws.dev, confluent.cloud); registry
    # data out of reach (ebay.ph, nintendo.pt).
    "goole.com", "outlook.de", "myoffice.ru", "nintendo.ru", "amazon.eu", "aws.dev", "confluent.cloud",
    "ebay.ph", "nintendo.pt",
])
def test_names_the_review_left_out_are_still_flagged(domain):
    assert domain not in scoring._BRAND_LEGIT_DOMAINS
    assert _check_typosquatting_v2(domain) is not None


@pytest.mark.parametrize("host", ["zq7x1random.s3.cloud.ru", "apple-id-verify.s3.cloud.ru"])
def test_a_bucket_on_cloud_ru_keeps_the_typosquat_rule(no_ml, host):
    # Any label under s3.cloud.ru resolves and is served under Cloud.ru's
    # certificate, so the bucket's name is its customer's choice. With
    # cloud.ru exempt, a random bucket went from caution to safe. Since
    # 2026-10-23 s3.cloud.ru is a tenant zone (data/tenant_zones.json: the
    # brand-on-tenant rule reads the bucket's name), but cloud.ru stays
    # unexempt: *.containers, *.apigw, *.cr and *.notebooks.cloud.ru resolve
    # any label too (tests/test_tenant_zones_2026_10.py).
    _, level, reasons = calculate_score({"domain": host})
    assert level.value != "safe", (host, [(r.signal, r.weight) for r in reasons])
    assert "typosquatting" in {r.signal for r in reasons}
    assert _check_typosquatting_v2(host)[0] == "icloud.com"
