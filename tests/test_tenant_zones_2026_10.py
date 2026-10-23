"""Tenant zones kept whatever their own popularity (data/tenant_zones.json).

data/public_suffixes_in_top.json held the Public Suffix List rules whose
name is in the top 100k. Tranco's top 100k ranked tunnel, cloud and
dynamic-DNS zones by the DNS traffic of their tenants; the licensed ranking
drops tenant rows before it ranks a name (build_top_domains.fold), so after
#284 the file lost 468 private-section rules under 235 names —
trycloudflare.com, cloud.goog, jcloud.kz, playstation-cloud.com, ngrok.io,
on.aws, us.kg … — and hosts under them stopped being tenants: no
brand-on-tenant rule (paypal-login.trycloudflare.com), the publisher's
tenant guard and the extension's copy gone with them.

These tests pin:
  - the file's format and the rule that builds public_suffixes_in_top.json
    from it: every private-section rule of a listed operator, rules added
    later included, never an ICANN rule, plus the zones the PSL lacks;
  - the committed file holds them all, and its record and the extension's
    and the phone's copies agree;
  - the scorer reads hosts under them as tenants (s3.cloud.ru buckets
    included), and cloud.ru itself is still not exempt;
  - the served model keeps the copy of the file it was trained on until a
    model trained on the new one replaces it;
  - the blocklist publisher blocks a bucket exactly and never promotes
    cloud.ru.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

from api.services import ml_features, scoring

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
sys.path.insert(0, str(ROOT / "scripts"))

import build_public_suffixes_in_top as psl_in_top  # noqa: E402

_EVIDENCE = re.compile(r"^Verified \d{4}-\d{2}-\d{2}: \S")
# The four names PR #294 found missing, and one of each kind the diff found.
RESTORED = ("trycloudflare.com", "cloud.goog", "jcloud.kz", "playstation-cloud.com")
CLOUD_RU_BUCKET_ZONES = ("s3.cloud.ru", "s3-website.cloud.ru", "s3-alt.cloud.ru")
# The sha256 of data/public_suffixes_in_top.json the 2026-10-23 model was
# trained on (before this change).
PRE_RESTORE_SHA = "8a40e6f92329ec95f1047e30512355b0a96569d877f905dadb71a6a7cc60ef72"


def _doc() -> dict:
    return json.loads((DATA / "tenant_zones.json").read_text(encoding="utf-8"))


def _committed_rules() -> list[str]:
    return json.loads((DATA / "public_suffixes_in_top.json").read_text())


# ── The file ──

def test_the_file_is_well_formed():
    doc = _doc()
    names = doc["psl_operators"]["names"]
    assert names == sorted(set(names)), "psl_operators: sorted, no repeats"
    for name in names:
        assert name == name.lower().strip(".") and name.count(".") == 1, name
    zones = {k: v for k, v in doc["not_in_psl"].items() if not k.startswith("_")}
    assert zones
    for zone, why in zones.items():
        assert zone == zone.lower() and zone.count(".") >= 1, zone
        assert _EVIDENCE.match(why), (zone, why)
        assert psl_in_top._base(zone) not in names, zone


def test_the_loader_returns_both_sections():
    zones = psl_in_top.load_tenant_zones()
    assert set(RESTORED) <= zones.psl_operators
    assert set(CLOUD_RU_BUCKET_ZONES) <= set(zones.not_in_psl)


@pytest.mark.parametrize("text", ["{", "[]", '{"psl_operators": {"names": "x.com"}}',
                                  '{"not_in_psl": {"x.ru": "no evidence"}}',
                                  '{"psl_operators": {"names": ["Bad.Com"]}}'])
def test_a_malformed_file_is_refused(tmp_path, text):
    path = tmp_path / "tenant_zones.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        psl_in_top.load_tenant_zones(path)


def test_a_missing_file_adds_nothing(tmp_path):
    zones = psl_in_top.load_tenant_zones(tmp_path / "absent.json")
    assert zones.psl_operators == frozenset() and zones.not_in_psl == {}


# ── The rule that builds public_suffixes_in_top.json ──

PSL = """\
// ===BEGIN ICANN DOMAINS===
com
kz
jp
*.kawasaki.jp
!city.kawasaki.jp
op.example
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
trycloudflare.com
*.tunnel.op.example
apps.op.example
github.io
jcloud.kz
// ===END PRIVATE DOMAINS===
"""


def test_an_operators_private_rules_are_kept_without_popularity():
    zones = psl_in_top.TenantZones(frozenset({"trycloudflare.com", "op.example", "kawasaki.jp"}),
                                   {"s3.cloud.ru": "Verified 2026-10-23: x"})
    rules = psl_in_top.shared_suffix_rules({"github.io"}, PSL, zones, infrastructure=set())
    # github.io: its base is ranked; trycloudflare.com, tunnel.op.example and
    # apps.op.example: listed operators; s3.cloud.ru: not in the PSL at all.
    # Never an ICANN rule (op.example, kawasaki.jp), never an unlisted,
    # unranked zone (jcloud.kz here).
    assert rules == ["apps.op.example", "github.io", "s3.cloud.ru", "trycloudflare.com", "tunnel.op.example"]


def test_a_rule_the_operator_adds_later_is_picked_up():
    zones = psl_in_top.TenantZones(frozenset({"op.example"}), {})
    later = PSL.replace("apps.op.example\n", "apps.op.example\nnew-region.op.example\n")
    assert "new-region.op.example" in psl_in_top.shared_suffix_rules(set(), later, zones, infrastructure=set())


def test_the_ranked_rules_are_unchanged():
    zones = psl_in_top.TenantZones(frozenset(), {})
    assert psl_in_top.shared_suffix_rules({"github.io"}, PSL, zones, infrastructure=set()) == \
        psl_in_top.rules_in_top({"github.io"}, PSL)


# ── The committed files ──

def test_the_committed_file_holds_every_tenant_zone():
    rules = set(_committed_rules())
    zones = psl_in_top.load_tenant_zones()
    bases = {psl_in_top._base(r) for r in rules}
    # Every listed operator still has a rule in the PSL (a stale name shows here).
    assert zones.psl_operators <= bases, sorted(zones.psl_operators - bases)
    assert set(zones.not_in_psl) <= rules
    for zone in RESTORED + CLOUD_RU_BUCKET_ZONES:
        assert zone in rules, zone
    # Kinds the diff found besides the four PR #294 named.
    for rule in ("ngrok-free.app", "us.kg", "lambda-url.us-east-1.on.aws", "dynv6.net"):
        assert rule in rules, rule


def test_the_committed_file_is_what_its_record_says():
    record = json.loads((DATA / "top_domains_sources.json").read_text())["files"]["public_suffixes_in_top.json"]
    body = (DATA / "public_suffixes_in_top.json").read_bytes()
    assert record == {"rules": len(_committed_rules()), "sha256": hashlib.sha256(body).hexdigest()}


def test_the_consistency_check_passes():
    assert psl_in_top.verify_consistency() == 0


def test_the_extension_and_the_phone_carry_them():
    data_js = (ROOT / "packages" / "extension-core" / "src" / "utils" / "scorer-data.js").read_text()
    tenant = json.loads(re.search(r'"hostingTenantSuffixes": (\[.*?\])', data_js).group(1))
    phone = (ROOT / "mobile" / "modules" / "cleanway-vpn" / "android" / "src" / "main" / "assets"
             / "shared_suffixes.txt").read_text().splitlines()
    for zone in RESTORED + CLOUD_RU_BUCKET_ZONES:
        assert zone in tenant and zone in phone, zone


# ── The scorer ──

@pytest.mark.parametrize("host", ["random-words-here.trycloudflare.com", "x.cloud.goog", "shop.jcloud.kz",
                                  "a.playstation-cloud.com", "bucket.s3.cloud.ru", "site.s3-website.cloud.ru",
                                  "b.s3-alt.cloud.ru", "abc.ngrok-free.app", "x.us.kg"])
def test_hosts_under_them_are_tenants(host):
    assert scoring._is_under_shared_suffix(host)


@pytest.mark.parametrize("host", ["trycloudflare.com", "www.trycloudflare.com", "s3.cloud.ru", "www.s3.cloud.ru",
                                  "cloud.ru", "www.cloud.ru", "console.cloud.ru"])
def test_the_zone_and_the_operators_own_hosts_are_not(host):
    assert not scoring._is_under_shared_suffix(host)


@pytest.mark.parametrize("host,brand", [
    ("paypal-login.trycloudflare.com", "paypal"),
    ("microsoft-verify.cloud.goog", "microsoft"),
    ("sberbank-bonus.jcloud.kz", "sberbank"),
    ("apple-id-verify.s3.cloud.ru", "apple"),
    ("gosuslugi.s3-website.cloud.ru", "gosuslugi"),
    ("netflix-billing-update.ngrok-free.app", "netflix"),
])
def test_a_brand_with_a_lure_on_them_is_brand_on_tenant(host, brand):
    assert scoring._check_brand_on_hosting_tenant(host) == brand


@pytest.mark.parametrize("host", ["zq7x1random.s3.cloud.ru", "my-backups.s3.cloud.ru",
                                  "debate-modifications-smilies-introduces.trycloudflare.com",
                                  "netflix-clone.trycloudflare.com"])
def test_a_tenant_without_a_brand_and_a_lure_is_not(host):
    assert scoring._check_brand_on_hosting_tenant(host) is None


def test_cloud_ru_itself_is_still_not_exempt():
    # Verified 2026-10-23. Ownership is proven: the .ru registry shows no
    # organisation (RU-CENTER, created 2004), but NS ns01/ns02.cloud.ru sit
    # in Cloud.ru's RIPE networks (194.5.92.0/24 SBERCLOUD-NET,
    # 46.243.141.0/22 '"Cloud Technologies" LLC trading as Cloud.ru') and
    # cloud.ru / www.cloud.ru serve an OV certificate with O=Cloud.ru LLC
    # (GlobalSign, to 2027-03-31). It stays unexempt all the same: an
    # exemption covers every host under the registrable, and the bucket
    # zones above are not the only ones where a customer names the host —
    # *.containers, *.apigw, *.cr and *.notebooks.cloud.ru resolve any
    # label (DoH), and CT logs hold 61 wildcard names under cloud.ru with
    # a certificate valid that day.
    assert "cloud.ru" not in scoring._BRAND_LEGIT_DOMAINS
    assert scoring._check_typosquatting_v2("cloud.ru") == ("icloud.com", "high similarity")


# ── The served model keeps the file it learned ──

def test_the_served_model_reads_the_copy_it_was_trained_on():
    import api.services.ml_scorer as ml_scorer

    meta = json.loads((DATA / "model_meta.json").read_text())
    sha = meta["feature_data"]["public_suffixes_in_top"]["sha256"]
    assert ml_scorer.is_serving(), ml_scorer.model_status()
    served = ml_scorer._feature_data
    features = ml_features.extract_ml_features("paypal-login.trycloudflare.com", served)
    if sha == PRE_RESTORE_SHA:
        # The 2026-10-23 model never saw the restored zones as tenants: it is
        # served its archived copy, and reads the tunnel as it learned it.
        archive = ml_features.archive_path(str(DATA), "public_suffixes_in_top.json", sha)
        assert Path(archive).exists()
        assert not served.shared_suffixes & {"trycloudflare.com"}
        assert features["is_hosting_subdomain"] == 0.0
    else:
        # A model trained after this change reads the live file.
        assert {"trycloudflare.com"} <= served.shared_suffixes
        assert features["is_hosting_subdomain"] == 1.0


# ── The blocklist publisher ──

def test_the_publisher_blocks_a_bucket_exactly_and_never_cloud_ru():
    import refresh_dangerous_domains as rdd

    shared = rdd.default_shared_suffixes()
    for zone in RESTORED + CLOUD_RU_BUCKET_ZONES:
        assert zone in shared, zone
    hosts = ["apple-id-verify.s3.cloud.ru", "sber-bonus.s3-website.cloud.ru", "lk-vtb.s3.cloud.ru",
             "paypal-login.trycloudflare.com"]
    # cloud.ru is in the top 1M (rank ~175,000), so before this change the
    # buckets were skipped as "a popular organisation's own host".
    out = rdd.build_blockset(hosts, set(), is_popular=lambda reg: reg == "cloud.ru", brand_owned=frozenset())
    assert out == set(hosts)
