"""Cleanway's popularity ranking comes from sources a paid product may use.

data/top_100k.json, data/top_10k.json, data/public_suffixes_in_top.json and
the Redis top-1M were Tranco's until 2026-10-23 — Tranco states no licence of
its own and its default list averages Cloudflare Radar (CC BY-NC 4.0).
scripts/build_top_domains.py builds them from the Majestic Million (CC BY
3.0) and the Chrome UX Report top origins (CC BY 4.0). These tests hold the
rank's rules (folding, tenants, the Russia factor, the Dowdall merge, reported
names), the refusal paths that keep the previous files, the archive that
keeps the served model on the files it learned, and the committed files to
their provenance record.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_top_domains as btd  # noqa: E402
import refresh_training_feeds as rtf  # noqa: E402

DATA = ROOT / "data"


# ── Licences ──

def test_no_unlicensed_source_is_read():
    urls = " ".join([btd.MAJESTIC, btd.CRUX, btd.PSL_URL] + [s.url for s in rtf.PHISHING_SOURCES]).lower()
    for banned in ("tranco", "radar", "umbrella", "alexa", "openphish", "abuse.ch", "phishtank"):
        assert banned not in urls, banned
    for source in ("majestic_million", "crux"):
        assert btd.LICENCES[source]["licence"].startswith("CC BY "), source
        assert btd.LICENCES[source]["attribution"]


def test_the_committed_files_are_what_their_record_says():
    record = json.loads((DATA / btd.SOURCES).read_text())
    for name, entry in record["files"].items():
        assert hashlib.sha256((DATA / name).read_bytes()).hexdigest() == entry["sha256"], (
            f"data/{name} changed without scripts/build_top_domains.py")
    assert record["sources"]["majestic_million"]["licence"] == "CC BY 3.0"
    assert record["sources"]["crux"]["licence"] == "CC BY 4.0"
    assert set(record["sources"]["crux"]["months"]) == {"global", "country/ru"}
    assert "tranco" not in json.dumps(record).lower()


def test_top_10k_is_the_head_of_top_100k():
    top = json.loads((DATA / "top_100k.json").read_text())
    ranks = json.loads((DATA / "top_10k.json").read_text())
    assert len(top) == len(set(top)) == 100_000
    assert list(ranks) == top[:10_000]
    assert list(ranks.values()) == list(range(1, 10_001))


@pytest.mark.parametrize("name", ["google.com", "gosuslugi.ru", "sberbank.ru", "vk.com", "yandex.ru",
                                  "wikipedia.org", "github.io", "bbc.co.uk", "gov.spb.ru"])
def test_names_the_scorer_relies_on_are_in_the_top(name):
    assert name in set(json.loads((DATA / "top_100k.json").read_text()))


# ── The scorer's registrable domain, without the scorer ──

def _corpus() -> list[str]:
    hosts = {
        "kvs.gov.spb.ru", "zenit.kfis.gov.spb.ru", "herzen.spb.ru", "a.b.hosting.myjino.ru", "b.hosting.myjino.ru",
        "bbc.co.uk", "news.bbc.co.uk", "login.example.co.uk", "apple.com.cn", "x.y.gob.mx", "www.pref.hokkaido.jp",
        "example.com", "www.example.com", "a.b.c.example.com", "localhost", "xn--80aswg.xn--p1ai",
        "www.xn--d1acj3b.xn--p1ai", "сайт.рф", "кремль.рф", "x.spb.ru", "spb.ru", "gov.ru", "rosreestr.gov.ru",
        "idg.chph.ras.ru", "shop.com.tr", "foo.github.io", "evil.s3.amazonaws.com", "co.uk", "",
    }
    for path in ("tests/data/ru_heuristics_legit.txt", "tests/data/ru_heuristics_phish.txt",
                 "data/benchmark_legit_ru.txt", "data/canary_must_resolve.txt"):
        for raw in (ROOT / path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                hosts.add(line.split(" | ")[0].strip().lower())
    return sorted(hosts)


def test_registrable_domain_is_the_scorers():
    from api.services.scoring import registrable_domain

    for host in _corpus():
        assert btd.registrable_domain(host) == registrable_domain(host), host


def test_the_redis_refresh_imports_nothing_the_runner_lacks():
    """refresh-tranco.yml installs httpx and redis only: the builder and the
    refresh must import without pydantic, fastapi or the scorer."""
    code = (
        "import sys, importlib.abc\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name.split('.')[0] in ('pydantic', 'fastapi', 'pydantic_settings', 'numpy') "
        "or name in ('api.services.scoring', 'api.models', 'api.config'):\n"
        "            raise ImportError('blocked: ' + name)\n"
        "sys.meta_path.insert(0, Block())\n"
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "import refresh_tranco, build_top_domains\n"
        "print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


# ── The rank ──

PSL_TEXT = (
    "// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\nru\nspb.ru\nio\n// ===END ICANN DOMAINS===\n"
    "// ===BEGIN PRIVATE DOMAINS===\ngithub.io\nus.org\n*.platform.example\nspb.ru\n"
    "// ===END PRIVATE DOMAINS===\n"
)


def test_fold_reads_registrable_domains_and_drops_tenants():
    psl = btd.parse_psl(PSL_TEXT)
    suffixes = btd.tenant_suffixes(psl)
    rows = [(5, "play.google.com"), (3, "google.com"), (9, "news.bbc.co.uk"), (4, "malsup.github.io"),
            (2, "gwcu.us.org"), (6, "kvs.gov.spb.ru"), (7, "94.183.174.80"), (8, "1.0.0.127.in-addr.arpa"),
            (1, "github.io"), (10, "www.github.io"), (11, "a.b.platform.example")]
    assert btd.fold(rows, suffixes) == {
        "google.com": 3, "bbc.co.uk": 9, "gov.spb.ru": 6, "github.io": 1}


def _sources(majestic, crux_global, crux_ru, reported=()):
    return btd.Sources(majestic, {"global": crux_global, "country/ru": crux_ru},
                       {"global": "202609", "country/ru": "202609"}, btd.parse_psl(PSL_TEXT),
                       {"feed": frozenset(reported)})


def test_dowdall_puts_names_both_lists_carry_first():
    ranking = btd.rank(_sources(
        majestic=[(1, "a.com"), (2, "both.com"), (3, "c.com")],
        crux_global=[(1000, "www.both.com"), (1000, "d.com")],
        crux_ru=[]))
    # a.com 1/1, both.com 1/2 + 1/1000, c.com 1/3, d.com 1/1000.
    assert ranking.names == ["a.com", "both.com", "c.com", "d.com"]
    ranking = btd.rank(_sources(
        majestic=[(1000, "x.com"), (1000, "both.com")],
        crux_global=[(1000, "both.com"), (1000, "y.com")], crux_ru=[]))
    assert ranking.names[0] == "both.com"


def test_russia_counts_at_its_bucket_times_the_factor():
    ranking = btd.rank(_sources(majestic=[], crux_global=[(10_000, "global.com")],
                                crux_ru=[(1000, "gorzdrav.spb.ru"), (1000, "global.com")]))
    assert ranking.crux["gorzdrav.spb.ru"] == 1000 * btd.RU_FACTOR
    assert ranking.crux["global.com"] == 1000 * btd.RU_FACTOR  # the better of 10,000 and 6,000
    assert ranking.names == ["global.com", "gorzdrav.spb.ru"]


def test_a_reported_name_needs_both_lists_or_many_links_or_the_very_top():
    ranking = btd.rank(_sources(
        majestic=[(5, "platform.com"), (50, "abused.com"), (9_000, "files.example"), (500_000, "linked.com")],
        crux_global=[(1000, "www.platform.com"), (50_000, "lure.top"), (1000, "visited.example")],
        crux_ru=[(5000, "abused.com"), (5000, "scam.example")],
        reported={"platform.com", "www.abused.com", "lure.top", "linked.com", "files.example",
                  "visited.example", "scam.example"}))
    # platform.com: both lists' top 100,000; abused.com and files.example:
    # Majestic's top 10,000; visited.example: CrUX's top 1,000.
    assert set(ranking.names) == {"platform.com", "abused.com", "files.example", "visited.example"}
    # lure.top: CrUX 50,000 only; scam.example: Russia 5,000 x 6; linked.com: Majestic 500,000.
    assert set(ranking.removed_reported) == {"lure.top", "linked.com", "scam.example"}


# ── Building the files ──

def _crux_gz(rows) -> bytes:
    return gzip.compress(("origin,rank\n" + "".join(f"https://{h},{r}\n" for r, h in rows)).encode())


def _majestic_csv(names) -> str:
    head = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
    return head + "".join(f"{i},{i},{d},x,1,1,{d},x,0,0,0,0\n" for i, d in enumerate(names, 1))


def _world(n=40, reported=("evil-login.com",), first=()):
    names = ["github.io", "us.org", *first] + [f"site{i}.com" for i in range(n)]
    responses = {
        btd.MAJESTIC: _majestic_csv(names),
        btd.CRUX.format(scope="global", month="202609"): _crux_gz([(1000, f"www.site{i}.com") for i in range(n)]
                                                                 + [(5000, "evil-login.com")]),
        btd.CRUX.format(scope="country/ru", month="202609"): _crux_gz([(1000, "gorzdrav.spb.ru")]),
        btd.PSL_URL: PSL_TEXT,
    }
    for spec in rtf.PHISHING_SOURCES:
        responses[spec.url] = json.dumps(list(reported)) if spec.parser is rtf.parse_json_list else "\n".join(reported)
    return responses


def _fetch(responses):
    def fetch(url, timeout=180.0):
        if url not in responses:
            raise httpx.HTTPStatusError("404", request=httpx.Request("GET", url), response=httpx.Response(404))
        value = responses[url]
        return value if isinstance(value, bytes) else value.encode()
    return fetch


@pytest.fixture
def small(monkeypatch, tmp_path):
    for name, value in {"MIN_MAJESTIC": 10, "CRUX_SCOPES": {"global": 5, "country/ru": 1}, "MIN_PSL_RULES": 3,
                        "MIN_FEEDS": 3, "TOP_N": 20, "TOP_RANKED_N": 5, "REDIS_N": 30, "MIN_PSL_IN_TOP": 1}.items():
        monkeypatch.setattr(btd, name, value)
    monkeypatch.setattr(btd.psl_in_top, "load_infrastructure", lambda: set())
    data = tmp_path / "data"
    data.mkdir()
    return data


def _args(**kw):
    return argparse.Namespace(dry_run=kw.get("dry_run", False), allow_churn=kw.get("allow_churn", True),
                              cache=None)


TODAY = datetime.date(2026, 10, 23)


def _build(data, responses, meta=None, **kw):
    return btd.build(_args(**kw), data_dir=str(data), meta_path=str(meta or data / "model_meta.json"),
                     fetch=_fetch(responses), today=TODAY)


def test_build_writes_the_four_files(small):
    assert _build(small, _world()) == 0
    top = json.loads((small / "top_100k.json").read_text())
    assert len(top) == 20 and {"evil-login.com"}.isdisjoint(top)  # reported, one list only
    assert json.loads((small / "top_10k.json").read_text()) == {d: i + 1 for i, d in enumerate(top[:5])}
    rules = json.loads((small / "public_suffixes_in_top.json").read_text())
    assert rules == ["github.io", "us.org"]
    record = json.loads((small / "top_domains_sources.json").read_text())
    assert record["built"] == "2026-10-23"
    assert record["files"]["top_100k.json"]["sha256"] == hashlib.sha256((small / "top_100k.json").read_bytes()).hexdigest()
    assert not list(small.glob("*.tmp"))


@pytest.mark.parametrize("broken", ["majestic", "crux", "psl", "feeds"])
def test_a_broken_source_keeps_every_previous_file(small, broken):
    assert _build(small, _world()) == 0
    before = {p.name: p.read_bytes() for p in small.iterdir()}
    responses = _world(n=41)
    if broken == "majestic":
        responses[btd.MAJESTIC] = "<html>503</html>"
    elif broken == "crux":
        del responses[btd.CRUX.format(scope="global", month="202609")]
    elif broken == "psl":
        responses[btd.PSL_URL] = "<html>not the list</html>"
    else:
        for spec in rtf.PHISHING_SOURCES[:2]:
            del responses[spec.url]
    assert _build(small, responses) == 2
    assert {p.name: p.read_bytes() for p in small.iterdir()} == before


def test_a_list_far_from_the_previous_one_needs_allow_churn(small):
    assert _build(small, _world()) == 0
    before = (small / "top_100k.json").read_bytes()
    other = _world()
    other[btd.MAJESTIC] = _majestic_csv(["github.io", "us.org"] + [f"other{i}.com" for i in range(40)])
    other[btd.CRUX.format(scope="global", month="202609")] = _crux_gz([(1000, f"other{i}.com") for i in range(40)])
    assert _build(small, other, allow_churn=False) == 2
    assert (small / "top_100k.json").read_bytes() == before
    assert _build(small, other, allow_churn=False, dry_run=True) == 0  # reports, writes nothing
    assert (small / "top_100k.json").read_bytes() == before


def test_a_dry_run_writes_nothing(small):
    assert _build(small, _world(), dry_run=True) == 0
    assert list(small.iterdir()) == []


# ── The served model keeps the files it learned ──

def _meta_for(data, meta):
    from api.services.ml_features import feature_data_record

    meta.write_text(json.dumps({"feature_data": feature_data_record(str(data))}))


def test_a_rebuild_archives_what_the_model_reads_and_prunes_what_none_does(small, tmp_path):
    assert _build(small, _world()) == 0
    meta = tmp_path / "model_meta.json"
    _meta_for(small, meta)
    old = {name: (small / name).read_bytes() for name in ("top_100k.json", "public_suffixes_in_top.json")}

    # The list moves on: the model's copy of what changed goes to
    # data/feature_data/; the suffix rules did not change and stay live.
    moved = _world(first=("new-first.com",))
    assert _build(small, moved, meta=meta) == 0
    archive = small / "feature_data"
    top_sha = hashlib.sha256(old["top_100k.json"]).hexdigest()
    assert (archive / btd.archive_name("top_100k.json", top_sha)).read_bytes() == old["top_100k.json"]
    psl_sha = hashlib.sha256(old["public_suffixes_in_top.json"]).hexdigest()
    assert not (archive / btd.archive_name("public_suffixes_in_top.json", psl_sha)).exists()
    assert (small / "public_suffixes_in_top.json").read_bytes() == old["public_suffixes_in_top.json"]
    assert {"new-first.com"} <= set(json.loads((small / "top_100k.json").read_text()))

    # ml_scorer finds the model's copies by their hashes.
    from api.services.ml_features import resolve_feature_data

    data, where = resolve_feature_data(json.loads(meta.read_text()), str(small))
    assert data is not None and {"new-first.com"}.isdisjoint(data.top_domains), where
    assert where == ", ".join(sorted([os.path.join("feature_data", btd.archive_name("top_100k.json", top_sha)),
                                      "public_suffixes_in_top.json"]))

    # A model trained on the new files: the archive is no one's and goes.
    _meta_for(small, meta)
    assert _build(small, moved, meta=meta) == 0
    assert not archive.exists()


def test_the_archive_name_is_what_the_scorer_looks_for():
    from api.services.ml_features import archive_path

    sha = "ab" * 32
    assert archive_path("/d", "top_100k.json", sha) == os.path.join("/d", "feature_data", btd.archive_name("top_100k.json", sha))


# ── The infrastructure names ──

def test_infrastructure_names_are_registrable_and_never_user_content():
    from api.services.hosting_platforms import USER_CONTENT_HOSTS, is_shared_platform_site
    from api.services.scoring import HOSTING_PLATFORMS, registrable_domain

    names = btd.psl_in_top.load_infrastructure()
    assert len(names) > 150
    lines = [line.split("#", 1)[0].strip() for line in (DATA / "infrastructure_domains.txt").read_text().splitlines()]
    entries = [x for x in lines if x]
    assert len(entries) == len(set(entries)), "duplicate lines"
    for name in names:
        assert registrable_domain(name) == name, name
        assert name not in HOSTING_PLATFORMS and name not in USER_CONTENT_HOSTS, name
        assert not is_shared_platform_site(name), name
    for never in ("googleusercontent.com", "sharepoint.com", "github.com", "t.me", "blogspot.com"):
        assert never not in names, never


def test_every_infrastructure_name_is_vetoed_on_the_phone():
    import build_mobile_assets

    veto = set(build_mobile_assets.build())
    shared = set(build_mobile_assets.build_shared())
    for name in btd.psl_in_top.load_infrastructure() - shared:
        assert name in veto, name


def test_public_suffix_rules_cover_the_infrastructure_names_too():
    """The phone vetoes the infrastructure names, so it must know their
    tenant suffixes (x.blob.core.windows.net under windows.net): the rules are
    looked up for those bases as well as for the top 100k."""
    top = set(json.loads((DATA / "top_100k.json").read_text()))
    infra = btd.psl_in_top.load_infrastructure()
    bases = {btd.psl_in_top._base(r) for r in json.loads((DATA / "public_suffixes_in_top.json").read_text())}
    assert bases <= top | infra
    assert bases & (infra - top)
