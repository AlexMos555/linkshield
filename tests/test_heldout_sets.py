"""scripts/heldout_sets and scripts/eval_day_one_coverage: the held-out
parsers, the freshness windows, the phone's coverage rule, and the report
shape the methodology page will read.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

ho = importlib.import_module("heldout_sets")
d1 = importlib.import_module("eval_day_one_coverage")

from api.services.blocklist_artifact import name_hash, render_artifact_v2  # noqa: E402

T = 1_790_000_000.0  # 2026-09-21T14:13:20Z
DAY = 86_400.0

PHISHTANK = (
    "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
    "1,https://www.evil-bank.xyz/login,https://x/1,2026-09-21T14:13:20+00:00,yes,2026-09-21T15:00:00+00:00,yes,Other\n"
    "2,http://evil-bank.xyz/,https://x/2,2026-09-20T14:13:20+00:00,yes,,yes,Other\n"
    "3,https://tenant.github.io/a,https://x/3,2026-09-19T14:13:20+00:00,yes,,yes,Other\n"
    "4,http://203.0.113.9/x,https://x/4,2026-09-21T10:00:00+00:00,yes,,yes,Other\n"
    "5,https://old-phish.top/,https://x/5,2026-08-01T00:00:00+00:00,yes,,yes,Other\n"
    "6,,https://x/6,2026-09-21T00:00:00+00:00,yes,,yes,Other\n"
    "7,https://www.evil-bank.xyz/again,https://x/7,2026-09-21T13:00:00+00:00,yes,,yes,Other\n"
)
TWEETFEED = (
    "2026-09-21 14:13:20,urldna_bot,domain,fresh-scam.com,#phishing,https://x.com/a\n"
    "2026-09-21 12:00:00,urldna_bot,url,https://sub.fresh-scam.com/p,#phishing,https://x.com/b\n"
    "2026-09-15 09:00:00,skocherhan,domain,week-old.net,#phishing,https://x.com/c\n"
    "2026-09-21 11:00:00,someone,ip,203.0.113.5,#malware,https://x.com/d\n"
    "2026-09-21 11:00:00,someone,domain,invoices.zip,#malware,https://x.com/e\n"
    "bad row\n"
)


def _artifact(names) -> set[int]:
    blob = render_artifact_v2(set(names))
    return ho.load_artifact(_write(blob))


def _write(blob: bytes) -> Path:
    import tempfile

    path = Path(tempfile.mkdtemp()) / "list.bin"
    path.write_bytes(blob)
    return path


# ── Parsers and windows ──────────────────────────────────────────────────────


def test_phishtank_rows_become_reports_with_their_submission_time():
    reports = ho.phishtank_reports(PHISHTANK)
    assert [r.host for r in reports] == ["www.evil-bank.xyz", "evil-bank.xyz", "tenant.github.io",
                                         "203.0.113.9", "old-phish.top", "www.evil-bank.xyz"]
    assert reports[0].seen_at == T


def test_tweetfeed_rows_keep_domains_and_urls_only():
    reports = ho.tweetfeed_reports(TWEETFEED)
    assert [r.host for r in reports] == ["fresh-scam.com", "sub.fresh-scam.com", "week-old.net"]
    assert reports[0].seen_at == T


def test_freshness_counts_a_hosts_first_report():
    reports = ho.phishtank_reports(PHISHTANK)
    assert ho.newest_report(reports) == T
    assert ho.first_seen(reports)["www.evil-bank.xyz"] == T - 73 * 60 - 20, "the earlier report, not the latest"
    assert ho.fresh_within(reports, 1, T) == ["www.evil-bank.xyz", "203.0.113.9", "evil-bank.xyz"]
    assert ho.fresh_within(reports, 7, T) == ["www.evil-bank.xyz", "203.0.113.9", "evil-bank.xyz",
                                              "tenant.github.io"]
    assert "old-phish.top" in ho.fresh_within(reports, 0, T)
    assert ho.fresh_within([], 1, T) == []


def test_gzip_and_plain_bodies_read_the_same():
    import gzip

    assert ho.decompress(gzip.compress(b"\xef\xbb\xbfa,b\n")) == "a,b\n"
    assert ho.decompress(b"a,b\n") == "a,b\n"


# ── The phone's rule ─────────────────────────────────────────────────────────


def test_coverage_uses_subdomain_matching_and_separates_the_unblockable():
    hashes = _artifact(["evil-bank.xyz"])
    hosts = ["www.evil-bank.xyz", "evil-bank.xyz", "tenant.github.io", "203.0.113.9", "missed.top"]
    stats = ho.coverage(hashes, hosts, {"github.io"})
    assert stats == {
        "hostnames": 5, "blockable_hostnames": 3, "ip_literal_hostnames": 1, "shared_hosting_hostnames": 1,
        "hit": 2, "hit_blockable": 2, "coverage_all_pct": 40.0, "coverage_blockable_pct": 66.7,
    }
    assert ho.coverage(hashes, [], set())["coverage_all_pct"] is None


def test_the_canary_is_not_a_name():
    hashes = _artifact(["evil-bank.xyz"])
    assert name_hash(ho.LIST_CANARY) not in hashes


# ── The day-one report ───────────────────────────────────────────────────────


def _builds():
    return {
        "all": {"feeds": ["TweetFeed", "OpenPhish"], "hashes": _artifact(["evil-bank.xyz", "fresh-scam.com"]),
                "names": 2, "artifact_bytes": 10, "sha256": "a", "excluded_feeds": []},
        "licensed-minus-tweetfeed": {"feeds": ["Phishunt"], "hashes": _artifact(["evil-bank.xyz"]),
                                     "names": 1, "artifact_bytes": 9, "sha256": "b",
                                     "excluded_feeds": ["OpenPhish", "TweetFeed"]},
    }


def test_score_marks_a_sample_that_is_a_source_as_circular():
    samples = {"phishtank": ho.phishtank_reports(PHISHTANK), "tweetfeed": ho.tweetfeed_reports(TWEETFEED)}
    held_out = d1.score(_builds(), samples, (1, 30), {"github.io"},
                        {"phishtank": "PhishTank", "tweetfeed": "TweetFeed"})
    tf = held_out["tweetfeed"]["windows"]["1"]["coverage"]
    assert tf["all"]["circular"] is True and tf["all"]["coverage_all_pct"] == 100.0
    assert tf["licensed-minus-tweetfeed"]["circular"] is False
    assert tf["licensed-minus-tweetfeed"]["coverage_all_pct"] == 0.0
    pt = held_out["phishtank"]["windows"]["1"]
    assert pt["hostnames"] == 3 and pt["ip_literal_hostnames"] == 1
    assert pt["coverage"]["all"]["circular"] is False
    assert pt["coverage"]["all"]["coverage_all_pct"] == 66.7
    assert held_out["phishtank"]["as_of"] == "2026-09-21T14:13:20Z"


def test_headline_keeps_only_the_honest_day_one_numbers():
    samples = {"phishtank": ho.phishtank_reports(PHISHTANK), "tweetfeed": ho.tweetfeed_reports(TWEETFEED)}
    held_out = d1.score(_builds(), samples, (1, 30), set(), {"phishtank": "PhishTank", "tweetfeed": "TweetFeed"})
    head = d1.headline(held_out)
    assert set(head["phishtank"]["coverage_all_pct"]) == {"all", "licensed-minus-tweetfeed"}
    assert set(head["tweetfeed"]["coverage_all_pct"]) == {"licensed-minus-tweetfeed"}
    assert head["tweetfeed"]["days"] == 1


def test_the_report_is_json_and_carries_no_hashes():
    samples = {"phishtank": ho.phishtank_reports(PHISHTANK)}
    held_out = d1.score(_builds(), samples, (1,), set(), {"phishtank": "PhishTank"})
    report = d1.assemble(_builds(), held_out, (1,), {"bodies": 2, "sha256": "f"},
                         generated_at="2026-09-29T00:00:00Z")
    text = json.dumps(report)
    assert report["schema"] == d1.SCHEMA
    assert report["feed_snapshot"] == {"bodies": 2, "sha256": "f"}
    assert "hashes" not in report["variants"]["all"]
    assert report["variants"]["all"]["feeds"] == ["TweetFeed", "OpenPhish"]
    assert report["headline"]["phishtank"]["coverage_all_pct"]["all"] == 66.7
    assert "circular" in text and report["freshness_days"] == [1]


def test_variants_are_the_four_licence_builds():
    rdd = d1._load_refresh_module()
    names = d1.variants(rdd)
    assert list(names) == ["all", "licensed", "all-minus-tweetfeed", "licensed-minus-tweetfeed"]
    assert names["licensed"] == rdd.NON_COMMERCIAL_FEEDS
    assert names["licensed-minus-tweetfeed"] == rdd.NON_COMMERCIAL_FEEDS | {"TweetFeed"}


def _stub_refresh(monkeypatch, rdd) -> None:
    """rdd.refresh that writes a one-name artifact instead of building."""
    async def _refresh(redis_url, dry_run, artifact_out=None, excluded=None, **_):
        Path(artifact_out).write_bytes(render_artifact_v2({"evil-bank.xyz"}))
        return 0

    monkeypatch.setattr(rdd, "refresh", _refresh)


def test_build_variants_record_the_sources_each_build_really_had(tmp_path, monkeypatch):
    import asyncio

    rdd = d1._load_refresh_module()
    _stub_refresh(monkeypatch, rdd)
    monkeypatch.delenv(rdd.phishtank_feed.KEY_ENV, raising=False)
    builds = asyncio.run(d1.build_variants(rdd, d1.Snapshot(tmp_path / "no-key"), {"all": frozenset()}))
    assert "PhishTank" not in builds["all"]["feeds"] and "TweetFeed" in builds["all"]["feeds"]

    # With the key the refresh job ingests PhishTank, so the build says so —
    # and the PhishTank sample is circular for it, out of the headline.
    monkeypatch.setenv(rdd.phishtank_feed.KEY_ENV, "k3y")
    builds = asyncio.run(d1.build_variants(rdd, d1.Snapshot(tmp_path / "key"),
                                           {"all": frozenset(), "licensed": rdd.NON_COMMERCIAL_FEEDS}))
    assert "PhishTank" in builds["all"]["feeds"] and "PhishTank" in builds["licensed"]["feeds"]
    assert "OpenPhish" not in builds["licensed"]["feeds"]
    assert builds["all"]["hashes"] == {name_hash("evil-bank.xyz")}
    held_out = d1.score(builds, {"phishtank": ho.phishtank_reports(PHISHTANK)}, (1,), set(),
                        {"phishtank": "PhishTank"})
    assert held_out["phishtank"]["windows"]["1"]["coverage"]["all"]["circular"] is True
    assert d1.headline(held_out) == {}


def test_the_keyed_phishtank_dump_is_fetched_once_and_its_url_never_written(tmp_path):
    import asyncio

    calls = []
    answers = [(404, {}, b""), (200, {"ETag": '"x"'}, b"phish_id,url\n1,https://a.example/\n")]

    async def _real(url, headers):
        calls.append(url)
        return answers.pop(0)

    snap = d1.Snapshot(tmp_path)
    fetch = snap.conditional_fetcher(_real)
    url = "https://data.phishtank.com/data/k3y/online-valid.csv.gz"
    assert asyncio.run(fetch(url, {}))[0] == 404, "a throttled answer is passed through, not kept"
    assert asyncio.run(fetch(url, {}))[0] == 200
    assert asyncio.run(fetch(url, {"If-None-Match": '"x"'})) == (200, {}, b"phish_id,url\n1,https://a.example/\n")
    assert calls == [url, url]
    assert (tmp_path / d1.PHISHTANK_KEYED_DUMP).exists()
    assert all(b"k3y" not in p.read_bytes() for p in tmp_path.iterdir())
    assert d1.snapshot_fingerprint(snap)["bodies"] == 1


def test_snapshot_serves_a_cached_body_without_fetching_again(tmp_path):
    import asyncio

    calls = []

    async def _real(url):
        calls.append(url)
        return "body of " + url

    snap = d1.Snapshot(tmp_path)
    fetch = snap.fetcher(_real)
    assert asyncio.run(fetch("https://feed.example/a")) == "body of https://feed.example/a"
    assert asyncio.run(fetch("https://feed.example/a")) == "body of https://feed.example/a"
    assert calls == ["https://feed.example/a"]
    fingerprint = d1.snapshot_fingerprint(snap)
    assert fingerprint["bodies"] == 1 and len(fingerprint["sha256"]) == 64
    assert json.loads((tmp_path / "index.json").read_text()) == {
        snap.path_for("https://feed.example/a").name: "https://feed.example/a",
    }


def test_main_writes_the_dated_report_and_latest_from_one_snapshot(tmp_path, monkeypatch, caplog):
    """The command line end to end: four stubbed builds, a canned PhishTank
    dump and a TweetFeed body already in the snapshot, --days, --out and
    --latest honoured, and the table logged with its circularity marks."""
    import asyncio
    import gzip
    import logging

    rdd = d1._load_refresh_module()
    _stub_refresh(monkeypatch, rdd)
    monkeypatch.setattr(d1, "_load_refresh_module", lambda: rdd)
    monkeypatch.delenv(rdd.phishtank_feed.KEY_ENV, raising=False)
    snap_dir = tmp_path / "snap"
    d1.Snapshot(snap_dir).path_for(rdd.TWEETFEED_YEAR).write_text(TWEETFEED, encoding="utf-8")

    async def _dump(self):
        return gzip.compress(PHISHTANK.encode("utf-8"))

    monkeypatch.setattr(d1.Snapshot, "phishtank_dump", _dump)
    out = tmp_path / "reports" / "day-one.json"
    out.parent.mkdir()
    monkeypatch.setattr(sys, "argv", ["eval_day_one_coverage.py", "--snapshot-dir", str(snap_dir),
                                      "--days", "1,30", "--out", str(out), "--latest"])

    with caplog.at_level(logging.INFO, logger="day-one-coverage"):
        assert asyncio.run(d1.main()) == 0

    report = json.loads(out.read_text())
    assert report == json.loads((out.parent / "day-one-coverage-latest.json").read_text())
    assert report["freshness_days"] == [1, 30]
    assert set(report["variants"]) == {"all", "licensed", "all-minus-tweetfeed", "licensed-minus-tweetfeed"}
    assert report["variants"]["all"]["false_positives_top10k"] == 0
    assert "hashes" not in json.dumps(report)
    # evil-bank.xyz is the one listed name: of the three fresh PhishTank
    # hosts (www.evil-bank.xyz, 203.0.113.9, evil-bank.xyz) it covers two.
    assert report["headline"]["phishtank"]["coverage_all_pct"]["all"] == 66.7
    assert set(report["headline"]["tweetfeed"]["coverage_all_pct"]) == {"all-minus-tweetfeed",
                                                                        "licensed-minus-tweetfeed"}
    table = [r.getMessage() for r in caplog.records if r.getMessage().startswith(("phishtank", "tweetfeed"))]
    assert len(table) == 4
    assert any("tweetfeed" in line and "all=0.0%*" in line for line in table), "a source's sample is marked"


@pytest.mark.parametrize("value,host", [
    ("https://A.Example.com/x", "a.example.com"),
    ("Example.com.", "example.com"),
    ("has/slash.com", ""),
    ("http://[::1/", ""),
])
def test_host_of_reads_urls_and_bare_names(value, host):
    assert ho._host_of(value) == host
