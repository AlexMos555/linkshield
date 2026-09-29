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


@pytest.mark.parametrize("value,host", [
    ("https://A.Example.com/x", "a.example.com"),
    ("Example.com.", "example.com"),
    ("has/slash.com", ""),
    ("http://[::1/", ""),
])
def test_host_of_reads_urls_and_bare_names(value, host):
    assert ho._host_of(value) == host
