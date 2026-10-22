"""The ML training corpus comes only from sources a paid product may train on.

Until 2026-10-21 data/phishtank.csv was the URLhaus full dump plus the
OpenPhish community feed. abuse.ch retired anonymous downloads that day (the
dump answers 410 Gone) and both sets of terms bar commercial use — a trained
model is a derivative. scripts/refresh_training_feeds.py now builds the
corpus from the feeds docs/THIRD_PARTY_FEEDS.md clears for a paid product,
each capped so no single feed decides what "phishing" looks like to the model.
"""
from __future__ import annotations

import csv
import datetime
import gzip
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import refresh_training_feeds as rtf  # noqa: E402


def _hosts_written(path) -> list[tuple[str, str]]:
    with open(path, newline="") as f:
        return [(row["url"], row["source"]) for row in csv.DictReader(f)]


def test_no_non_commercial_source_is_read():
    urls = " ".join(spec.url for spec in rtf.PHISHING_SOURCES).lower()
    for banned in ("abuse.ch", "openphish", "phishing.army", "phishtank"):
        assert banned not in urls, f"{banned} is not licensed for training a paid product's model"


def test_every_source_names_its_licence_and_has_a_cap():
    assert len(rtf.PHISHING_SOURCES) >= 4
    for spec in rtf.PHISHING_SOURCES:
        assert spec.licence.strip(), f"{spec.name}: say which terms allow training on it"
        assert 0 < spec.cap <= rtf.TRAINING_PHISHING_HOSTS // 3, f"{spec.name}: cap {spec.cap} lets one feed dominate"


def test_parsers():
    assert list(rtf.parse_domain_list("# c\nevil.example\n0.0.0.0 bad.example\n\nhttp://x/y\n")) == [
        "evil.example", "bad.example"]
    assert list(rtf.parse_url_list("https://Login.Evil.example/a\n\nnot a url\n")) == ["login.evil.example"]
    assert list(rtf.parse_json_list(json.dumps(["a.example", "*.b.example", ".c.example", 3]))) == ["a.example"]
    for not_a_list in ("<html>rate limited</html>", json.dumps({"x": 1})):
        with pytest.raises(ValueError):
            list(rtf.parse_json_list(not_a_list))
    tweetfeed = ("2026-10-01 10:00:00,u,domain,evil.example,#phishing,t\n"
                 "2026-10-01 10:00:00,u,url,https://login.bad.example/x,#phishing,t\n"
                 "2026-10-01 10:00:00,u,ip,203.0.113.7,#c2,t\n"
                 "2026-10-01 10:00:00,u,domain,documents.zip,#malware,t\n")
    assert list(rtf.parse_tweetfeed(tweetfeed)) == ["evil.example", "login.bad.example"]


def test_caps_and_interleave_keep_any_prefix_balanced():
    hosts = {
        "Big": [f"b{i}.example" for i in range(50_000)],
        "Mid": [f"m{i}.example" for i in range(4_000)],
        "Small": [f"s{i}.example" for i in range(300)],
        "Other": [f"o{i}.example" for i in range(10_000)],
    }
    caps = {"Big": 3_000, "Mid": 3_000, "Small": 3_000, "Other": 3_000}
    corpus = rtf.build_corpus(hosts, caps, seed=7)
    by_source = {}
    for _, source in corpus:
        by_source[source] = by_source.get(source, 0) + 1
    assert by_source == {"Big": 3_000, "Mid": 3_000, "Small": 300, "Other": 3_000}
    # train_model takes the first N hosts in file order: every prefix must
    # already be mixed, not one feed's block followed by the next one's.
    head = [source for _, source in corpus[:1_000]]
    assert max(head.count(s) for s in hosts) <= 1_000 // 3
    # Deterministic for the same feeds, so a retrain is reproducible.
    assert corpus == rtf.build_corpus(hosts, caps, seed=7)


def test_a_host_listed_by_two_feeds_appears_once():
    corpus = rtf.build_corpus({"A": ["x.example", "a.example"], "B": ["X.example", "b.example"]},
                              {"A": 10, "B": 10}, seed=1)
    hosts = [h for h, _ in corpus]
    assert sorted(hosts) == ["a.example", "b.example", "x.example"]


def _fake_fetch(responses):
    def fetch(url, timeout=180.0):
        value = responses.get(url)
        if isinstance(value, Exception) or value is None:
            raise value or RuntimeError(f"unexpected url {url}")
        return value.encode()
    return fetch


def _healthy_responses(n=3_000):
    out = {}
    for spec in rtf.PHISHING_SOURCES:
        tag = spec.name.lower().replace(" ", "").replace(".", "")
        hosts = [f"h{i}-{tag}.example" for i in range(n)]
        if spec.parser is rtf.parse_json_list:
            out[spec.url] = json.dumps(hosts)
        elif spec.parser is rtf.parse_url_list:
            out[spec.url] = "\n".join(f"https://{h}/login" for h in hosts)
        elif spec.parser is rtf.parse_tweetfeed:
            out[spec.url] = "\n".join(f"2026-10-01 10:00:00,u,domain,{h},#phishing,t" for h in hosts)
        else:
            out[spec.url] = "\n".join(hosts)
    return out


def test_refresh_writes_a_mixed_corpus(tmp_path, monkeypatch):
    monkeypatch.setattr(rtf, "_DATA", str(tmp_path))
    monkeypatch.setattr(rtf, "_get", _fake_fetch(_healthy_responses()))
    assert rtf.refresh_phishing() == 0
    rows = _hosts_written(tmp_path / "phishtank.csv")
    assert all(url.startswith("https://") for url, _ in rows)
    sources = {s for _, s in rows}
    assert sources == {spec.name for spec in rtf.PHISHING_SOURCES}
    for spec in rtf.PHISHING_SOURCES:
        assert sum(s == spec.name for _, s in rows) <= spec.cap


def test_a_dead_feed_is_skipped_not_fatal(tmp_path, monkeypatch):
    responses = _healthy_responses()
    dead = rtf.PHISHING_SOURCES[0]
    responses[dead.url] = RuntimeError("410 Gone")
    monkeypatch.setattr(rtf, "_DATA", str(tmp_path))
    monkeypatch.setattr(rtf, "_get", _fake_fetch(responses))
    assert rtf.refresh_phishing() == 0
    assert dead.name not in {s for _, s in _hosts_written(tmp_path / "phishtank.csv")}


def test_too_few_feeds_refuses_and_keeps_the_previous_corpus(tmp_path, monkeypatch):
    """One or two surviving feeds would teach the model one feed's idea of
    phishing (PhishDestroy alone is crypto drainers). The step fails, so the
    workflow stops before the commit and production keeps the last model."""
    previous = tmp_path / "phishtank.csv"
    previous.write_text("url,source\nhttps://old.example/,X\n")
    responses = {spec.url: RuntimeError("down") for spec in rtf.PHISHING_SOURCES}
    first = rtf.PHISHING_SOURCES[0]
    responses[first.url] = _healthy_responses()[first.url]
    monkeypatch.setattr(rtf, "_DATA", str(tmp_path))
    monkeypatch.setattr(rtf, "_get", _fake_fetch(responses))
    assert rtf.refresh_phishing() == 2
    assert previous.read_text() == "url,source\nhttps://old.example/,X\n"


def test_too_few_hosts_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(rtf, "_DATA", str(tmp_path))
    monkeypatch.setattr(rtf, "_get", _fake_fetch(_healthy_responses(n=50)))
    assert rtf.refresh_phishing() == 2
    assert not (tmp_path / "phishtank.csv").exists()


# ── The benign lists (2026-10-22) ──
#
# Until then both came from Tranco, whose default list averages Cloudflare
# Radar (CC BY-NC 4.0) and which states no licence of its own. Now the
# Majestic Million (CC BY 3.0) and the Chrome UX Report top origins (CC BY
# 4.0), global and Russia.

def test_no_unlicensed_benign_source_is_read():
    urls = " ".join([rtf.MAJESTIC, rtf.CRUX]).lower()
    for banned in ("tranco", "cloudflare", "radar", "umbrella", "alexa"):
        assert banned not in urls, f"{banned}: no licence a paid product can train under"
    assert "country/ru" in rtf.CRUX_SCOPES   # the regional zones live in Russia's list


MAJESTIC_CSV = (
    "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,"
    "PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
    "1,1,google.com,com,478136,2049353,google.com,com,1,1,507044,2211598\n"
    "2,1,XN--80ASWG.XN--P1AI,xn--p1ai,10,10,сайт.рф,рф,2,1,10,10\n"
    "3,2,play.google.com,com,9,9,play.google.com,com,3,2,9,9\n"
    "x,3,broken.com,com,1,1,broken.com,com,0,0,0,0\n"
)


def test_parse_majestic_reads_rank_and_the_ascii_domain():
    assert rtf.parse_majestic(MAJESTIC_CSV) == [
        (1, "google.com"), (2, "xn--80aswg.xn--p1ai"), (3, "play.google.com")]
    with pytest.raises(ValueError):
        rtf.parse_majestic("<html>503</html>")


def test_parse_crux_reads_the_origin_host():
    text = ("origin,rank\nhttps://www.Example.com,1000\nhttp://www.example.com,5000\n"
            "https://gorzdrav.spb.ru:8443,10000\nhttps://localhost,1000\n")
    assert rtf.parse_crux(text) == [(1000, "www.example.com"), (5000, "www.example.com"),
                                    (10000, "gorzdrav.spb.ru")]
    with pytest.raises(ValueError):
        rtf.parse_crux("rank,domain\n1,google.com\n")


def test_crux_months_go_back_across_the_new_year():
    assert rtf.crux_months(datetime.date(2026, 10, 22)) == ["202609", "202608", "202607", "202606"]
    assert rtf.crux_months(datetime.date(2026, 1, 5), back=2) == ["202512", "202511"]


def _crux_gz(rows) -> bytes:
    return gzip.compress(("origin,rank\n" + "".join(f"https://{h},{r}\n" for r, h in rows)).encode())


def _benign_fetch(responses):
    """Like _fake_fetch, but an unknown URL is a 404 — what GitHub answers
    for a CrUX month not published yet."""
    def fetch(url, timeout=180.0):
        if url not in responses:
            raise httpx.HTTPStatusError("404", request=httpx.Request("GET", url), response=httpx.Response(404))
        value = responses[url]
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, bytes) else value.encode()
    return fetch


def _benign_responses(month="202609"):
    return {
        rtf.MAJESTIC: MAJESTIC_CSV,
        rtf.CRUX.format(scope="global", month=month): _crux_gz(
            [(1000, "www.example.com"), (1000, "www.google.com"), (10000, "a.b.com"), (10000, "someone.github.io")]),
        rtf.CRUX.format(scope="country/ru", month=month): _crux_gz(
            [(1000, "a.b.com"), (5000, "gorzdrav.spb.ru"), (5000, "lk.dnevnik.ru")]),
    }


@pytest.fixture
def small_lists(monkeypatch, tmp_path):
    monkeypatch.setattr(rtf, "_DATA", str(tmp_path))
    monkeypatch.setattr(rtf, "MIN_BENIGN_DOMAINS", 3)
    monkeypatch.setattr(rtf, "CRUX_SCOPES", {"global": 2, "country/ru": 2})
    monkeypatch.setattr(rtf, "crux_months", lambda today, back=4: ["202609", "202608"])
    return tmp_path


def test_refresh_benign_writes_both_ranked_lists(small_lists, monkeypatch):
    # The newest month is not published yet: the month before is read.
    monkeypatch.setattr(rtf, "_get", _benign_fetch(_benign_responses(month="202608")))
    assert rtf.refresh_benign() == 0
    # Majestic plus the global CrUX list's registrable domains, one row each
    # at its best rank; no tenant (someone.github.io is not github.io), and
    # nothing from Russia's list (dnevnik.ru, spb.ru).
    assert (small_lists / rtf.BENIGN_DOMAINS).read_text().splitlines() == [
        "1,google.com", "2,xn--80aswg.xn--p1ai", "3,play.google.com", "1000,example.com", "10000,b.com"]
    # One row per host at its best rank, global and Russia merged.
    assert (small_lists / rtf.BENIGN_HOSTS).read_text().splitlines() == [
        "1000,a.b.com", "1000,www.example.com", "1000,www.google.com", "5000,gorzdrav.spb.ru",
        "5000,lk.dnevnik.ru", "10000,someone.github.io"]


def test_the_files_train_model_reads_are_the_ones_written():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from ml import train_model

    assert (train_model.BENIGN_DOMAINS_CSV, train_model.BENIGN_HOSTS_CSV) == (rtf.BENIGN_DOMAINS, rtf.BENIGN_HOSTS)


@pytest.mark.parametrize("broken", ["majestic", "russia", "short"])
def test_a_missing_benign_list_keeps_both_previous_files(small_lists, monkeypatch, broken):
    """Both lists or neither: a new domain list with last week's hosts, or
    CrUX's global list without Russia's regional zones, is a corpus no run
    was measured on."""
    for name in (rtf.BENIGN_DOMAINS, rtf.BENIGN_HOSTS):
        (small_lists / name).write_text("1,previous.example\n")
    responses = _benign_responses()
    if broken == "majestic":
        responses[rtf.MAJESTIC] = RuntimeError("connection reset")
    elif broken == "russia":
        del responses[rtf.CRUX.format(scope="country/ru", month="202609")]
    else:
        monkeypatch.setattr(rtf, "MIN_BENIGN_DOMAINS", 10)
    monkeypatch.setattr(rtf, "_get", _benign_fetch(responses))
    assert rtf.refresh_benign() == 2
    for name in (rtf.BENIGN_DOMAINS, rtf.BENIGN_HOSTS):
        assert (small_lists / name).read_text() == "1,previous.example\n"
