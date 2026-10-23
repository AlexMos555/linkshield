"""Regression tests for scripts/eval_ml_model.py (the held-out ML evaluation).

Two ways the evaluation misreported its own inputs:

* TweetFeed ships raw Unicode hosts ('автозаим.рф'). The model, the
  blocklist hashes and the scorer all speak the punycode wire form, so a
  Unicode host was scored on different bytes, never matched the published
  blocklist and could be counted twice next to its xn-- spelling.
* A downloaded ranking is not the shipped data/top_100k.json, so "rank
  10k–100k" is not the same as "allowlisted": on 2026-10-04 only 689 of
  1,000 sampled names of the then-used Tranco snapshot were (the Majestic
  Million, read since 2026-10-23, is one of two lists the allowlist
  merges). The sample must be split by the actual allowlist status instead
  of being labelled allowlisted wholesale.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

PUNY = "xn--80aafugyk5a.xn--p1ai"  # автозаим.рф


def _load() -> ModuleType:
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    return importlib.import_module("eval_ml_model")


def test_unicode_host_is_folded_to_punycode():
    m = _load()
    assert m._host_of("автозаим.рф") == PUNY
    assert m._host_of("https://АВТОЗАИМ.рф/login?x=1") == PUNY
    assert m._host_of("https://login.автозаим.рф/") == "login." + PUNY
    assert m._host_of(PUNY) == PUNY
    assert m._host_of("Example.COM") == "example.com"


def test_tweetfeed_dedups_unicode_and_punycode_spellings(tmp_path):
    m = _load()
    feed = tmp_path / "week.csv"
    feed.write_text(
        "2026-10-01,u,domain,автозаим.рф,#phishing,t\n"
        f"2026-10-01,u,url,https://{PUNY}/pay,#phishing,t\n",
        encoding="utf-8",
    )
    hosts, info = m.tweetfeed_week(feed)
    assert hosts == [PUNY]
    assert info["unique_hosts"] == 1


def _majestic_csv(tmp_path: Path, rows: list[tuple[int, str]]) -> Path:
    head = "GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs\n"
    path = tmp_path / "majestic_million.csv"
    path.write_text(head + "".join(f"{r},{r},{d},x,1,1,{d},x,0,0,0,0\n" for r, d in rows))
    return path


def test_ranking_head_is_split_by_actual_allowlist_status(tmp_path):
    m = _load()
    rows = [(10_000 + i, f"head{i}.com") for i in range(1, 21)] + [(200_000, "tail.ru")]
    shipped = {f"head{i}.com" for i in range(1, 21) if i % 2}  # half the head is in the shipped list
    samples = m.ranking_samples(_majestic_csv(tmp_path, rows), 100, allowlisted=lambda h: h in shipped)

    listed, listed_info = samples["majestic_10k_100k"]
    unlisted, unlisted_info = samples["majestic_10k_100k_unlisted"]
    assert set(listed) == shipped
    assert set(unlisted) == {f"head{i}.com" for i in range(1, 21)} - shipped
    assert listed_info["pool"] == unlisted_info["pool"] == 10
    assert "allowlisted" in listed_info["note"]
    assert "not in the shipped" in unlisted_info["note"]
