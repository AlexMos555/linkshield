"""Regression tests for scripts/eval_ml_model.py (the held-out ML evaluation).

Two ways the evaluation misreported its own inputs:

* TweetFeed ships raw Unicode hosts ('автозаим.рф'). The model, the
  blocklist hashes and the scorer all speak the punycode wire form, so a
  Unicode host was scored on different bytes, never matched the published
  blocklist and could be counted twice next to its xn-- spelling.
* The downloaded Tranco snapshot is not the shipped data/top_100k.json, so
  "rank 10k–100k" is not the same as "allowlisted": on 2026-10-04 only 689
  of 1,000 sampled names were. The sample must be split by the actual
  allowlist status instead of being labelled allowlisted wholesale.
"""
from __future__ import annotations

import importlib
import io
import sys
import zipfile
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


def _tranco_zip(tmp_path: Path, rows: list[tuple[int, str]]) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", "\n".join(f"{r},{d}" for r, d in rows))
    path = tmp_path / "top-1m.csv.zip"
    path.write_bytes(buf.getvalue())
    return path


def test_tranco_head_is_split_by_actual_allowlist_status(tmp_path):
    m = _load()
    rows = [(10_000 + i, f"head{i}.com") for i in range(1, 21)] + [(200_000, "tail.ru")]
    shipped = {f"head{i}.com" for i in range(1, 21) if i % 2}  # half the head is in the shipped list
    samples = m.tranco_samples(_tranco_zip(tmp_path, rows), 100, allowlisted=lambda h: h in shipped)

    listed, listed_info = samples["tranco_10k_100k"]
    unlisted, unlisted_info = samples["tranco_10k_100k_unlisted"]
    assert set(listed) == shipped
    assert set(unlisted) == {f"head{i}.com" for i in range(1, 21)} - shipped
    assert listed_info["pool"] == unlisted_info["pool"] == 10
    assert "allowlisted" in listed_info["note"]
    assert "not in the shipped" in unlisted_info["note"]
