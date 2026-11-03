"""What the weekly fresh-URL report holds since method_version 2 (2026-11-03).

Every answer is kept, and so is how it was counted. There is one existence
fact per row, the same for every resolver, and the phishing sample is a
fixed-seed draw capped per site. The rules themselves are
scripts/benchmark_method.py (tests/test_benchmark_method.py). These tests run
scripts/eval_fresh_urls.py offline: every feed and adapter is a stub.
"""
from __future__ import annotations

import importlib
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import httpx
import pytest


def _load_eval_module():
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    return importlib.import_module("eval_fresh_urls")


def _answer(name: str, verdict: str, **fields):
    async def _check(_client, url):
        return _load_eval_module().Verdict(name, verdict, **fields)
    return _check


NOW = "2026-11-03T14:00:00+00:00"
# The run's clock in these runs: an hour after the dump's rows.
CLOCK = "2026-11-03T15:00:00+00:00"


async def _run_main(eval_module, monkeypatch, tmp_path, pool, adapters, *flags,
                    sample: int = 2, dump: dict | None = None) -> tuple[dict, str]:
    """main() offline over `pool` as PhishTank's dump, every row submitted at
    NOW unless `dump` says otherwise: every adapter a stub (`adapters[name]`,
    else "safe" and nothing else)."""
    async def fake_feed():
        return eval_module.PhishtankDump(pool, **{"submitted": [NOW] * len(pool), **(dump or {})})

    monkeypatch.setattr(eval_module, "fetch_phishtank_dump", fake_feed)
    monkeypatch.setattr(eval_module, "_run_clock", lambda: datetime.fromisoformat(CLOCK))
    monkeypatch.setattr(eval_module, "VT_KEY", None)
    for name in list(eval_module.ADAPTERS):
        monkeypatch.setitem(eval_module.ADAPTERS, name, adapters.get(name) or _answer(name, "safe"))
        monkeypatch.setitem(eval_module.MIN_INTERVAL_S, name, 0.0)
    monkeypatch.setattr(sys, "argv", ["eval_fresh_urls.py", "--sample", str(sample), "--out-tag", "t",
                                      "--out-dir", str(tmp_path), *flags])
    assert await eval_module.main() == 0
    report = json.loads((tmp_path / "t-fresh-urls.json").read_text(encoding="utf-8"))
    return report, (tmp_path / "t-fresh-urls.md").read_text(encoding="utf-8")


def _by_url(rule):
    """An adapter whose Verdict is rule(url)."""
    async def _check(_client, url):
        return rule(url)
    return _check


@pytest.mark.asyncio
async def test_cleanway_keeps_what_its_answer_rests_on(monkeypatch):
    """The API says what a verdict rests on (verdict_basis: blocklist,
    threat_intel, allowlist …), which checks the budget cut off and whether
    the name exists. The benchmark kept only level and score, so nobody could
    tell a blocklist hit from an analysis, or an allowlisted tenant
    (zrg.okx.mybluehost.me, "safe 0") from a real look."""
    eval_module = _load_eval_module()
    monkeypatch.setattr(eval_module, "BENCHMARK_BYPASS_TOKEN", "tok")
    bodies = iter([
        {"level": "dangerous", "score": 90, "verdict_basis": "blocklist", "reason_codes": ["blocklist"],
         "checks_incomplete": [], "exists": None},
        {"level": "caution", "score": 25, "verdict_basis": "not_found", "reason_codes": ["domain_not_found"],
         "checks_incomplete": ["rdap", "ssl"], "exists": False},
        {"level": "safe", "score": 0, "verdict_basis": "allowlist", "reason_codes": "not-a-list"},
    ])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=next(bodies))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        listed = await eval_module.check_cleanway(client, "https://dead-phish.example/login")
        gone = await eval_module.check_cleanway(client, "https://sbertank.ru/")
        tenant = await eval_module.check_cleanway(client, "https://zrg.okx.mybluehost.me/")
    assert (listed.verdict, listed.level, listed.verdict_basis, listed.reason_codes,
            listed.checks_incomplete, listed.exists) == ("dangerous", "dangerous", "blocklist", ["blocklist"], [], None)
    assert (gone.verdict, gone.detail, gone.level, gone.exists) == ("unknown", "not_found", "caution", False)
    assert gone.checks_incomplete == ["rdap", "ssl"] and gone.verdict_basis == "not_found"
    assert (tenant.verdict, tenant.verdict_basis, tenant.reason_codes, tenant.exists) == ("safe", "allowlist", None, None)


def test_check_cleanway_describes_the_public_check_as_it_is():
    """It said "rule + ML scoring, NO threat-intel API fan-out": the public
    check runs the full analyzer, behind the allowlist and the blocklist."""
    doc = _load_eval_module().check_cleanway.__doc__
    assert "NO threat-" not in doc
    for word in ("allowlist", "blocklist", "threat-intel", "verdict_basis", "checks_incomplete", "exists"):
        assert word in doc, word


@pytest.mark.asyncio
async def test_the_raw_json_keeps_every_answer_and_how_it_was_counted(tmp_path, monkeypatch):
    eval_module = _load_eval_module()
    adapters = {
        "cleanway": _answer("cleanway", "dangerous", detail="dangerous", level="dangerous", score=90,
                            verdict_basis="threat_intel", reason_codes=["urlhaus"], checks_incomplete=["rdap"],
                            exists=True),
        "phishtank": _answer("phishtank", "unknown", detail="status=429"),
        "existence": _answer("existence", "unknown", detail="noerror", exists=True),
    }
    report, _md = await _run_main(eval_module, monkeypatch, tmp_path, ["https://phish0.example/login"], adapters,
                                  sample=1)
    row = report["raw"]["phishing"]["cleanway"][0]
    assert row["verdict_basis"] == "threat_intel" and row["reason_codes"] == ["urlhaus"]
    assert row["checks_incomplete"] == ["rdap"] and row["exists"] is True and row["level"] == "dangerous"
    assert row["outcome"] == "dangerous"
    other = report["raw"]["phishing"]["phishtank"][0]
    assert other["outcome"] == "no_answer"
    assert not {"level", "verdict_basis", "reason_codes", "checks_incomplete"} & set(other), other
    assert report["raw"]["existence"]["phishing"][0]["status"] == "resolves"
    assert report["method_version"] == 2


@pytest.mark.asyncio
async def test_a_name_that_resolves_nowhere_counts_for_no_resolver(tmp_path, monkeypatch):
    """Cleanway's blocklist answers before any existence check, and Cloudflare
    Families answers 0.0.0.0 for a name it lists whether or not it exists:
    both counted a dead name as a catch (2 + 12 rows on 2026-11-01), while
    Cleanway's own "not found" counted for no one. Now a name nobody resolves
    is 'not_found' for every resolver, whatever it answered — the raw answer
    stays in the JSON."""
    eval_module = _load_eval_module()
    pool = ["https://dead.example/login", "https://live.example/login"]
    legit_urls, _sites, _src = eval_module.pick_legit("curated", 2)
    dead_legit = legit_urls[0]

    def alive(url: str) -> bool:
        return "dead" not in url and url != dead_legit

    adapters = {
        "existence": _by_url(lambda url: eval_module.Verdict("existence", "unknown", exists=alive(url))),
        "cleanway": _by_url(lambda url: eval_module.Verdict(
            "cleanway", "dangerous" if url in pool else "safe", level="dangerous" if url in pool else "safe",
            verdict_basis="blocklist" if url in pool else "ml_and_heuristics")),
        "cloudflare_families": _by_url(lambda url: eval_module.Verdict(
            "cloudflare_families", "dangerous" if url in pool else "safe",
            detail="status=0 ip_block=True" if url in pool else "resolved")),
        "phishtank": _by_url(lambda url: eval_module.Verdict(
            "phishtank", "dangerous" if url in pool else "unknown", detail="valid=True")),
    }
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, pool, adapters)
    dead = report["raw"]["phishing_urls"].index("https://dead.example/login")
    for name in ("cleanway", "cloudflare_families", "phishtank"):
        stats = report["phishing"][name]
        assert (stats["tp"], stats["dangerous"], stats["not_found"], stats["resolving"]) == (1, 1, 1, 1), name
        assert (stats["answered"], stats["dangerous_rate_answered"]) == (1, 1.0), name
        assert report["raw"]["phishing"][name][dead]["verdict"] == "dangerous", name  # the raw answer
        assert report["raw"]["phishing"][name][dead]["outcome"] == "not_found", name
    assert report["existence"]["phishing"] == {"resolves": 1, "nxdomain": 1, "non_public": 0, "unknown": 0}
    # The legitimate sample is counted by the same rule, the breakdown included.
    assert report["safe"]["cleanway"]["not_found"] == 1 and report["safe"]["cleanway"]["tn"] == 1
    assert report["cleanway_on_legit"]["overall"]["not_found"] == 1
    assert "'not found' for every resolver" in md


@pytest.mark.asyncio
async def test_caution_and_a_dead_name_are_counted_apart(tmp_path, monkeypatch):
    """Both were one "unknown". Cleanway's own `exists: false` is a witness
    for every resolver: the row is not found for Cloudflare too."""
    eval_module = _load_eval_module()
    pool = ["https://gone.example/", "https://warn.example/"]

    def cleanway(url):
        if "gone" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="not_found", level="caution",
                                       verdict_basis="not_found", exists=False)
        if "warn" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="caution", level="caution", exists=True)
        return eval_module.Verdict("cleanway", "safe", level="safe", exists=True)

    adapters = {
        "existence": _answer("existence", "unknown", detail="status=2"),  # the probe could not tell
        "cleanway": _by_url(cleanway),
        "cloudflare_families": _by_url(lambda url: eval_module.Verdict(
            "cloudflare_families", "dangerous" if url in pool else "safe")),
    }
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, pool, adapters)
    ours = report["phishing"]["cleanway"]
    assert (ours["caution"], ours["not_found"], ours["dangerous"], ours["unknown"]) == (1, 1, 0, 2)
    cf = report["phishing"]["cloudflare_families"]
    assert (cf["dangerous"], cf["not_found"], cf["tp"]) == (1, 1, 1)
    assert "| phishing | cleanway | 2 | 0 | 1 | 0 | 1 | 0 | 1 |" in md


@pytest.mark.asyncio
async def test_the_phishing_sample_is_a_fixed_seed_draw_capped_per_site(tmp_path, monkeypatch):
    """The dump's first rows were one campaign's burst (allegro 50 of 200 on
    2026-11-01); random subdomains of one name counted many times. The report says how the
    sample was drawn, with the seed, so anyone holding the same dump draws
    the same URLs."""
    eval_module = _load_eval_module()
    seed = importlib.import_module("benchmark_method").PHISHING_SAMPLE_SEED
    campaign = [f"https://{i:04x}.campaign.cfd/x" for i in range(30)]
    others = [f"https://other{i}.example/" for i in range(5)]
    submitted = [f"2026-11-0{1 + i % 3}T00:00:00+00:00" for i in range(35)]
    dump = {"sha256": "feed-sha", "submitted": submitted}
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, campaign + others, {}, sample=5, dump=dump)
    picked = report["raw"]["phishing_urls"]
    assert len(picked) == 5
    assert sum(1 for u in picked if ".campaign.cfd/" in u) <= 2
    sampling = report["sampling"]
    assert sampling["seed"] == seed
    assert (sampling["pool_rows"], sampling["pool_sites"], sampling["max_per_site"]) == (35, 6, 2)
    assert sampling["dump_rows"] == 35
    assert sampling["window"] == {"days": 7, "start": "2026-10-27T00:00:00+00:00",
                                  "end": "2026-11-03T00:00:00+00:00", "undated_rows": 0,
                                  "future_rows": 0, "clock": CLOCK}
    assert sampling["dump_sha256"] == "feed-sha"
    assert sampling["submitted"]["oldest"] <= sampling["submitted"]["median"] <= sampling["submitted"]["newest"]
    assert "registrable domain" in sampling["site_rule"]
    text = report["sources"]["phishing"]
    assert text.startswith("PhishTank online-valid (35 URLs)")
    assert f"seed={seed}" in text and "at most 2 per site" in text
    assert "deduplicated by registrable domain" not in text
    assert "random sample" in md and "not comparable" in md

    again, _ = await _run_main(eval_module, monkeypatch, tmp_path, campaign + others, {}, sample=5, dump=dump)
    assert again["raw"]["phishing_urls"] == picked  # same dump, same seed, same sample
    reseeded, _ = await _run_main(eval_module, monkeypatch, tmp_path, campaign + others, {}, "--seed", "3",
                                  sample=5, dump=dump)
    assert reseeded["sampling"]["seed"] == 3


@pytest.mark.asyncio
async def test_the_whole_dump_is_read_and_fingerprinted():
    """It read only the dump's first limit x 3 rows. Now every row, with the
    SHA-256 of the decompressed CSV for a reproducer to check theirs."""
    import gzip
    import hashlib

    eval_module = _load_eval_module()
    header = "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target"
    rows = [f"{i},https://p{i}.example/x,http://d/{i},2026-11-0{1 + i % 3}T00:00:00+00:00,yes,x,yes,Other"
            for i in range(5000)]
    rows.insert(3, "9999,,http://d/empty,2026-11-01T00:00:00+00:00,yes,x,yes,Other")  # no url: skipped
    text = "\n".join([header, *rows]) + "\n"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=gzip.compress(text.encode("utf-8")))

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        dump = await eval_module.fetch_phishtank_dump(client)
    assert len(dump.urls) == len(dump.submitted) == 5000
    assert dump.urls[:2] == ["https://p0.example/x", "https://p1.example/x"]
    assert dump.submitted[1] == "2026-11-02T00:00:00+00:00"
    assert dump.sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_the_sample_is_drawn_from_the_last_week_of_the_dump_and_says_so(tmp_path, monkeypatch):
    """The dump is newest-first and goes back to 2012. A draw over all of it
    (the first draft of method_version 2) measured links years old, while the
    report said "fresh PhishTank entries". The pool is the rows submitted in
    the 7 days before the newest one, and the report says which days."""
    eval_module = _load_eval_module()
    fresh = [f"https://new{i}.example/" for i in range(6)]
    stale = [f"https://old{i}.example/" for i in range(30)]
    dump = {"submitted": ["2026-11-03T13:55:30+00:00"] * 3 + ["2026-10-28T08:00:00+00:00"] * 3
            + ["2025-10-13T10:00:00+00:00"] * 30}
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, fresh + stale, {}, sample=10, dump=dump)
    assert sorted(report["raw"]["phishing_urls"]) == sorted(fresh)
    sampling = report["sampling"]
    assert sampling["window"]["start"] == "2026-10-27T13:55:30+00:00"
    assert sampling["window"]["end"] == "2026-11-03T13:55:30+00:00"
    assert (sampling["dump_rows"], sampling["pool_rows"], sampling["pool_sites"], sampling["sites"]) == (36, 6, 6, 6)
    assert sampling["submitted"]["oldest"].startswith("2026-10-28")
    assert "6 submitted in the 7 days before its newest row" in report["sources"]["phishing"]
    assert "submitted 2026-10-27 13:55 – 2026-11-03 13:55 UTC" in md
    # The age is stated as the window, never as a bare "fresh" that a stale draw could contradict.
    assert "fresh PhishTank" not in md

    # --window-days 0: the whole dump, and the report claims nothing fresh.
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, fresh + stale, {}, "--window-days", "0",
                                 sample=10, dump=dump)
    assert report["sampling"]["window"] == {"days": 0, "start": None, "end": None, "undated_rows": 0,
                                            "future_rows": 0, "clock": None}
    assert report["sampling"]["pool_rows"] == 36
    assert "fresh PhishTank" not in md and "any age" in md and "of all its rows" in report["sources"]["phishing"]


@pytest.mark.asyncio
async def test_a_dump_without_submission_times_stops_the_run(tmp_path, monkeypatch):
    """Without a time on any row nothing says what is fresh: no sample is
    drawn and the run fails, rather than measure stale links unnoticed."""
    eval_module = _load_eval_module()

    async def fake_feed():
        return eval_module.PhishtankDump(["https://phish0.example/"], submitted=[""])

    monkeypatch.setattr(eval_module, "fetch_phishtank_dump", fake_feed)
    monkeypatch.setattr(sys, "argv", ["eval_fresh_urls.py", "--sample", "1", "--out-tag", "t",
                                      "--out-dir", str(tmp_path)])
    assert await eval_module.main() == 1
    assert not (tmp_path / "t-fresh-urls.json").exists()


@pytest.mark.asyncio
async def test_the_probe_decides_whether_a_name_exists(tmp_path, monkeypatch):
    """Cleanway's `exists: false` also answers a name that resolves into a
    blocked network (the SSRF guard gives the same answer), and its answer
    may come from its cache. The probe, asked once per URL at the start,
    decides; the resolvers' own answers only when it could not tell."""
    eval_module = _load_eval_module()
    pool = ["https://guarded.example/", "https://cached.example/", "https://servfail.example/"]
    probe = {"guarded": True, "cached": False, "servfail": None}

    def cleanway(url):
        if "guarded" in url:   # resolves into a blocked network: Cleanway's not-found answer
            return eval_module.Verdict("cleanway", "unknown", detail="not_found", level="caution",
                                       verdict_basis="not_found", exists=False)
        if "cached" in url:    # a day-old verdict from the public cache
            return eval_module.Verdict("cleanway", "dangerous", level="dangerous", exists=True)
        if "servfail" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="not_found", level="caution", exists=False)
        return eval_module.Verdict("cleanway", "safe", level="safe", exists=True)

    def existence(url):
        key = next((k for k in probe if k in url), None)
        return eval_module.Verdict("existence", "unknown", exists=probe[key] if key else True)

    adapters = {
        "existence": _by_url(existence),
        "cleanway": _by_url(cleanway),
        "cloudflare_families": _by_url(lambda url: eval_module.Verdict(
            "cloudflare_families", "dangerous" if url in pool else "safe")),
    }
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, pool, adapters, sample=3)
    urls = report["raw"]["phishing_urls"]
    rows = {u.split("//")[1].split(".")[0]: i for i, u in enumerate(urls)}
    status = report["raw"]["existence"]["phishing"]
    assert status[rows["guarded"]]["status"] == "resolves" and status[rows["guarded"]]["decided_by"] == "probe"
    assert status[rows["cached"]]["status"] == "nxdomain" and status[rows["cached"]]["decided_by"] == "probe"
    assert status[rows["servfail"]]["status"] == "nxdomain" and status[rows["servfail"]]["decided_by"] == "resolvers"
    ours = report["raw"]["phishing"]["cleanway"]
    # On a row the probe resolved, Cleanway's not-found answer is what a user
    # sees: a caution.
    assert ours[rows["guarded"]]["outcome"] == "caution"
    assert ours[rows["cached"]]["outcome"] == "not_found"
    assert report["phishing"]["cloudflare_families"]["tp"] == 1      # the guarded row, live
    assert "only when the probe cannot tell" in md and "blocked network" in md


@pytest.mark.asyncio
async def test_a_row_dated_in_the_future_leaves_the_week_as_it_is(tmp_path, monkeypatch, caplog):
    """One row dated 2099 made the window 2098-12-25 – 2099-01-01, a pool of
    one row: the run failed as n_phishing_below_min and the site stayed on the
    old report without a word (review of #395). The window ends at the run's
    clock; the report and the log say which rows were left out."""
    eval_module = _load_eval_module()
    fresh = [f"https://new{i}.example/" for i in range(4)]
    dump = {"submitted": [NOW] * 4 + ["2099-01-01T00:00:00+00:00"]}
    with caplog.at_level(logging.WARNING):
        report, md = await _run_main(eval_module, monkeypatch, tmp_path, [*fresh, "https://future.example/"],
                                     {}, sample=10, dump=dump)
    assert sorted(report["raw"]["phishing_urls"]) == sorted(fresh)
    window = report["sampling"]["window"]
    assert (window["end"], window["future_rows"], window["clock"]) == (NOW, 1, CLOCK)
    assert "2099-01-01T00:00:00+00:00" in caplog.text
    assert "1 row dated after the run's clock" in md


@pytest.mark.asyncio
async def test_a_name_that_leads_only_to_non_public_addresses_is_not_live(tmp_path, monkeypatch):
    """etransfer-accept.ddns.net resolved only to 0.0.0.0 on 2026-11-03 (a
    takedown): Families' 0.0.0.0 there counted as a Cloudflare catch and
    Cleanway's not-found answer (its SSRF guard) as a caution. A row whose
    every address is non-public is not found for every resolver now, and
    raw.existence keeps the addresses."""
    eval_module = _load_eval_module()
    pool = ["https://takedown.example/", "https://live.example/"]

    def existence(url):
        addresses = ["0.0.0.0"] if "takedown" in url else ["93.184.216.34"]
        return eval_module.Verdict("existence", "unknown", detail="noerror", exists=True, addresses=addresses)

    def cleanway(url):
        if "takedown" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="not_found", level="caution",
                                       verdict_basis="not_found", exists=False)
        return eval_module.Verdict("cleanway", "dangerous", level="dangerous", exists=True)

    adapters = {
        "existence": _by_url(existence),
        "cleanway": _by_url(cleanway),
        "cloudflare_families": _by_url(lambda url: eval_module.Verdict(
            "cloudflare_families", "dangerous" if url in pool else "safe",
            detail="status=0 ip_block=True" if url in pool else "resolved")),
    }
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, pool, adapters)
    row = report["raw"]["phishing_urls"].index("https://takedown.example/")
    probe = report["raw"]["existence"]["phishing"][row]
    assert (probe["status"], probe["decided_by"], probe["addresses"]) == ("non_public", "probe", ["0.0.0.0"])
    assert report["raw"]["existence"]["phishing"][1 - row]["addresses"] == ["93.184.216.34"]
    for name in ("cleanway", "cloudflare_families"):
        assert report["raw"]["phishing"][name][row]["outcome"] == "not_found", name
        assert "addresses" not in report["raw"]["phishing"][name][row], name  # the probe's alone
    assert (report["phishing"]["cloudflare_families"]["tp"], report["phishing"]["cleanway"]["caution"]) == (1, 0)
    assert report["existence"]["phishing"] == {"resolves": 1, "nxdomain": 0, "non_public": 1, "unknown": 0}
    assert "non-public" in md and "non-public" in report["sources"]["existence"]


@pytest.mark.asyncio
async def test_a_name_with_no_public_address_at_all_is_not_live(tmp_path, monkeypatch):
    """Third review of #395: 4 Allegro names of the seed-42 sample (2026-11-03)
    were a CNAME to a Cloudflare tunnel whose only address is fd10:aec2:5dae::,
    and 4 names had neither an A nor an AAAA record (5 by the third review,
    which asked www.ershoujian.com as its apex). All counted as live:
    Families' CNAME-only answer was a Cloudflare miss, Cleanway's not-found
    answer a caution. The probe asks AAAA whenever no A address is public
    (tests/test_nxdomain_verdict.py); here the row it reports is not live for
    any resolver, and the published text says when AAAA is asked."""
    eval_module = _load_eval_module()
    addresses = {"https://tunnel.example/": ["fd10:aec2:5dae::"], "https://bare.example/": [],
                 "https://live.example/": ["93.184.216.34"]}
    pool = list(addresses)

    def cleanway(url):
        if url == "https://live.example/":
            return eval_module.Verdict("cleanway", "dangerous", level="dangerous", exists=True)
        return eval_module.Verdict("cleanway", "unknown", detail="not_found", level="caution",
                                   verdict_basis="not_found", exists=False)

    def families(url):
        if url == "https://live.example/":
            return eval_module.Verdict("cloudflare_families", "dangerous", detail="status=0 ip_block=True")
        return eval_module.Verdict("cloudflare_families", "safe", detail="status=0 ip_block=False", exists=True)

    adapters = {
        "existence": _by_url(lambda url: eval_module.Verdict(
            "existence", "unknown", detail="noerror", exists=True,
            addresses=addresses.get(url, ["93.184.216.34"]))),   # the legit batch: live
        "cleanway": _by_url(cleanway),
        "cloudflare_families": _by_url(families),
    }
    report, md = await _run_main(eval_module, monkeypatch, tmp_path, pool, adapters, sample=3)
    urls = report["raw"]["phishing_urls"]
    assert sorted(urls) == sorted(pool)
    for url in ("https://tunnel.example/", "https://bare.example/"):
        row = urls.index(url)
        assert report["raw"]["existence"]["phishing"][row]["status"] == "non_public", url
        for name in ("cleanway", "cloudflare_families"):
            assert report["raw"]["phishing"][name][row]["outcome"] == "not_found", (url, name)
    assert report["existence"]["phishing"] == {"resolves": 1, "nxdomain": 0, "non_public": 2, "unknown": 0}
    families_summary, cleanway_summary = report["phishing"]["cloudflare_families"], report["phishing"]["cleanway"]
    assert (families_summary["tp"], families_summary["fn"]) == (1, 0)
    assert (cleanway_summary["tp"], cleanway_summary["caution"]) == (1, 0)
    assert "when no A address is public" in md
    assert "when no A address is public" in report["sources"]["existence"]
    assert "every A address" not in md and "every A address" not in report["sources"]["existence"]


@pytest.mark.asyncio
async def test_the_gate_log_says_how_many_cleanway_answers_were_degraded(tmp_path, monkeypatch, caplog):
    """The gate counts only rows with no answer, so a week where Cleanway
    answered "caution" because its checks were cut off (expired keys, open
    circuit breakers) or the site did not answer passes it unseen. The gate
    is unchanged; its log line says how many answers were like that."""
    eval_module = _load_eval_module()
    pool = ["https://cut.example/", "https://down.example/", "https://fine.example/", "https://quiet.example/"]

    def cleanway(url):
        if "cut" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="caution", level="caution",
                                       verdict_basis="ml_and_heuristics", checks_incomplete=["rdap", "ssl"])
        if "down" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="caution", level="caution",
                                       verdict_basis="unreachable", checks_incomplete=[])
        if "quiet" in url:
            return eval_module.Verdict("cleanway", "unknown", detail="rate_limited")  # no answer
        if url in pool:
            return eval_module.Verdict("cleanway", "dangerous", level="dangerous", verdict_basis="threat_intel")
        return eval_module.Verdict("cleanway", "safe", level="safe", verdict_basis="ml_and_heuristics",
                                   checks_incomplete=["ssl"])

    with caplog.at_level(logging.INFO, logger="eval_fresh_urls"):
        report, _md = await _run_main(eval_module, monkeypatch, tmp_path, pool,
                                      {"cleanway": _by_url(cleanway)}, sample=4)
    lines = [r.getMessage() for r in caplog.records if "degraded" in r.getMessage()]
    assert lines == [
        "cleanway answers degraded (not gated): phishing 3 answers — checks_incomplete 1 (33.3%), "
        "verdict_basis unreachable 1 (33.3%); legit 4 answers — checks_incomplete 4 (100.0%), "
        "verdict_basis unreachable 0 (0.0%)"
    ]
    # The gate decides as before: this run is too small to publish.
    assert not (tmp_path / "latest.json").exists()
