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
import sys
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


async def _run_main(eval_module, monkeypatch, tmp_path, pool, adapters, *flags,
                    sample: int = 2, dump: dict | None = None) -> tuple[dict, str]:
    """main() offline over `pool` as PhishTank's dump: every adapter a stub
    (`adapters[name]`, else "safe" and nothing else)."""
    async def fake_feed():
        return eval_module.PhishtankDump(pool, **(dump or {}))

    monkeypatch.setattr(eval_module, "fetch_phishtank_dump", fake_feed)
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
        assert stats["dangerous_rate_all"] == 0.5 and stats["dangerous_rate_resolving"] == 1.0, name
        assert report["raw"]["phishing"][name][dead]["verdict"] == "dangerous", name  # the raw answer
        assert report["raw"]["phishing"][name][dead]["outcome"] == "not_found", name
    assert report["existence"]["phishing"] == {"resolves": 1, "nxdomain": 1, "unknown": 0}
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
    assert "| phishing | cleanway | 0 | 1 | 0 | 1 | 0 |" in md


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
