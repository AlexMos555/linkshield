"""Regression tests for scripts/eval_fresh_urls.py.

The weekly fresh-URL benchmark cron failed silently every Monday from
2026-06-22 through 2026-06-29 because `fetch_tranco_legit` assumed
`data/top_100k.json` was a dict, but the file's schema had drifted to a
bare list during a routine data refresh. `list.keys()` raised
AttributeError, the cron crashed in 12 seconds, and the public
`docs/benchmarks/latest.json` stayed frozen on a stale snapshot.

These tests pin both supported shapes so the next schema drift can't
silently re-break the cron.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _load_eval_module() -> ModuleType:
    """Import scripts/eval_fresh_urls.py as a module without making
    `scripts/` a package (no __init__.py). Pytest's pythonpath = ["."]
    setting means `scripts.` imports are available even without the
    init file."""
    if "scripts.eval_fresh_urls" in sys.modules:
        return sys.modules["scripts.eval_fresh_urls"]
    # Add scripts/ to sys.path so direct module load works on systems
    # where the implicit-namespace-package path resolution doesn't
    # find it (Python 3.9 on some macOS builds, GitHub Actions).
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    return importlib.import_module("eval_fresh_urls")


def _write_top_100k(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_tranco_legit_handles_list_shape(tmp_path, monkeypatch):
    """top_100k.json as a bare list (current shape, 2026-06+) must
    not crash. This is the regression: code did `.keys()` on a list."""
    eval_module = _load_eval_module()
    _write_top_100k(
        tmp_path / "top_100k.json",
        ["google.com", "facebook.com", "github.com", "wikipedia.org"],
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=3)
    assert len(out) == 3
    assert all(u.startswith("https://") for u in out)
    # Domains must come from the input set.
    hosts = {u.removeprefix("https://") for u in out}
    assert hosts.issubset({"google.com", "facebook.com", "github.com", "wikipedia.org"})


def test_fetch_tranco_legit_handles_dict_shape(tmp_path, monkeypatch):
    """top_100k.json as {domain: rank} (legacy shape) is still
    accepted — historical files committed to the repo before the
    schema drift used this layout."""
    eval_module = _load_eval_module()
    _write_top_100k(
        tmp_path / "top_100k.json",
        {"google.com": 1, "facebook.com": 2, "github.com": 3, "wikipedia.org": 4},
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=2)
    assert len(out) == 2
    hosts = {u.removeprefix("https://") for u in out}
    assert hosts.issubset({"google.com", "facebook.com", "github.com", "wikipedia.org"})


def test_fetch_tranco_legit_rejects_unknown_shape(tmp_path, monkeypatch):
    """A future schema drift that's neither list nor dict must fail
    loudly, not silently produce zero URLs. We want the cron to red
    on the next refresh, not stay green with empty samples."""
    import pytest

    eval_module = _load_eval_module()
    _write_top_100k(tmp_path / "top_100k.json", "google.com")  # bare string
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    with pytest.raises(ValueError, match="expected list or dict"):
        eval_module.fetch_tranco_legit(limit=1)


def test_fetch_tranco_legit_uses_top_1m_when_present(tmp_path, monkeypatch):
    """When data/top-1m.csv exists, prefer it over the JSON fallback —
    the JSON path is only a last-resort. (Sanity check that the
    fallback branch isn't accidentally taken when the canonical CSV
    is there.)"""
    eval_module = _load_eval_module()
    csv_path = tmp_path / "top-1m.csv"
    csv_path.write_text(
        "\n".join(
            [f"{i},rank{i}.example.com" for i in range(1, 200)]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=5)
    assert len(out) == 5
    # Every domain must look like rankNN.example.com — confirms the
    # CSV branch ran, not the JSON fallback.
    for u in out:
        host = u.removeprefix("https://")
        assert host.startswith("rank") and host.endswith(".example.com")


# ─────────────────────────────────────────────────────────────────
# Quality gate — pre-publish gate that guards docs/benchmarks/latest.json
# ─────────────────────────────────────────────────────────────────

def _healthy_report() -> dict:
    """Baseline report that passes every gate — individual tests copy
    this and mutate one field to isolate what tripped the gate."""
    return {
        "ts": "2026-07-01T05:15:00Z",
        "n_phishing": 200,
        "n_safe": 200,
        "phishing": {
            "cleanway": {
                "tp": 120, "fp": 0, "tn": 0, "fn": 40, "unknown": 40,
                "recall": 0.75, "fpr": None,
                "precision": 1.0, "f1": 0.857,
            },
        },
        "safe": {
            "cleanway": {
                "tp": 0, "fp": 2, "tn": 190, "fn": 0, "unknown": 8,
                "recall": None, "fpr": 0.0104,
                "precision": None, "f1": None,
            },
        },
    }


def test_quality_gate_passes_healthy_run():
    """A well-formed 200-sample run with sane recall + FPR must pass —
    otherwise the gate is over-tuned and would starve latest.json."""
    eval_module = _load_eval_module()
    result = eval_module.check_quality_gate(_healthy_report())
    assert result.passed is True
    assert result.failed_gate is None


def test_quality_gate_blocks_low_sample_count():
    """A --sample 50 smoke run must not overwrite latest.json even
    though the numbers look reasonable — 50 URLs is too noisy to
    represent the public benchmark."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["n_phishing"] = 50
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    assert result.failed_gate == "n_phishing_below_min"
    assert "50" in (result.detail or "")


def test_quality_gate_blocks_high_unknown_rate():
    """The 2026-06-30 blowout — most of the phishing batch came back
    `unknown` because Cleanway rate-limited us. classify() still
    computes a recall on the few classified samples but it's noise.
    The gate must catch this and refuse to publish."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    # Move nearly everything into unknown: 10 classified, 190 unknown.
    report["phishing"]["cleanway"] = {
        "tp": 8, "fp": 0, "tn": 0, "fn": 2, "unknown": 190,
        "recall": 0.8, "fpr": None,
        "precision": 1.0, "f1": 0.888,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    # 190/(10+190) = 95%, well above the 30% ceiling — and 10<50 so the
    # classified-count gate also fires. Either failure is acceptable as
    # long as SOMETHING blocks; assert one of the two known failures.
    assert result.failed_gate in {
        "phishing_classified_below_min",
        "phishing_unknown_rate_too_high",
    }


def test_quality_gate_blocks_null_recall():
    """When every phishing sample came back as `unknown`, classify()
    returns recall=None. That's the exact 2026-06-30 signature and it
    MUST NOT flip the public pointer."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["n_phishing"] = 200
    report["phishing"]["cleanway"] = {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0, "unknown": 200,
        "recall": None, "fpr": None,
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    # The 0 classified samples gate should trip first.
    assert result.failed_gate in {
        "phishing_classified_below_min",
        "phishing_recall_null",
    }


def test_quality_gate_blocks_safe_batch_unknown_blowout():
    """If the safe batch has FPR=None AND is mostly `unknown` (the
    2026-06-30 fingerprint — phishing batch drained the 5/min window
    just before the safe batch), we can't trust the FPR side and
    must not publish."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["safe"]["cleanway"] = {
        "tp": 0, "fp": 0, "tn": 20, "fn": 0, "unknown": 180,
        "recall": None, "fpr": None,  # ← the fingerprint
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    assert result.failed_gate == "safe_unknown_rate_too_high"


def test_quality_gate_allows_safe_batch_with_valid_fpr_even_if_noisy():
    """If FPR came back non-null we accept the safe batch even if the
    unknown rate is a bit high — a real FPR is what we publish, and
    we already gated on the phishing side for the recall claim."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    # 40% unknown on safe — above the 30% ceiling — but FPR is set.
    report["safe"]["cleanway"] = {
        "tp": 0, "fp": 1, "tn": 119, "fn": 0, "unknown": 80,
        "recall": None, "fpr": 0.0083,
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is True


def test_min_interval_cleanway_bumped_to_16s():
    """The 5-per-minute cap needs >12s spacing; 13s was in-spec but
    left no room for network jitter. 16s (or more) is the value we
    ship — regression test in case anyone reverts to save wall-clock.
    """
    eval_module = _load_eval_module()
    assert eval_module.MIN_INTERVAL_S["cleanway"] >= 16.0


def test_both_batches_are_interleaved_for_every_resolver():
    """Phishing first spent the day's paid-source budgets (IPQS 150, LLM
    judge 300) before a single legit site was checked, so the false-positive
    rate was measured mostly without them. Interleaved, both batches meet the
    same budget state — and the same share of any quota running out."""
    eval_module = _load_eval_module()
    assert eval_module.interleave_batches(["p0", "p1", "p2"], ["l0"]) == [
        ("phishing", 0), ("legit", 0), ("phishing", 1), ("phishing", 2),
    ]


@pytest.mark.asyncio
async def test_an_interleaved_run_splits_back_into_its_batches():
    eval_module = _load_eval_module()
    seen: list[list[str]] = []

    async def fake_run(name, urls):
        seen.append(list(urls))
        return [eval_module.Verdict(name, "safe", detail=u) for u in urls]

    phish, legit = await eval_module.run_resolver_on_both(
        "cleanway", ["https://p0", "https://p1"], ["https://l0", "https://l1", "https://l2"], run=fake_run)
    assert seen == [["https://p0", "https://l0", "https://p1", "https://l1", "https://l2"]]  # one run
    assert [v.detail for v in phish] == ["https://p0", "https://p1"]
    assert [v.detail for v in legit] == ["https://l0", "https://l1", "https://l2"]


# ─────────────────────────────────────────────────────────────────
# The legitimate sample: real Russian sites outside the allowlist
# ─────────────────────────────────────────────────────────────────

import re  # noqa: E402

import httpx  # noqa: E402


def _legit():
    _load_eval_module()  # puts scripts/ on sys.path
    return importlib.import_module("benchmark_legit")


def test_committed_legit_sample_is_big_sourced_and_outside_the_allowlist():
    """The false-positive rate is only a measurement if the server really
    analyses every legit site — none may be one it trusts on sight."""
    from api.services.scoring import is_trusted_top_domain

    legit = _legit()
    sites = legit.load_legit_sample()
    assert len(sites) >= legit.MIN_SITES
    trusted = [s.host for s in sites if is_trusted_top_domain(s.host)]
    assert trusted == [], f"auto-trusted by the server: {trusted}"
    for s in sites:
        assert re.fullmatch(r"Wikidata Q\d+ P856|full check 2026-09-25 #1", s.source), s
    # Every kind of site an older person visits is represented.
    by_category = {c: sum(1 for s in sites if s.category == c) for c in legit.CATEGORIES}
    assert min(by_category.values()) >= 10, by_category
    assert sum(1 for s in sites if s.host.endswith(".xn--p1ai")) >= 30  # .рф
    # The geo-blocked case the 2026-09-25 report found called "Dangerous".
    assert sum(1 for s in sites if s.reachability == "blocked-abroad") >= 30


def test_a_site_nobody_saw_is_kept_only_for_a_state_body():
    """A blocked-abroad host never served its page to the curator: it rests on
    its Wikidata entry alone, which the list's header allows only for a state
    body. A resort museum (марцводы.рф) slipped in under a blanket '.рф is
    municipal' rule."""
    municipal = re.compile(r"поселени|район|сельсовет|-адм|округ|администрац", re.IGNORECASE)
    unseen = [s for s in _legit().load_legit_sample() if s.reachability == "blocked-abroad"]
    offenders = [
        s.host for s in unseen
        if s.category not in {"regional_gov", "city", "university"}
        and not (s.category == "rf" and municipal.search(s.name))
    ]
    assert offenders == []


def test_the_report_s_false_alarms_are_in_the_sample():
    hosts = {s.host for s in _legit().load_legit_sample()}
    for named in ("bankspb.ru", "президент.рф", "мойбизнес.рф", "разговорыоважном.рф", "rosreestr.gov.ru"):
        assert named.encode("idna").decode("ascii") in hosts, named


@pytest.mark.parametrize(
    "line,error",
    [
        ("example.ru | city | reachable-abroad | Wikidata Q1 P856", "expected"),
        ("президент.рф | rf | reachable-abroad | Wikidata Q1 P856 | x", "punycode"),
        ("www.example.ru | city | reachable-abroad | Wikidata Q1 P856 | x", "no www"),
        ("https://example.ru | city | reachable-abroad | Wikidata Q1 P856 | x", "no scheme"),
        ("example.ru | shop | reachable-abroad | Wikidata Q1 P856 | x", "unknown category"),
        ("example.ru | city | somewhere | Wikidata Q1 P856 | x", "unknown reachability"),
    ],
)
def test_malformed_legit_lines_fail_loudly(line, error):
    with pytest.raises(ValueError, match=error):
        _legit().parse_legit_sample(line)


def test_a_repeated_legit_host_fails_loudly():
    row = "example.ru | city | reachable-abroad | Wikidata Q1 P856 | x"
    with pytest.raises(ValueError, match="twice"):
        _legit().parse_legit_sample(f"# comment\n\n{row}\n{row}\n")


def _sites(n: int):
    legit = _legit()
    return [legit.LegitSite(f"site{i}.ru", "city", "reachable-abroad", "Wikidata Q1 P856", "x") for i in range(n)]


def test_selection_is_fixed_seed_and_drops_what_the_server_now_trusts():
    legit = _legit()
    sites = _sites(20)
    first = legit.select_legit_sample(sites, 10, lambda h: h == "site3.ru")
    again = legit.select_legit_sample(sites, 10, lambda h: h == "site3.ru")
    assert first == again
    assert len(first) == 10
    assert "site3.ru" not in {s.host for s in first}


def test_curated_run_claims_outside_allowlist_only_when_it_could_check(monkeypatch):
    eval_module = _load_eval_module()
    urls, sites, sources = eval_module.pick_legit("curated", 5, is_trusted=lambda _h: False)
    assert len(urls) == 5 and all(u.startswith("https://") for u in urls)
    assert [f"https://{s.host}" for s in sites] == urls
    assert sources["legit_outside_allowlist"] is True

    monkeypatch.setattr(_legit(), "allowlist_rule", lambda: None)
    _, _, unverified = eval_module.pick_legit("curated", 5)
    assert unverified["legit_outside_allowlist"] is False


def test_tranco_run_never_claims_a_false_positive_measurement(tmp_path, monkeypatch):
    eval_module = _load_eval_module()
    _write_top_100k(tmp_path / "top_100k.json", ["a.com", "b.com"])
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    _, sites, sources = eval_module.pick_legit("tranco", 2)
    assert sites is None
    assert sources["legit_outside_allowlist"] is False


def test_cleanway_answers_are_broken_down_by_slice():
    legit = _legit()
    sites = [
        legit.LegitSite("a.ru", "city", "blocked-abroad", "Wikidata Q1 P856", "a"),
        legit.LegitSite("b.ru", "city", "reachable-abroad", "Wikidata Q2 P856", "b"),
        legit.LegitSite("c.ru", "bank", "reachable-abroad", "Wikidata Q3 P856", "c"),
    ]
    outcomes = [
        legit.cleanway_outcome("dangerous", "dangerous"),
        legit.cleanway_outcome("unknown", "caution"),
        legit.cleanway_outcome("unknown", "rate_limited"),
    ]
    assert outcomes == ["dangerous", "caution", "no_answer"]
    out = legit.legit_breakdown(outcomes, sites)
    assert out["overall"] == {"safe": 0, "caution": 1, "dangerous": 1, "not_found": 0, "no_answer": 1}
    assert out["by_reachability"]["blocked-abroad"]["dangerous"] == 1
    assert out["by_category"]["city"]["caution"] == 1
    md = "\n".join(legit.render_breakdown_md(out))
    assert "| blocked-abroad | 0 | 0 | 1 | 0 | 0 |" in md


# ─────────────────────────────────────────────────────────────────
# Rate-limit identity: rotating installs under the per-IP ceiling
# ─────────────────────────────────────────────────────────────────


class _FakeTime:
    def __init__(self):
        self.now = 1000.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _pool(eval_module, fake, **kw):
    ids = iter(f"id-{i}" for i in range(1, 100))
    return eval_module.InstallPool(clock=fake.clock, sleep=fake.sleep, new_id=lambda: next(ids), **kw)


async def _ask(pool) -> str:
    async with pool.identity() as lease:
        await lease.ready()
        return lease.headers["X-Cleanway-Install"]


@pytest.mark.asyncio
async def test_each_install_is_paced_like_a_phone():
    eval_module = _load_eval_module()
    fake = _FakeTime()
    pool = _pool(eval_module, fake, size=1, min_interval=16.0)
    await _ask(pool)
    await _ask(pool)
    assert fake.sleeps == [16.0]  # 5 fresh checks a minute per install


@pytest.mark.asyncio
async def test_an_install_is_retired_after_its_quota():
    eval_module = _load_eval_module()
    fake = _FakeTime()
    pool = _pool(eval_module, fake, size=1, per_install=2, min_interval=0.0)
    assert [await _ask(pool) for _ in range(5)] == ["id-1", "id-1", "id-2", "id-2", "id-3"]
    assert pool.installs_used == 3


@pytest.mark.asyncio
async def test_the_run_stays_under_its_hourly_budget():
    eval_module = _load_eval_module()
    fake = _FakeTime()
    pool = _pool(eval_module, fake, size=1, per_install=100, min_interval=0.0, hourly_budget=3)
    for _ in range(4):
        await _ask(pool)
    assert len(fake.sleeps) == 1 and fake.sleeps[0] >= 3600  # the 4th waits for the window


@pytest.mark.asyncio
async def test_no_more_installs_in_flight_than_the_pool_holds():
    import asyncio

    eval_module = _load_eval_module()
    pool = eval_module.InstallPool(size=2, min_interval=0.0)
    first, second = pool.identity(), pool.identity()
    await first.__aenter__()
    await second.__aenter__()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(_ask(pool), timeout=0.05)
    await first.__aexit__(None, None, None)
    assert re.fullmatch(r"[0-9a-f-]{36}", await _ask(pool))
    await second.__aexit__(None, None, None)


def test_the_run_is_bounded_below_the_servers_per_ip_ceilings():
    from api.config import get_settings

    eval_module = _load_eval_module()
    s = get_settings()
    assert eval_module.IP_HOURLY_CEILING == s.public_install_ip_ceiling_per_window
    assert eval_module.IP_HOURLY_BUDGET < s.public_install_ip_ceiling_per_window
    assert eval_module.REQUESTS_PER_INSTALL < s.public_install_rate_limit_per_window
    fresh_per_minute = eval_module.PARALLEL_INSTALLS * 60 / eval_module.MIN_INTERVAL_S["cleanway"]
    assert fresh_per_minute < s.public_fresh_ip_ceiling_per_minute
    assert 60 / eval_module.MIN_INTERVAL_S["cleanway"] < s.public_fresh_checks_per_minute


async def _one_check(eval_module, monkeypatch, token: str) -> dict:
    monkeypatch.setattr(eval_module, "BENCHMARK_BYPASS_TOKEN", token)
    monkeypatch.setattr(eval_module, "_POOL", eval_module.InstallPool(size=1, min_interval=0.0))
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        return httpx.Response(200, json={"level": "safe", "score": 3})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verdict = await eval_module.check_cleanway(client, "https://example.ru")
    assert verdict.verdict == "safe"
    return seen[0]


@pytest.mark.asyncio
async def test_without_a_token_the_benchmark_identifies_as_an_app_install(monkeypatch):
    from api.services.rate_limiter import _INSTALL_ID_RE

    headers = await _one_check(_load_eval_module(), monkeypatch, token="")
    assert _INSTALL_ID_RE.fullmatch(headers["x-cleanway-install"])  # the server accepts it
    assert "x-cleanway-benchmark" not in headers


@pytest.mark.asyncio
async def test_latency_is_the_servers_not_our_own_pacing(monkeypatch):
    """The first smoke run reported a 14 s median: the wait for a paced
    install was counted as Cleanway's answer time."""
    eval_module = _load_eval_module()
    monkeypatch.setattr(eval_module, "BENCHMARK_BYPASS_TOKEN", "")
    monkeypatch.setattr(eval_module, "_POOL", eval_module.InstallPool(size=1, min_interval=0.3))

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"level": "safe", "score": 0})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await eval_module.check_cleanway(client, "https://one.ru")
        paced = await eval_module.check_cleanway(client, "https://two.ru")  # waits ~0.3 s for the install
    assert paced.latency_ms < 150


@pytest.mark.asyncio
async def test_a_run_checks_resolvers_side_by_side_and_records_when_cleanway_ran(tmp_path, monkeypatch):
    """VirusTotal alone needs ~105 min for 2 x 200 URLs; run after the others
    it pushed the weekly job past its timeout, which writes nothing. Offline:
    every feed and adapter is a stub."""
    import asyncio

    eval_module = _load_eval_module()
    phishing = [f"https://phish{i}.example/login" for i in range(3)]
    calls: list[str] = []

    async def fake_feed(_limit):
        return phishing

    async def no_feed(_limit):
        return []

    def fake_adapter(name):
        async def _check(_client, url):
            calls.append(name)
            await asyncio.sleep(0)  # let the other resolvers in, as real I/O would
            return eval_module.Verdict(name, "dangerous" if "phish" in url else "safe", detail=url)
        return _check

    monkeypatch.setattr(eval_module, "fetch_urlhaus_recent", fake_feed)
    monkeypatch.setattr(eval_module, "fetch_phishtank_recent", no_feed)
    monkeypatch.setattr(eval_module, "VT_KEY", "stub")
    for name in ("cleanway", "gsb", "phishtank", "cloudflare_families", "virustotal"):
        monkeypatch.setitem(eval_module.ADAPTERS, name, fake_adapter(name))
        monkeypatch.setitem(eval_module.MIN_INTERVAL_S, name, 0.0)
    monkeypatch.setattr(sys, "argv", ["eval_fresh_urls.py", "--sample", "3", "--out-tag", "t",
                                      "--out-dir", str(tmp_path)])

    assert await eval_module.main() == 0
    report = json.loads((tmp_path / "t-fresh-urls.json").read_text(encoding="utf-8"))

    assert len(set(calls[:5])) > 1, calls  # not one resolver after another
    legit = report["raw"]["legit_urls"]
    for name in ("cleanway", "virustotal"):
        assert [v["detail"] for v in report["raw"]["phishing"][name]] == phishing
        assert [v["detail"] for v in report["raw"]["safe"][name]] == legit
    assert report["phishing"]["cleanway"]["recall"] == 1.0
    assert report["safe"]["cleanway"]["fpr"] == 0.0
    window = report["cleanway_window_utc"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", window["start"])
    assert window["start"] <= window["end"]
    assert not (tmp_path / "latest.json").exists()  # 3 URLs never pass the gate


@pytest.mark.asyncio
async def test_a_429_is_retried_by_the_same_install(monkeypatch):
    """The retry after a 429 went out under the next install in the queue —
    a per-install limit dodged by switching ids, which the script says it
    never does."""
    eval_module = _load_eval_module()
    monkeypatch.setattr(eval_module, "BENCHMARK_BYPASS_TOKEN", "")
    monkeypatch.setattr(eval_module, "_POOL", eval_module.InstallPool(size=4, min_interval=0.0))
    ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        ids.append(request.headers["x-cleanway-install"])
        if len(ids) == 1:
            return httpx.Response(429, headers={"retry-after": "1"})
        return httpx.Response(200, json={"level": "safe", "score": 3})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        verdict = await eval_module.check_cleanway(client, "https://example.ru")
    assert verdict.verdict == "safe"
    assert len(ids) == 2 and ids[0] == ids[1]
    assert eval_module._POOL.requests == 2  # both attempts paced and counted


@pytest.mark.asyncio
async def test_with_a_token_the_benchmark_uses_the_bypass(monkeypatch):
    headers = await _one_check(_load_eval_module(), monkeypatch, token="tok")
    assert headers["x-cleanway-benchmark"] == "tok"
    assert "x-cleanway-install" not in headers


def test_report_markdown_says_what_the_legit_sample_is():
    eval_module = _load_eval_module()
    report = _healthy_report()
    for batch in ("phishing", "safe"):
        report[batch]["cleanway"]["latency_p50_ms"] = None
    report["sources"] = {"legit_outside_allowlist": True, "cleanway_identity": "4 rotating installs"}
    report["cleanway_on_legit"] = _legit().legit_breakdown([], [])
    report["cleanway_window_utc"] = {"start": "2026-10-04T15:16:02Z", "end": "2026-10-04T15:44:10Z"}
    md = eval_module.render_md(report)
    assert "OUTSIDE the Tranco top-100k" in md
    assert "Cleanway on the legitimate sample" in md
    assert "The Cleanway checks ran 2026-10-04T15:16:02Z – 2026-10-04T15:44:10Z." in md
    report["sources"]["legit_outside_allowlist"] = False
    assert "NOT a measurement" in eval_module.render_md(report)
