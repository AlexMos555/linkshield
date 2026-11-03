"""The counting rules of the weekly fresh-URL benchmark (scripts/benchmark_method.py).

Until 2026-11-03 the published run (method_version 1):
  * took the first rows of PhishTank's online-valid dump and dropped
    repeated hostnames only, while the report said "deduplicated by
    registrable domain". One campaign's burst filled a quarter of a week
    (allegro 50 of 200 rows on 2026-11-01, bradesco 39 on 2026-10-25), and
    random subdomains of one name each counted as a phishing site;
  * counted a "dangerous" for a name that does not resolve when it came from
    Cleanway's blocklist or Cloudflare's 0.0.0.0 sinkhole — both answer
    before any existence check — but not when Cleanway found the name dead;
  * had one "unknown" for a caution, a dead name and no answer alike.

The first draft of method_version 2 drew over the whole dump instead. The dump
is newest-first and goes back to 2012, so the sample was mostly years old
(seed 42 on the 2026-11-03 dump: 5 of 200 rows from the last 7 days, 102
older than a year) while the report still called it fresh, and a host's
chance grew with its row count (qrco.de, docs.google.com: in every sample).
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _method():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    return importlib.import_module("benchmark_method")


def _host(url: str) -> str:
    """As eval_fresh_urls.domain_of: the hostname, without www."""
    return url.split("://", 1)[-1].split("/", 1)[0].removeprefix("www.")


# ── Where one site ends ──

def test_a_site_is_the_registrable_domain_by_the_servers_own_rules():
    site_of, rule = _method().site_rule()
    assert "public_suffix" in rule and "_platform_tenant_site" in rule
    # One campaign on random subdomains of one name is one site …
    assert site_of("0762184c.taozhen.net") == site_of("ab829014.taozhen.net") == "taozhen.net"
    assert site_of("allegro.oglozsenie-812984.sbs") == "oglozsenie-812984.sbs"
    # … under a multi-label public suffix too (the PSL's ICANN rules) …
    assert site_of("login.example.co.uk") == "example.co.uk"
    assert site_of("paypal-secure.my.id") == "paypal-secure.my.id"
    # … but two tenants of a hosting platform are two customers, as the server
    # reads them: collapsing them would hide the class Cleanway misses most.
    assert site_of("fuzzy-giggle-eta.vercel.app") != site_of("spectrum-revenve-team.vercel.app")
    assert site_of("oosoftlms.weebly.com") == "oosoftlms.weebly.com"
    assert site_of("221.14.192.60") == "221.14.192.60"


def test_without_the_scorer_the_rule_falls_back_to_the_public_suffix_list(monkeypatch):
    """The weekly runner installs only httpx and pydantic. Should the scorer
    stop importing there, the dedup still follows the PSL — and says so."""
    method = _method()
    monkeypatch.setitem(sys.modules, "api.services.scoring", None)  # import fails
    site_of, rule = method.site_rule()
    assert site_of("a.b.example.co.uk") == "example.co.uk"
    assert "tenants not split" in rule


# ── The phishing sample ──

def _pool(n: int) -> list[str]:
    return [f"https://site{i}.example/login" for i in range(n)]


def _sample(urls, limit, seed=7, max_per_site=2, pool=None):
    method = _method()
    site_of, _rule = method.site_rule()
    return method.sample_phishing(urls, limit, seed=seed, host_of=_host, site_of=site_of,
                                  max_per_site=max_per_site, pool=pool)


def _times(ages_in_hours: list[float]) -> list[str]:
    """Submission times `ages_in_hours` before 2026-11-03 14:00 UTC, as the dump writes them."""
    from datetime import datetime, timedelta, timezone

    newest = datetime(2026, 11, 3, 14, 0, tzinfo=timezone.utc)
    return [(newest - timedelta(hours=h)).isoformat() for h in ages_in_hours]


def test_the_pool_is_the_window_before_the_dumps_newest_row():
    """PhishTank's dump is newest-first and goes back to 2012: a draw over all
    of it measures links years old. The pool is the rows submitted in the
    `days` before the newest row, so the dump alone fixes it."""
    method = _method()
    submitted = _times([0, 30, 7 * 24, 7 * 24 + 0.01, 400 * 24])
    pool, window = method.recent_window(submitted, days=7)
    assert pool == [0, 1, 2]                     # the start itself is in, a second older is out
    assert window == {"days": 7, "start": "2026-10-27T14:00:00+00:00",
                      "end": "2026-11-03T14:00:00+00:00", "undated_rows": 0}


def test_the_window_skips_undated_rows_and_reads_a_time_without_zone_as_utc():
    method = _method()
    pool, window = method.recent_window(["2026-11-03T12:00:00", "", None, "not a time",
                                         "2026-11-03T13:00:00+00:00"], days=7)
    assert pool == [0, 4]
    assert window["undated_rows"] == 3 and window["end"] == "2026-11-03T13:00:00+00:00"


def test_no_window_means_the_whole_dump_and_no_dates_mean_no_pool():
    method = _method()
    pool, window = method.recent_window(_times([0, 9000]), days=0)
    assert pool == [0, 1] and window == {"days": 0, "start": None, "end": None, "undated_rows": 0}
    # A dump without a single readable time cannot say what is fresh: no sample,
    # and the run stops, rather than drawing stale links unnoticed.
    pool, window = method.recent_window(["", "x"], days=7)
    assert pool == [] and (window["start"], window["end"], window["undated_rows"]) == (None, None, 2)


def test_the_sample_is_a_fixed_seed_draw_from_the_window_not_its_top():
    urls = _pool(1000)
    submitted = _times([i / 10 for i in range(300)] + [400 * 24] * 700)   # 300 fresh, 700 a year old
    pool, _window = _method().recent_window(submitted, days=7)
    picked, stats = _sample(urls, 10, pool=pool)
    again, _ = _sample(urls, 10, pool=pool)
    other, _ = _sample(urls, 10, seed=8, pool=pool)
    assert picked == again                     # reproducible from the dump and the seed
    assert picked != other
    assert picked != list(range(10))           # not the window's first ten rows
    assert all(i < 300 for i in picked)        # never outside the window
    assert max(picked) > 100                   # drawn from the whole window
    assert picked == sorted(picked)            # kept in the dump's order
    assert stats["seed"] == 7 and stats["pool_rows"] == 300 and stats["n"] == 10


def test_the_draw_is_uniform_over_sites_not_over_rows():
    """A host with thousands of rows (qrco.de, docs.google.com on the real dump)
    was in every sample: the rows were shuffled, so its chance grew with its
    row count. Sites are shuffled now, then hosts are picked from them."""
    urls = ["https://big.example/x"] * 2000 + [f"https://s{i}.example/" for i in range(99)]
    seeds = range(200)
    hits = sum(1 for seed in seeds
               if any(urls[i] == "https://big.example/x" for i in _sample(urls, 10, seed=seed)[0]))
    assert 0.03 <= hits / len(seeds) <= 0.2    # 10 of 100 sites: about 10%, not ~100%


def test_a_host_is_drawn_once_at_its_first_row_in_the_dump():
    urls = ["https://a.example/new", "https://b.example/", "https://a.example/old"]
    picked, stats = _sample(urls, 5)
    assert picked == [0, 1] and stats["pool_hosts"] == 2


def test_one_site_never_gives_more_than_max_per_site_rows_and_a_host_counts_once():
    campaign = [f"https://{i:08x}.campaign.cfd/{i}" for i in range(60)]
    repeats = ["https://same.example/a", "https://same.example/b", "https://www.same.example/c"]
    others = _pool(40)
    urls = campaign + repeats + others
    picked, stats = _sample(urls, 100)
    hosts = [_host(urls[i]) for i in picked]
    assert sum(1 for h in hosts if h.endswith(".campaign.cfd")) == 2
    assert hosts.count("same.example") == 1
    assert len(picked) == 2 + 1 + 40           # everything else is in
    assert stats["max_per_site"] == 2
    assert stats["pool_hosts"] == 60 + 1 + 40
    assert stats["pool_sites"] == 1 + 1 + 40
    assert stats["sites"] == 42


def test_an_unparsable_row_is_skipped():
    picked, _ = _sample(["", "https://ok.example/"], 5)
    assert picked == [1]


# ── One existence fact per row, the same for every resolver ──

@pytest.mark.parametrize("probe, others, expected", [
    # The probe decides whenever it can tell. Cleanway's `exists: false` also
    # covers a name that resolves into a blocked network (its SSRF guard gives
    # the same answer), and its "it exists" may come from a day-old cache.
    (True, [False, False], "resolves"),
    (False, [True, None], "nxdomain"),
    (True, [], "resolves"),
    (False, [], "nxdomain"),
    # Only when it could not (SERVFAIL, a timeout): the resolvers' own answers.
    (None, [None, True, False], "resolves"),
    (None, [False, None], "nxdomain"),
    (None, [None, None], "unknown"),
    (None, [], "unknown"),
])
def test_row_existence(probe, others, expected):
    assert _method().row_existence(probe, others) == expected


@pytest.mark.parametrize("verdict, level, existence, expected", [
    # A name that does not resolve: nobody caught it, nobody missed it —
    # Cleanway's blocklist, Cloudflare's 0.0.0.0, PhishTank's listing alike.
    ("dangerous", None, "nxdomain", "not_found"),
    ("dangerous", "dangerous", "nxdomain", "not_found"),
    ("safe", "safe", "nxdomain", "not_found"),
    ("unknown", "caution", "nxdomain", "not_found"),
    ("unknown", None, "nxdomain", "not_found"),
    # Anything else as answered.
    ("dangerous", None, "resolves", "dangerous"),
    ("dangerous", None, "unknown", "dangerous"),
    ("safe", None, "resolves", "safe"),
    ("unknown", "caution", "resolves", "caution"),   # Cleanway said "not found", the name resolves
    ("unknown", "caution", "unknown", "caution"),
    ("unknown", None, "resolves", "no_answer"),       # rate-limited, not indexed, error
])
def test_outcome(verdict, level, existence, expected):
    assert _method().outcome(verdict, level, existence) == expected


# ── The summary ──

@pytest.mark.parametrize("k, n, expected", [
    (50, 100, [0.4038, 0.5962]),
    (0, 10, [0.0, 0.2775]),
    (10, 10, [0.7225, 1.0]),
])
def test_wilson95(k, n, expected):
    assert _method().wilson95(k, n) == pytest.approx(expected, abs=1e-4)


def test_wilson95_of_nothing_is_none():
    assert _method().wilson95(0, 0) is None


def test_the_phishing_summary_counts_every_kind_of_answer():
    method = _method()
    outcomes = ["dangerous"] * 6 + ["caution"] * 2 + ["not_found"] + ["safe"] + ["no_answer"]
    s = method.summarize(outcomes, "dangerous")
    assert (s["n"], s["dangerous"], s["caution"], s["safe"], s["not_found"], s["no_answer"]) == (11, 6, 2, 1, 1, 1)
    assert s["resolving"] == 10
    # answered = n - not found - no answer: a rate never counts a row nobody judged.
    assert s["answered"] == 9
    assert s["dangerous_rate_answered"] == pytest.approx(6 / 9)
    assert s["dangerous_rate_answered_wilson95"] == method.wilson95(6, 9)
    assert s["warned_rate_answered"] == pytest.approx(8 / 9)          # dangerous or caution
    assert s["warned_rate_answered_wilson95"] == method.wilson95(8, 9)
    assert not {"dangerous_rate_all", "dangerous_rate_resolving"} & set(s)
    # The fields landing/lib/benchmark.ts reads, as before: caution, dead names
    # and no answer are all "unknown", recall is tp / (tp + fn).
    assert (s["tp"], s["fn"], s["fp"], s["tn"], s["unknown"]) == (6, 1, 0, 0, 4)
    assert s["recall"] == pytest.approx(6 / 7)
    assert s["recall_wilson95"] == method.wilson95(6, 7)
    assert s["precision"] == 1.0 and s["fpr"] is None and s["fpr_wilson95"] is None


def test_the_legit_summary_counts_a_dangerous_answer_as_a_false_positive():
    s = _method().summarize(["safe"] * 8 + ["dangerous"] + ["caution"] + ["not_found"] + ["no_answer"], "safe")
    assert (s["fp"], s["tn"], s["tp"], s["fn"], s["unknown"]) == (1, 8, 0, 0, 3)
    assert s["fpr"] == pytest.approx(1 / 9)
    assert s["answered"] == 10
    assert s["dangerous_rate_answered"] == pytest.approx(1 / 10)
    # A caution on a real bank's site is a warning its users see too.
    assert s["warned_rate_answered"] == pytest.approx(2 / 10)
    assert s["recall"] is None and s["recall_wilson95"] is None


def test_a_rate_limited_resolver_is_not_shown_missing_what_it_never_judged():
    """PhishTank answered 429 on 174 of 200 rows on 2026-11-01. Over every
    live row its catches would read 13%, as if the 174 were misses."""
    s = _method().summarize(["dangerous"] * 26 + ["no_answer"] * 174, "dangerous")
    assert (s["answered"], s["dangerous_rate_answered"]) == (26, 1.0)


def test_an_empty_batch_has_no_rates():
    s = _method().summarize([], "dangerous")
    assert s["n"] == 0 and s["answered"] == 0
    assert s["dangerous_rate_answered"] is None and s["warned_rate_answered"] is None
    assert s["dangerous_rate_answered_wilson95"] is None and s["warned_rate_answered_wilson95"] is None


def test_the_answer_table_says_what_every_resolver_answered():
    method = _method()
    report = {
        "phishing": {"cleanway": method.summarize(["dangerous", "caution", "not_found", "safe", "no_answer"],
                                                  "dangerous")},
        "safe": {"cleanway": method.summarize(["safe", "safe", "caution", "dangerous"], "safe")},
    }
    md = "\n".join(method.render_outcomes_md(report))
    # n | dangerous | caution | safe | not found | no answer | answered | dangerous / answered | warned / answered
    assert "| phishing | cleanway | 5 | 1 | 1 | 1 | 1 | 1 | 3 | 33.3% (" in md
    assert "| legit | cleanway | 4 | 1 | 1 | 2 | 0 | 0 | 4 | 25.0% (" in md
    assert "| 50.0% (" in md                   # legit: warned = dangerous or caution, 2 of 4
    assert "dangerous / answered (95% CI)" in md and "warned / answered (95% CI)" in md
    # It called "dangerous / resolving" the false-alarm rate on the legit batch,
    # while it left Cleanway's cautions (63 of 200 real sites on 2026-11-01) out.
    assert "false-alarm" not in md and "false alarm" not in md
    # A report written before the fields existed renders no table.
    assert method.render_outcomes_md({"phishing": {"cleanway": {"tp": 1}}, "safe": {}}) == []
