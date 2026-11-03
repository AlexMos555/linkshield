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


def _sample(urls, limit, seed=7, max_per_site=2):
    method = _method()
    site_of, _rule = method.site_rule()
    return method.sample_phishing(urls, limit, seed=seed, host_of=_host, site_of=site_of,
                                  max_per_site=max_per_site)


def test_the_sample_is_a_fixed_seed_draw_from_the_whole_dump_not_its_top():
    urls = _pool(1000)
    picked, stats = _sample(urls, 10)
    again, _ = _sample(urls, 10)
    other, _ = _sample(urls, 10, seed=8)
    assert picked == again                     # reproducible from the dump and the seed
    assert picked != other
    assert picked != list(range(10))           # not the dump's first ten rows
    assert max(picked) > 100                   # drawn from the whole dump
    assert picked == sorted(picked)            # kept in the dump's order
    assert stats["seed"] == 7 and stats["pool_rows"] == 1000 and stats["n"] == 10


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

@pytest.mark.parametrize("answers, expected", [
    ([None, True, False], "resolves"),   # one resolver resolved it: it exists somewhere
    ([False, None], "nxdomain"),
    ([False, False], "nxdomain"),
    ([None, None], "unknown"),
    ([], "unknown"),
])
def test_row_existence(answers, expected):
    assert _method().row_existence(answers) == expected


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
    assert s["dangerous_rate_all"] == pytest.approx(6 / 11)
    assert s["dangerous_rate_resolving"] == pytest.approx(6 / 10)
    assert s["dangerous_rate_resolving_wilson95"] == method.wilson95(6, 10)
    assert s["dangerous_rate_all_wilson95"] == method.wilson95(6, 11)
    # The fields landing/lib/benchmark.ts reads, as before: caution, dead names
    # and no answer are all "unknown", recall is tp / (tp + fn).
    assert (s["tp"], s["fn"], s["fp"], s["tn"], s["unknown"]) == (6, 1, 0, 0, 4)
    assert s["recall"] == pytest.approx(6 / 7)
    assert s["recall_wilson95"] == method.wilson95(6, 7)
    assert s["precision"] == 1.0 and s["fpr"] is None and s["fpr_wilson95"] is None


def test_the_legit_summary_counts_a_dangerous_answer_as_a_false_positive():
    s = _method().summarize(["safe"] * 8 + ["dangerous"] + ["caution"] + ["not_found"], "safe")
    assert (s["fp"], s["tn"], s["tp"], s["fn"], s["unknown"]) == (1, 8, 0, 0, 2)
    assert s["fpr"] == pytest.approx(1 / 9)
    assert s["dangerous_rate_resolving"] == pytest.approx(1 / 10)
    assert s["recall"] is None and s["recall_wilson95"] is None


def test_an_empty_batch_has_no_rates():
    s = _method().summarize([], "dangerous")
    assert s["n"] == 0 and s["dangerous_rate_all"] is None and s["dangerous_rate_resolving"] is None
    assert s["dangerous_rate_resolving_wilson95"] is None


def test_the_answer_table_says_what_every_resolver_answered():
    method = _method()
    report = {
        "phishing": {"cleanway": method.summarize(["dangerous", "caution", "not_found", "safe"], "dangerous")},
        "safe": {"cleanway": method.summarize(["safe", "safe"], "safe")},
    }
    md = "\n".join(method.render_outcomes_md(report))
    assert "| phishing | cleanway | 1 | 1 | 1 | 1 | 0 | 25.0% | 33.3% (" in md
    assert "| legit | cleanway | 0 | 0 | 2 | 0 | 0 | 0.0% | 0.0% (" in md
    # A report written before the fields existed renders no table.
    assert method.render_outcomes_md({"phishing": {"cleanway": {"tp": 1}}, "safe": {}}) == []
