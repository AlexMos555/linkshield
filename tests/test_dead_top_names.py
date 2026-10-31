"""Popular names that stopped existing get none of the lists' trust.

On 2026-10-31, 1,139 of data/top_100k.json's names were NXDOMAIN and 215
registered to nobody — rank 105 among them. Whoever registers one inherits
the allowlist, the popularity rank, the OTX waiver, the blocklist's
never-block guard and the phone's veto (api/services/dead_top_names.py).
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import pathlib

import pytest

from api.services import dead_top_names, ml_features, scoring, tranco

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def dead(monkeypatch):
    """Tombstone the given names for the test."""
    def _set(*names: str) -> None:
        monkeypatch.setattr(dead_top_names, "DEAD_TOP_NAMES", frozenset(names))
    return _set


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


# ── The file ──

def test_the_file_loads_sorted_with_a_date_per_name():
    """No subset check against the current lists: a tombstone outlives the
    name's place on them (a rebuild may bring it back)."""
    import datetime

    data = json.loads((ROOT / "data" / dead_top_names.DEAD_FILE).read_text(encoding="utf-8"))
    names = data["names"]
    assert set(names) == dead_top_names.DEAD_TOP_NAMES
    assert list(names) == sorted(names)
    assert all(n == n.lower().strip(".") and "." in n for n in names)
    assert all(datetime.date.fromisoformat(d) for d in names.values())


def test_an_unreadable_file_tombstones_nothing(tmp_path, caplog):
    assert dead_top_names.load(str(tmp_path / "missing.json")) == frozenset()
    assert "not loaded" in caplog.text


def test_every_tombstone_is_untrusted_and_so_is_anything_under_it():
    for name in sorted(dead_top_names.DEAD_TOP_NAMES):
        assert not scoring.is_trusted_top_domain(name), name
        assert not scoring.is_trusted_top_domain(f"zq7.{name}"), name


# ── The allowlist ──

def test_a_dead_entry_is_no_key_and_no_shorter_entry_stands_in(dead):
    assert scoring.top_domain_key("x.mai.gov.ro") == "mai.gov.ro"
    dead("mai.gov.ro")
    # gov.ro is an entry too, but it is not the dead name's owner.
    assert scoring.top_domain_key("x.mai.gov.ro") is None
    assert scoring.top_domain_key("gov.ro") == "gov.ro"
    assert not scoring.is_trusted_top_domain("mai.gov.ro")


def test_a_dead_name_is_scored_not_waved_through(dead):
    dead()
    _, _, reasons = scoring.calculate_score(_signals("postimg.org", domain_age_days=2))
    assert "known_legitimate" in {r.signal for r in reasons}
    dead("postimg.org")
    _, _, reasons = scoring.calculate_score(_signals("postimg.org", domain_age_days=2))
    assert "known_legitimate" not in {r.signal for r in reasons}
    assert "domain_very_new" in {r.signal for r in reasons}


def test_the_lists_themselves_stay_the_models_bytes():
    """Applied where the lists are read: data/top_100k.json and the set the
    model is served (LIVE_FEATURE_DATA) are untouched."""
    assert ml_features.LIVE_FEATURE_DATA.top_domains is scoring.TOP_DOMAINS
    assert len(scoring.TOP_DOMAINS) == 100_000


# ── OTX ──

def test_otx_reports_about_a_dead_top_10k_name_count(dead):
    name = "w2rt6byl5nf1opmc-a.com"
    assert name in scoring.TOP_10K_RANKS
    dead(name)
    _, _, reasons = scoring.calculate_score(_signals(name, alienvault_pulse_count=30))
    assert sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx")) == 60


# ── The ML safe override ──

def test_the_model_cannot_talk_a_dead_name_down(dead, monkeypatch):
    from api.services import ml_scorer

    monkeypatch.setattr(ml_scorer, "ml_predict", lambda d: {"phishing_probability": 0.02, "confidence": 0.9})
    # The same shape under a name no list has: the model's "safe" counts.
    _, _, reasons = scoring.calculate_score(_signals("paypal.com.login.qx7-unlisted.org", domain_age_days=2))
    assert "ml_safe_override" in {r.signal for r in reasons}
    dead("postimg.org")
    _, _, reasons = scoring.calculate_score(_signals("paypal.com.login.postimg.org", domain_age_days=2))
    assert "ml_safe_override" not in {r.signal for r in reasons}


# ── The popularity rank ──

def test_a_dead_name_has_no_rank_whatever_redis_holds(dead, monkeypatch):
    async def _no_redis():
        raise AssertionError("a dead name must not be looked up")
    monkeypatch.setattr(tranco, "get_redis", _no_redis)
    dead("postimg.org")
    assert asyncio.run(tranco.get_tranco_rank("postimg.org")) is None


# ── The blocklist publisher ──

def test_the_publishers_guards_leave_dead_names_out(monkeypatch):
    rdd = _script("refresh_dangerous_domains")
    monkeypatch.setattr(rdd, "DEAD_TOP_NAMES", frozenset({"postimg.org"}))
    guard = rdd.load_popular_guard()
    assert "postimg.org" not in guard and "google.com" in guard

    class _Redis:
        async def hmget(self, key, names):
            return ["105" for _ in names]

    is_popular = asyncio.run(rdd._tranco_guard(_Redis(), ["i.postimg.org", "www.google.com"], None))
    assert not is_popular("postimg.org") and is_popular("google.com")
    out = rdd.build_blockset(["i.postimg.org"], guard, shared_suffixes=set(), is_popular=is_popular,
                             brand_owned=frozenset())
    assert out == {"i.postimg.org"}


# ── The phone's veto ──

def test_the_phones_veto_leaves_dead_names_out():
    assets = _script("build_mobile_assets")
    veto = set(assets.OUT.read_text(encoding="utf-8").split())
    top10k = set(json.loads((ROOT / "data" / "top_10k.json").read_text()))
    dead_in_10k = dead_top_names.DEAD_TOP_NAMES & top10k
    assert dead_in_10k and not dead_in_10k & veto
    assert "google.com" in veto


# ── The sweep ──

def _fake(answers: dict[tuple[str, str], str], default: str = "alive"):
    """A resolver: `answers` by (name, server), "*" for every server; the
    parent zone's servers under the server name "parent" (default: as the
    resolvers say)."""
    def answer(name: str, server: str) -> str:
        if name in ("google.com", "wikipedia.org", "cloudflare.com"):
            return "alive"
        if name.startswith("cleanway-canary-"):
            return "nxdomain"
        return answers.get((name, server), answers.get((name, "*"), default))

    async def resolve(name: str, server: str) -> str:
        return answer(name, server)

    async def at_parent(name: str) -> str:
        return answer(name, "parent")

    return resolve, at_parent


def _args(tmp_path, **kw):
    import argparse
    top = tmp_path / "top.json"
    top.write_text(json.dumps(["a.com", "b.com", "c.com", "gone.com", "u.com", "l.com"]))
    rep = tmp_path / "rep.json"
    rep.write_text(json.dumps({"r.com": 5000}))
    base = dict(dry_run=False, report=None, today="2026-10-31", max_new=100, pending=None, pending_base=None,
                out=str(tmp_path / "dead.json"), top=str(top), reported=str(rep))
    base.update(kw)
    return argparse.Namespace(**base)


def test_a_name_is_dead_only_when_both_resolvers_say_nxdomain(tmp_path):
    sweep = _script("refresh_dead_top_names")
    answers = {("a.com", "*"): "nxdomain",                                       # dead at both
               ("b.com", "1.1.1.1"): "nxdomain", ("b.com", "8.8.8.8"): "alive",  # one says so
               ("b.com", "parent"): "nxdomain",
               ("c.com", "*"): "unknown", ("c.com", "parent"): "nxdomain",       # SERVFAIL, timeouts
               ("r.com", "*"): "nxdomain",                                       # a reported name
               ("gone.com", "*"): "nxdomain", ("gone.com", "parent"): "alive",   # delegated and served
               ("u.com", "*"): "nxdomain", ("u.com", "parent"): "unknown",       # the registry did not answer
               ("l.com", "*"): "nxdomain", ("l.com", "parent"): "lame"}          # delegated, served by nobody
    args = _args(tmp_path)
    assert asyncio.run(sweep.run(args, *_fake(answers))) == 0
    names = json.loads(pathlib.Path(args.out).read_text())["names"]
    assert names == {"a.com": "2026-10-31", "l.com": "2026-10-31", "r.com": "2026-10-31"}


def test_a_name_the_first_resolver_dropped_is_asked_again(tmp_path):
    sweep = _script("refresh_dead_top_names")
    resolve, at_parent = _fake({("a.com", "*"): "nxdomain"})
    asked: dict[str, int] = {}

    async def flaky(name, server):
        if name == "a.com" and server == "1.1.1.1":
            asked[name] = asked.get(name, 0) + 1
            if asked[name] == 1:
                return "unknown"
        return await resolve(name, server)

    args = _args(tmp_path)
    assert asyncio.run(sweep.run(args, flaky, at_parent)) == 0
    assert json.loads(pathlib.Path(args.out).read_text())["names"] == {"a.com": "2026-10-31"}


def test_tombstones_are_sticky_and_revived_names_are_reported(tmp_path):
    sweep = _script("refresh_dead_top_names")
    args = _args(tmp_path, report=str(tmp_path / "report.md"), today="2026-11-07")
    pathlib.Path(args.out).write_text(sweep.render({"gone.com": "2026-10-31"}))
    assert asyncio.run(sweep.run(args, *_fake({("a.com", "*"): "nxdomain"}))) == 0
    names = json.loads(pathlib.Path(args.out).read_text())["names"]
    assert names == {"a.com": "2026-11-07", "gone.com": "2026-10-31"}  # gone.com resolves again, kept
    assert "`gone.com`" in pathlib.Path(args.report).read_text() and "Revived" in pathlib.Path(args.report).read_text()


def test_revived_names_alone_exit_for_an_issue(tmp_path):
    sweep = _script("refresh_dead_top_names")
    args = _args(tmp_path)
    pathlib.Path(args.out).write_text(sweep.render({"gone.com": "2026-10-31"}))
    assert asyncio.run(sweep.run(args, *_fake({}))) == sweep.EXIT_REVIVED
    assert json.loads(pathlib.Path(args.out).read_text())["names"] == {"gone.com": "2026-10-31"}


def test_an_open_sweep_prs_additions_are_kept_and_nothing_else_of_it(tmp_path):
    """The next run's PR replaces the open one: the names it adds come
    along, marked in the report. A line its base had and main has since lost
    (removed by a person) does not come back."""
    sweep = _script("refresh_dead_top_names")
    pending = tmp_path / "pending.json"
    pending.write_text(sweep.render({"c.com": "2026-10-31", "removed.com": "2026-10-24"}))
    base = tmp_path / "base.json"
    base.write_text(sweep.render({"removed.com": "2026-10-24"}))
    args = _args(tmp_path, pending=str(pending), pending_base=str(base), today="2026-11-07",
                 report=str(tmp_path / "report.md"))
    assert asyncio.run(sweep.run(args, *_fake({("a.com", "*"): "nxdomain", ("c.com", "*"): "unknown"}))) == 0
    assert json.loads(pathlib.Path(args.out).read_text())["names"] == {"a.com": "2026-11-07", "c.com": "2026-10-31"}
    text = pathlib.Path(args.report).read_text()
    assert "`c.com` *(carried over)*" in text and "`a.com`" in text and "removed.com" not in text


def test_the_canary_is_a_fresh_name_each_run():
    sweep = _script("refresh_dead_top_names")
    assert sweep.dead_canary() != sweep.dead_canary()


@pytest.mark.parametrize("case", ["canary", "parent", "parent_nx", "too_many"])
def test_the_sweep_refuses_and_writes_nothing(tmp_path, case):
    sweep = _script("refresh_dead_top_names")
    args = _args(tmp_path, max_new=1)
    resolve, at_parent = _fake({}, default="nxdomain")
    if case == "canary":
        async def resolve(name, server):  # a resolver that answers NXDOMAIN for everything
            return "nxdomain"
    elif case == "parent":
        async def at_parent(name):  # parent servers that cannot be asked
            return "unknown"
    elif case == "parent_nx":
        async def at_parent(name):  # a parent check that calls google.com dead
            return "nxdomain"
    assert asyncio.run(sweep.run(args, resolve, at_parent)) == 2
    assert not pathlib.Path(args.out).exists()


def test_a_dry_run_writes_nothing(tmp_path):
    sweep = _script("refresh_dead_top_names")
    args = _args(tmp_path, dry_run=True)
    assert asyncio.run(sweep.run(args, *_fake({("a.com", "*"): "nxdomain"}))) == 0
    assert not pathlib.Path(args.out).exists()


# ── What the parent zone said ──

def _reply(rcode="NOERROR", tc=False, answer=(), authority=(), aa=False):
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rrset

    q = dns.message.make_query("x.example.com", "NS")
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.from_text(rcode))
    if tc:
        r.flags |= dns.flags.TC
    if not aa:
        r.flags &= ~dns.flags.AA
    else:
        r.flags |= dns.flags.AA
    r.answer = [dns.rrset.from_text(*a) for a in answer]
    r.authority = [dns.rrset.from_text(*a) for a in authority]
    return r


@pytest.mark.parametrize("reply, verdict", [
    (dict(rcode="NXDOMAIN"), "nxdomain"),
    (dict(authority=[("x.example.com.", 172800, "IN", "NS", "ns1.host.net.")]), "referral"),
    (dict(authority=[("example.com.", 900, "IN", "SOA",
                      "a.ns. h.ns. 1 7200 900 1209600 86400")]), "alive"),                      # NODATA
    (dict(answer=[("x.example.com.", 300, "IN", "NS", "ns1.host.net.")]), "alive"),
    (dict(tc=True), "unknown"),                       # a.registry.qa over UDP: empty, truncated
    (dict(), "unknown"),                              # NOERROR naming nothing
    (dict(authority=[("other.example.com.", 0, "IN", "NS", "ck02.example.com.")]), "unknown"),
    (dict(rcode="REFUSED"), "unknown"),
])
def test_only_the_parents_own_word_counts(reply, verdict):
    import dns.name

    sweep = _script("refresh_dead_top_names")
    assert sweep.parent_verdict(_reply(**reply), dns.name.from_text("x.example.com")) == verdict


def test_a_tombstone_the_parent_delegates_again_is_reported_as_revived(tmp_path):
    """Its new servers may deny the apex like FC2's: the resolvers still say
    NXDOMAIN, the registry says it is someone's again."""
    sweep = _script("refresh_dead_top_names")
    args = _args(tmp_path, report=str(tmp_path / "report.md"))
    pathlib.Path(args.out).write_text(sweep.render({"gone.com": "2026-10-31"}))
    answers = {("gone.com", "*"): "nxdomain", ("gone.com", "parent"): "alive"}
    assert asyncio.run(sweep.run(args, *_fake(answers))) == sweep.EXIT_REVIVED
    assert "`gone.com`" in pathlib.Path(args.report).read_text()


@pytest.mark.parametrize("replies, verdict", [
    ([("NOERROR", True)], "alive"),                                  # FC2 serving www
    ([("NXDOMAIN", True), ("NXDOMAIN", True)], "lame"),              # DNSPod: no zone for it
    ([("REFUSED", False), ("REFUSED", False)], "lame"),              # dnsv2
    ([("NXDOMAIN", False), ("NOERROR", False)], "lame"),             # dns-parking: no authority
    ([("NXDOMAIN", True), None], "unknown"),                         # a server did not answer
    ([], "unknown"),
])
def test_a_referral_counts_only_if_a_named_server_serves_the_zone(replies, verdict):
    sweep = _script("refresh_dead_top_names")
    msgs = [None if r is None else _reply(rcode=r[0], aa=r[1]) for r in replies]
    assert sweep.served_verdict(msgs) == verdict


def test_the_parent_is_asked_over_tcp_without_recursion(monkeypatch):
    import dns.flags

    sweep = _script("refresh_dead_top_names")
    sent = []

    async def tcp(query, where, timeout=None, **kw):
        sent.append((query, where))
        return _reply(rcode="NXDOMAIN")

    async def udp(*a, **kw):
        raise AssertionError("the parent is asked over TCP")

    monkeypatch.setattr(sweep.dns.asyncquery, "tcp", tcp)
    monkeypatch.setattr(sweep.dns.asyncquery, "udp", udp)

    async def zone(name):
        return "com", ["192.0.2.1"]

    at_parent = sweep.make_parent_check(zone_servers=zone)
    assert asyncio.run(at_parent("x.example.com")) == "nxdomain"
    query, where = sent[0]
    assert where == "192.0.2.1" and not query.flags & dns.flags.RD


def test_a_lame_referral_is_dead(monkeypatch):
    import dns.rrset

    sweep = _script("refresh_dead_top_names")
    referral = _reply(authority=[("x.example.com.", 172800, "IN", "NS", "ns1.host.net.")])
    referral.additional = [dns.rrset.from_text("ns1.host.net.", 300, "IN", "A", "192.0.2.53")]

    async def tcp(query, where, timeout=None, **kw):
        return referral

    async def udp_with_fallback(query, where, timeout=None, **kw):
        assert where == "192.0.2.53"
        return _reply(rcode="NXDOMAIN", aa=True), False

    monkeypatch.setattr(sweep.dns.asyncquery, "tcp", tcp)
    monkeypatch.setattr(sweep.dns.asyncquery, "udp_with_fallback", udp_with_fallback)

    async def zone(name):
        return "com", ["192.0.2.1"]

    assert asyncio.run(sweep.make_parent_check(zone_servers=zone)("x.example.com")) == "lame"
