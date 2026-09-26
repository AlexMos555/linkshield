"""build_blockset() must never darken a shared or popular host.

2026-08-18: production /dns-query returned NXDOMAIN for github.com,
www.github.com, api.github.com and raw.githubusercontent.com — every GitHub
subdomain, for everyone using our DNS profile. URLhaus lists 869 malware URLs
hosted ON github.com; the script added the exact host unconditionally
(`out.add(h)`) and only guarded the *registrable promotion*, while the DoH
gateway also matches on the registrable base — so `github.com` in the set
blocked all of GitHub. Also darkened: zapier.app, od.lk, acusense.ae,
adclick.g.doubleclick.net, attach.mail.daum.net, 0zz0.com.

Rules pinned here (see build_blockset docstring):
  * hostnames that are path-shared by everyone (raw.githubusercontent.com,
    drive.google.com, storage.googleapis.com …) are never added;
  * a hostname whose registrable is popular (top-100k, or Tranco-1M via the
    optional rank lookup) is added ONLY if it sits under a shared suffix
    (github.io, blogspot.com, us.org, blob.core.windows.net …) — i.e. it is
    one tenant's site — and even then not when the feed shows many URLs on
    that one host (a shared host, not a tenant);
  * dedicated phishing domains get the exact host AND the registrable.
"""
from __future__ import annotations

import base64
import importlib.util
import logging
import pathlib

import pytest

from api.services import blocklist_retention as retention
from api.services.blocklist_artifact import REDIS_TEXT_KEY, artifact_covers, parse_artifact_v2

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "refresh_dangerous_domains.py"
_spec = importlib.util.spec_from_file_location("refresh_dangerous_domains", _SCRIPT)
rdd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rdd)  # type: ignore[union-attr]

TOP = {"github.com", "githubusercontent.com", "googleapis.com", "google.com", "daum.net",
       "doubleclick.net", "windows.net", "bounceme.net", "us.org", "blogspot.com", "github.io",
       "zapier.app"}
SHARED = {"github.io", "blogspot.com", "us.org", "bounceme.net", "blob.core.windows.net",
          "githubusercontent.com", "googleapis.com"}


def _build(hosts, popular=None):
    return rdd.build_blockset(hosts, TOP, shared_suffixes=SHARED, is_popular=popular)


def test_github_com_is_never_added_even_with_hundreds_of_urls():
    hosts = ["github.com"] * 869 + ["www.github.com", "api.github.com"]
    out = _build(hosts)
    assert "github.com" not in out
    assert "www.github.com" not in out
    assert "api.github.com" not in out


def test_path_shared_hosts_are_never_added():
    for h in ["raw.githubusercontent.com", "gist.githubusercontent.com", "storage.googleapis.com",
              "drive.google.com", "docs.google.com", "sites.google.com", "cdn.discordapp.com",
              "s3.amazonaws.com"]:
        assert h not in _build([h] * 3), h


def test_popular_org_subdomains_are_skipped():
    out = _build(["attach.mail.daum.net", "adclick.g.doubleclick.net"])
    assert out == set()


def test_tenant_site_on_shared_platform_is_blocked_exactly_not_the_platform():
    out = _build(["evil-login.github.io", "secure.bounceme.net", "gwcu.us.org",
                  "mystore.blob.core.windows.net"])
    assert {"evil-login.github.io", "secure.bounceme.net", "gwcu.us.org",
            "mystore.blob.core.windows.net"} <= out
    for platform in ["github.io", "bounceme.net", "us.org", "blob.core.windows.net", "windows.net"]:
        assert platform not in out, platform


def test_shared_platform_apex_itself_is_never_added():
    assert _build(["github.io", "blogspot.com", "us.org"]) == set()


def test_many_urls_on_one_host_under_shared_suffix_means_shared_host_not_tenant():
    # 40 malware URLs on one hostname under githubusercontent.com: that is a
    # shared host (everyone's raw files), not one tenant's site.
    out = _build(["files.githubusercontent.com"] * (rdd.SHARED_URL_THRESHOLD + 5))
    assert "files.githubusercontent.com" not in out
    # …whereas a couple of URLs on a tenant site is the normal phishing shape.
    assert "evil.github.io" in _build(["evil.github.io"] * 2)


def test_dedicated_phishing_domain_blocks_host_and_registrable():
    out = _build(["www.paypal-security.891374.cfd", "login.scotiabano.com"])
    # registrable of www.paypal-security.891374.cfd is 891374.cfd (the
    # brand-looking label is a subdomain) — block host + registrable.
    assert {"www.paypal-security.891374.cfd", "891374.cfd",
            "login.scotiabano.com", "scotiabano.com"} <= out


def test_compound_tld_registrable_is_three_labels_heuristic():
    # No PSL available: the ccTLD heuristic must still refuse to promote com.am
    # (that promotion was LIVE in prod: every Armenian .com.am darkened).
    out = _build(["www.roblox.com.am", "beryl-bet365.com.cn", "roblox.com.ee"])
    assert {"roblox.com.am", "beryl-bet365.com.cn"} <= out
    for suffix in ["com.am", "com.cn", "com.ee"]:
        assert suffix not in out, suffix


def test_psl_registrable_and_never_promote_a_public_suffix():
    psl = {"com", "am", "com.am", "cfd", "io", "github.io", "uk", "co.uk", "*.ck", "ee", "com.ee"}
    out = rdd.build_blockset(["www.roblox.com.am", "evil.github.io", "a.b.co.uk", "x.www.ck", "roblox.com.ee"],
                             TOP, shared_suffixes=SHARED, public_suffixes=psl)
    assert "roblox.com.am" in out and "com.am" not in out
    assert "evil.github.io" in out and "github.io" not in out
    assert "b.co.uk" in out and "co.uk" not in out
    assert "x.www.ck" in out and "www.ck" not in out  # wildcard rule *.ck
    assert "roblox.com.ee" in out and "com.ee" not in out
    # PSL parsing keeps wildcards, drops exceptions and comments.
    assert rdd.parse_psl("// c\n*.ck\n!www.ck\n\nCOM.AM\n") == {"*.ck", "com.am"}


def test_optional_popularity_lookup_guards_tranco_1m_hosts():
    # 0zz0.com is a real file host (Tranco ~1M) that URLhaus lists malware on;
    # with a rank lookup it must not be blocked wholesale.
    def popular(d: str) -> bool:
        return d == "0zz0.com"
    out = _build(["0zz0.com", "www.0zz0.com"], popular=popular)
    assert "0zz0.com" not in out
    assert "www.0zz0.com" not in out


def test_verified_legit_shared_tenant_is_never_blocked():
    """A legit brand page on an org-scoped platform (metamask.github.io — the
    real MetaMask GitHub Pages, which a phisher cannot create because they do
    not own the "metamask" GitHub org) is false-flagged by OpenPhish's crypto
    heuristics. A curated allowlist skips it — the on-device escape hatch is
    not enough, since a MetaMask user hitting "site can't be reached" won't
    know to un-block it. Zero miss cost: only exact verified hosts are listed."""
    out = rdd.build_blockset(["metamask.github.io"] * 3, TOP, shared_suffixes=SHARED)
    assert "metamask.github.io" not in out
    # A brand-plus-tokens lookalike on the same platform is STILL blocked —
    # the allowlist is exact hosts, not brand substrings.
    out2 = rdd.build_blockset(["metamask-wallet-verify.github.io"], TOP, shared_suffixes=SHARED)
    assert "metamask-wallet-verify.github.io" in out2


# ─────────────────────────────────────────────────────────────────
# 2026-09-19: brand-owned domains in the feeds (data/brand_owned_hosts.txt)
#
# walmart.com.br (MarkMonitor DNS, WHOIS "Domain Under Protection", every path
# 302 → www.walmart.com) and americanexpress.io (Amex's tech blog, WHOIS
# American Express, CSC, americanexpress.com's own nameservers) were on every
# phone. Found by scripts/sweep_brand_owned_fps.py.
#
# roblox.com.hr / roblox.ly were REPORTED as Roblox's defensive domains and are
# not: registered 2026-07/08 by a private person on a shared Cloudflare account
# and VPS, `/` bounces to www.roblox.com while /share serves a PHP phishing kit
# (vhost "roblox.et"). They must stay blocked.
# ─────────────────────────────────────────────────────────────────

_PSL_BRANDS = {"com", "br", "com.br", "io", "hr", "com.hr", "ly"}


def test_brand_owned_hosts_are_never_published_but_lookalikes_are():
    out = rdd.build_blockset(["walmart.com.br", "www.walmart.com.br", "walmart-ofertas.com.br",
                              "www.americanexpress.io", "americanexpress-login.io"],
                             TOP, shared_suffixes=SHARED, public_suffixes=_PSL_BRANDS)
    # Neither the feed host nor the registrable promoted from www.<brand> is published…
    for owned in ("walmart.com.br", "www.walmart.com.br", "americanexpress.io", "www.americanexpress.io"):
        assert owned not in out, owned
    # …while a lookalike under the same ccTLD still is: exact hosts, not brand substrings.
    assert {"walmart-ofertas.com.br", "americanexpress-login.io"} <= out


def test_the_roblox_cloakers_are_not_vetoed_and_stay_blocked():
    assert not {"roblox.com.hr", "www.roblox.com.hr", "roblox.ly", "www.roblox.ly"} & rdd.load_brand_owned_hosts()
    out = rdd.build_blockset(["www.roblox.com.hr", "www.roblox.ly"], TOP, shared_suffixes=SHARED,
                             public_suffixes=_PSL_BRANDS)
    assert {"roblox.com.hr", "www.roblox.com.hr", "roblox.ly", "www.roblox.ly"} <= out


def test_brand_owned_list_takes_exact_hostnames_only(tmp_path, caplog):
    listing = tmp_path / "brand_owned_hosts.txt"
    listing.write_text("# comment\nWalmart.COM.br.  # trailing comment\n*.roblox.com.hr\n"
                       "https://americanexpress.io/\n\n", encoding="utf-8")
    assert rdd.load_brand_owned_hosts(str(listing)) == {"walmart.com.br"}
    rejected = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(rejected) == 2 and all("exact hostnames only" in m for m in rejected)


def test_missing_brand_owned_list_warns_and_vetoes_nothing(tmp_path, caplog):
    assert rdd.load_brand_owned_hosts(str(tmp_path / "absent.txt")) == frozenset()
    assert any(r.levelno == logging.WARNING and "brand-owned" in r.getMessage() for r in caplog.records)


def test_a_vetoed_host_still_covered_by_a_published_parent_is_reported(caplog):
    # Vetoing www.<brand> alone does nothing while <brand> is published: the
    # phone blocks every subdomain of a listed name. Say so instead of
    # pretending the veto worked.
    out = rdd.build_blockset(["www.brandsite.xyz"], TOP, shared_suffixes=SHARED,
                             brand_owned=frozenset({"www.brandsite.xyz"}))
    assert "www.brandsite.xyz" not in out and "brandsite.xyz" in out
    assert any(r.levelno == logging.WARNING and "www.brandsite.xyz" in r.getMessage()
               and "brandsite.xyz" in r.getMessage() for r in caplog.records)


def test_ip_literals_are_skipped():
    assert _build(["1.2.3.4", "10.0.0.1"]) == set()


# ─────────────────────────────────────────────────────────────────
# Publish gates — abort and keep the previous set rather than publish junk
# ─────────────────────────────────────────────────────────────────

def test_publish_gate_rejects_too_small_and_too_large():
    ok, why = rdd.publish_gate(set(f"d{i}.example" for i in range(10)), previous=None, popular=set(), shared=set())
    assert not ok and "small" in why
    huge = {f"d{i}.example" for i in range(rdd.MAX_ENTRIES + 1)}
    ok, why = rdd.publish_gate(huge, previous=None, popular=set(), shared=set())
    assert not ok and "large" in why


def test_publish_gate_rejects_popular_or_shared_intersection():
    names = {f"d{i}.example" for i in range(400)} | {"github.com"}
    ok, why = rdd.publish_gate(names, previous=None, popular={"github.com"}, shared=set())
    assert not ok and "github.com" in why
    names = {f"d{i}.example" for i in range(400)} | {"us.org"}
    ok, why = rdd.publish_gate(names, previous=None, popular=set(), shared={"us.org"})
    assert not ok and "us.org" in why


def test_publish_gate_rejects_excessive_churn_unless_forced():
    prev = {f"old{i}.example" for i in range(400)}
    new = {f"new{i}.example" for i in range(400)}
    ok, why = rdd.publish_gate(new, previous=prev, popular=set(), shared=set())
    assert not ok and "churn" in why
    ok, _ = rdd.publish_gate(new, previous=prev, popular=set(), shared=set(), force=True)
    assert ok


def test_publish_gate_accepts_normal_refresh():
    prev = {f"d{i}.example" for i in range(400)}
    new = prev - {"d1.example", "d2.example"} | {"fresh.example"}
    ok, why = rdd.publish_gate(new, previous=prev, popular={"github.com"}, shared={"us.org"})
    assert ok, why


# ─────────────────────────────────────────────────────────────────
# 2026-08-19: live false positives + gate bypasses found by the
# adversarial review of the shipped stack
# ─────────────────────────────────────────────────────────────────

def test_operator_infrastructure_is_never_blocked():
    """media.githubusercontent.com was NXDOMAIN in production: one URLhaus
    entry, and the tenant rule treated GitHub's own media CDN as "one
    tenant's site". There are no tenants under an operator suffix."""
    out = rdd.build_blockset(
        ["media.githubusercontent.com", "release-assets.githubusercontent.com",
         "lh3.googleusercontent.com", "storage.googleapis.com", "x.oaiusercontent.com"],
        TOP, shared_suffixes=SHARED | {"githubusercontent.com", "googleusercontent.com", "googleapis.com"},
    )
    assert out == set()
    # …and the operator suffixes are not tenant suffixes to begin with.
    assert rdd.OPERATOR_SUFFIXES & rdd.default_shared_suffixes() == set()


def test_a_ranked_tenant_site_is_not_blocked():
    """A tenant host people actually use (Tranco-ranked) is not one scammer's
    page; a single feed entry must not darken it."""
    def popular(d: str) -> bool:
        return d in {"docs.example.github.io", "github.io"}
    out = rdd.build_blockset(["docs.example.github.io", "scam.github.io"], TOP,
                             shared_suffixes=SHARED, is_popular=popular)
    assert "docs.example.github.io" not in out
    assert "scam.github.io" in out


def test_trailing_dot_hosts_are_normalised_before_every_guard():
    """'example.com.' kept its dot through build_blockset, the publish gate and
    the SADD, and only lost it in the renderer: the registrable became 'com.'
    (a bare TLD) and 'blogspot.com.' slipped past the shared-apex guard."""
    out = _build(["Evil-Shop.com.", "blogspot.com.", "gwcu.us.org."])
    assert "evil-shop.com" in out
    assert "com" not in out and "com." not in out
    assert "blogspot.com" not in out and "blogspot.com." not in out
    assert "gwcu.us.org" in out
    assert all(n == n.strip().lower().rstrip(".") for n in out)


@pytest.mark.asyncio
async def test_publish_is_refused_when_the_public_suffix_list_is_unavailable(monkeypatch):
    """Without the PSL the fallback heuristic promotes public suffixes
    (pe.kr, blog.br …) into the blocklist — a whole national zone dark on
    every phone. Keeping the previous set is the cheaper mistake."""
    async def _no_psl():
        return None

    monkeypatch.setattr(rdd, "_fetch_psl", _no_psl)

    async def _fetch(url):
        if "urlhaus" in url:
            return "\n".join(f'"{i}","d","https://ojang.pe.kr/x{i}"' for i in range(5))
        return "https://phish.example/a"

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    code = await rdd.refresh("redis://unused", dry_run=False)
    assert code == 4


# ─────────────────────────────────────────────────────────────────
# 2026-09-19: retention — a rolling feed was un-blocking live phishing
#
# Each run rebuilt the set ONLY from what the feeds list right now. OpenPhish's
# free feed is a rolling window of its latest ~300 URLs, so a phishing host
# rotated out of it — and off every phone — while the site was still up:
# of 33 OpenPhish-covered brand-phishing hosts on 2026-09-15, 10 had left the
# list by 2026-09-19 while still answering HTTP 200/403
# (securebankofamerica.vercel.app, open-instagram.vercel.app, …).
# ─────────────────────────────────────────────────────────────────

DAY = 86_400
T0 = 1_790_000_000
WINDOW = retention.DEFAULT_RETAIN_DAYS * DAY
# A stable aggregate (Phishing.Database-shaped): enough names to pass the
# publish gate, present on every run.
BASE = [f"scam{i}.xyz" for i in range(400)]
PSL = {"com", "xyz", "app", "vercel.app", "br", "com.br"}
TENANT_PHISH = "securebankofamerica.vercel.app"
DEDICATED_PHISH = "evil-bank.com"


class _FakePipeline:
    """Queues commands; execute() applies them in order, like MULTI/EXEC."""

    def __init__(self, redis: "_FakeRedis") -> None:
        self._redis = redis
        self._calls: list = []

    def __getattr__(self, name):
        def queue(*args, **kwargs):
            self._calls.append((name, args, kwargs))
            return self
        return queue

    async def execute(self):
        return [await getattr(self._redis, name)(*a, **kw) for name, a, kw in self._calls]


class _FakeRedis:
    """In-memory stand-in for the refresh job's Redis surface: strings, sets,
    hashes, sorted sets, transactional pipelines. Commands named in `fail`
    raise ConnectionError, to simulate a Redis blip on one code path."""

    def __init__(self, fail=()) -> None:
        self.data: dict = {}
        self.ttl: dict = {}
        self.fail = set(fail)

    def _check(self, command: str) -> None:
        if command in self.fail:
            raise ConnectionError(f"simulated {command} failure")

    def pipeline(self, transaction: bool = True) -> _FakePipeline:
        return _FakePipeline(self)

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def delete(self, *keys):
        return sum(self.data.pop(k, None) is not None for k in keys)

    async def exists(self, key):
        return int(key in self.data)

    async def expire(self, key, seconds):
        if key not in self.data:
            return 0
        self.ttl[key] = seconds
        return 1

    async def rename(self, src, dst):
        self.data[dst] = self.data.pop(src)
        return True

    async def sadd(self, key, *members):
        members_set = self.data.setdefault(key, set())
        before = len(members_set)
        members_set.update(members)
        return len(members_set) - before

    async def smembers(self, key):
        return set(self.data.get(key, set()))

    async def scard(self, key):
        return len(self.data.get(key, set()))

    async def sunionstore(self, dest, keys):
        self.data[dest] = set().union(*(self.data.get(k, set()) for k in keys))
        return len(self.data[dest])

    async def hset(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def hmget(self, key, fields):
        return [self.data.get(key, {}).get(f) for f in fields]

    async def zadd(self, key, mapping, nx=False):
        self._check("zadd")
        zset = self.data.setdefault(key, {})
        fresh = {m: s for m, s in mapping.items() if not (nx and m in zset)}
        added = len(set(fresh) - set(zset))
        zset.update(fresh)
        return added

    async def zrange(self, key, start, end, withscores=False):
        self._check("zrange")
        rows = sorted(self.data.get(key, {}).items(), key=lambda kv: (kv[1], kv[0]))
        return rows if withscores else [m for m, _ in rows]

    async def zrem(self, key, *members):
        self._check("zrem")
        zset = self.data.get(key, {})
        removed = sum(zset.pop(m, None) is not None for m in members)
        self._drop_if_empty(key)
        return removed

    async def zremrangebyscore(self, key, low, high):
        self._check("zremrangebyscore")
        zset = self.data.get(key, {})
        doomed = [m for m, s in zset.items() if _score_in(s, low, high)]
        for m in doomed:
            del zset[m]
        self._drop_if_empty(key)
        return len(doomed)

    def _drop_if_empty(self, key) -> None:
        if key in self.data and not self.data[key]:
            del self.data[key]

    async def memory_usage(self, key):
        return None

    async def info(self, section=None):
        return {}

    async def aclose(self):
        return None


def _bound(raw) -> tuple[float, bool]:
    text = str(raw)
    exclusive = text.startswith("(")
    return float(text.lstrip("(")), exclusive


def _score_in(score: float, low, high) -> bool:
    lo, lo_ex = _bound(low)
    hi, hi_ex = _bound(high)
    above = score > lo if lo_ex else score >= lo
    below = score < hi if hi_ex else score <= hi
    return above and below


def _stub_world(monkeypatch, fake, openphish_urls, top=frozenset()) -> None:
    async def _fetch(url):
        if url == rdd.OPENPHISH_FEED:
            return "\n".join(openphish_urls)
        if url == rdd.PHISHING_DATABASE:
            return "\n".join(BASE)
        return ""

    async def _psl():
        return set(PSL)

    async def _verified(_sample):
        return []

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    monkeypatch.setattr(rdd, "_fetch_psl", _psl)
    monkeypatch.setattr(rdd, "_load_top_100k", lambda: set(top))
    monkeypatch.setattr(rdd, "verify_published", _verified)
    monkeypatch.setattr("redis.asyncio.from_url", lambda *_a, **_kw: fake)


async def _run(monkeypatch, fake, openphish_urls, now, dry_run=False, top=frozenset()) -> int:
    _stub_world(monkeypatch, fake, openphish_urls, top)
    return await rdd.refresh("redis://fake", dry_run=dry_run, now=now)


def _published(fake) -> set:
    return fake.data.get(rdd.SET_KEY, set())


def _phone_blocks(fake, name: str) -> bool:
    _, hashes = parse_artifact_v2(base64.b64decode(fake.data[REDIS_TEXT_KEY]))
    return artifact_covers(set(hashes), name)


def _url(host: str) -> str:
    return f"https://{host}/login"


@pytest.mark.asyncio
async def test_host_is_kept_inside_the_window_after_leaving_the_feeds(monkeypatch):
    fake = _FakeRedis()
    assert await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0) == 0
    assert TENANT_PHISH in _published(fake)
    # OpenPhish rotates it out of its rolling window; the site is still up.
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600) == 0
    assert TENANT_PHISH in _published(fake)
    assert await _run(monkeypatch, fake, [], now=T0 + 13 * DAY) == 0
    assert TENANT_PHISH in _published(fake)
    assert _phone_blocks(fake, TENANT_PHISH)
    # Retained names go through the same guards: the tenant host, never the platform.
    assert "vercel.app" not in _published(fake)


@pytest.mark.asyncio
async def test_host_is_dropped_after_the_window(monkeypatch):
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    departed_at = T0 + 6 * 3600
    await _run(monkeypatch, fake, [], now=departed_at)
    assert await _run(monkeypatch, fake, [], now=departed_at + WINDOW + 1) == 0
    assert TENANT_PHISH not in _published(fake)
    assert not _phone_blocks(fake, TENANT_PHISH)


@pytest.mark.asyncio
async def test_pruning_removes_old_members_and_the_key_carries_a_ttl(monkeypatch):
    fake = _FakeRedis()
    fake.data[retention.LAST_SEEN_KEY] = {"ancient-phish.com": float(T0 - 30 * DAY)}
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    assert "ancient-phish.com" not in fake.data.get(retention.LAST_SEEN_KEY, {})
    assert "ancient-phish.com" not in _published(fake)

    departed_at = T0 + 6 * 3600
    await _run(monkeypatch, fake, [], now=departed_at)
    # Only names that LEFT the feeds are stored — not the ~500k still listed.
    assert fake.data[retention.LAST_SEEN_KEY] == {TENANT_PHISH: departed_at}
    assert fake.ttl[retention.LAST_SEEN_KEY] > WINDOW

    await _run(monkeypatch, fake, [], now=departed_at + WINDOW + 1)
    assert retention.LAST_SEEN_KEY not in fake.data


@pytest.mark.asyncio
async def test_retained_host_that_became_popular_is_vetoed(monkeypatch):
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(DEDICATED_PHISH)], now=T0)
    assert DEDICATED_PHISH in _published(fake)
    # The domain changed hands and is now Tranco-ranked: retention must not
    # outvote the popularity guard (the Tranco lookup must see retained names).
    fake.data["tranco:ranks"] = {DEDICATED_PHISH: "4242"}
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600) == 0
    assert DEDICATED_PHISH not in _published(fake)
    # …and the bundled top-100k veto applies to retained names too.
    fake2 = _FakeRedis()
    await _run(monkeypatch, fake2, [_url(DEDICATED_PHISH)], now=T0)
    await _run(monkeypatch, fake2, [], now=T0 + 6 * 3600, top={DEDICATED_PHISH})
    assert DEDICATED_PHISH not in _published(fake2)


@pytest.mark.asyncio
async def test_a_brand_owned_host_published_before_the_veto_is_not_retained(monkeypatch):
    fake = _FakeRedis()
    assert await _run(monkeypatch, fake, [], now=T0) == 0
    # Published by a run that predates the veto list; now it left the feeds,
    # so retention would carry it for 14 days — the veto must still win.
    fake.data[rdd.SET_KEY] = _published(fake) | {"walmart.com.br"}
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600) == 0
    assert "walmart.com.br" in fake.data.get(retention.LAST_SEEN_KEY, {})  # it WAS a retention candidate
    assert "walmart.com.br" not in _published(fake)
    assert not _phone_blocks(fake, "www.walmart.com.br")


@pytest.mark.asyncio
async def test_host_back_in_a_feed_restarts_its_window_when_it_leaves_again(monkeypatch):
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    await _run(monkeypatch, fake, [], now=T0 + 6 * 3600)
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0 + 10 * DAY)
    assert TENANT_PHISH not in fake.data.get(retention.LAST_SEEN_KEY, {})
    await _run(monkeypatch, fake, [], now=T0 + 11 * DAY)
    # The first departure (T0 + 6h) would have expired at ~T0 + 14d.
    await _run(monkeypatch, fake, [], now=T0 + 20 * DAY)
    assert TENANT_PHISH in _published(fake)


@pytest.mark.asyncio
async def test_retention_read_failure_publishes_from_the_feeds_alone(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    fake.fail = {"zrange"}
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600) == 0
    assert TENANT_PHISH not in _published(fake)
    assert "scam1.xyz" in _published(fake)  # the feed-only set WAS published
    assert any(r.levelno == logging.WARNING and "retention" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_retention_write_failure_publishes_from_the_feeds_alone(monkeypatch, caplog):
    """A name we could not record would be re-stamped as 'just departed' on
    every run and never age out — so an unrecorded plan is not published."""
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    fake.fail = {"zremrangebyscore"}
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600) == 0
    assert TENANT_PHISH not in _published(fake)
    assert "scam1.xyz" in _published(fake)
    assert any(r.levelno == logging.WARNING and "retention" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_dry_run_without_redis_works_and_says_retention_is_off(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _stub_world(monkeypatch, _FakeRedis(), [_url(TENANT_PHISH)])
    assert await rdd.refresh(None, dry_run=True, now=T0) == 0
    assert any("retention" in r.getMessage() and "no Redis" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_dry_run_with_redis_reads_retention_but_writes_nothing(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    before = set(_published(fake))
    assert await _run(monkeypatch, fake, [], now=T0 + 6 * 3600, dry_run=True) == 0
    assert retention.LAST_SEEN_KEY not in fake.data
    assert _published(fake) == before
    assert any("[dry-run]" in r.getMessage() and "retention" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_retention_disabled_by_zero_days_publishes_the_feeds_alone(monkeypatch):
    monkeypatch.setenv(retention.RETAIN_DAYS_ENV, "0")
    fake = _FakeRedis()
    await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0)
    await _run(monkeypatch, fake, [], now=T0 + 6 * 3600)
    assert TENANT_PHISH not in _published(fake)
    assert retention.LAST_SEEN_KEY not in fake.data


def test_plan_retention_departures_returns_and_window():
    plan = retention.plan_retention(
        stored={"old.example": float(T0 - 20 * DAY), "recent.example": float(T0 - DAY),
                "back.example": float(T0 - DAY)},
        previous={"gone.example", "still.example", "recent.example", "old.example",
                  rdd.LIST_CANARY},
        present={"still.example", "back.example"},
        now=T0, window_seconds=WINDOW,
    )
    # Newly missing from the feeds: recorded now. Already-recorded names keep
    # their original timestamp (no re-stamping), and the canary is not a feed name.
    assert plan.departed == {"gone.example"}
    assert plan.returned == {"back.example"}
    assert plan.retained == {"gone.example", "recent.example"}
    assert plan.cutoff == T0 - WINDOW


def test_retain_days_env_parsing(caplog):
    assert retention.retain_days_from_env(None) == retention.DEFAULT_RETAIN_DAYS == 14
    assert retention.retain_days_from_env("  ") == 14
    assert retention.retain_days_from_env("30") == 30
    assert retention.retain_days_from_env("0") == 0
    for bad in ("abc", "-1", str(retention.MAX_RETAIN_DAYS + 1), "7.5"):
        assert retention.retain_days_from_env(bad) == 14, bad
    assert any("BLOCKLIST_RETAIN_DAYS" in r.getMessage() for r in caplog.records)


# ── Feed outages must not look like departures (review finding) ──────────
# A feed that fails to download contributes nothing to `present`, so without
# a guard every name it backed would be recorded as "departed" and retained:
# the zset balloons (Phishing.Database alone is ~390k names) and a broken
# feed is masked for the whole window instead of tripping the churn gate.


def _stub_outage(monkeypatch, fake, failing_url, openphish_urls) -> None:
    _stub_world(monkeypatch, fake, openphish_urls)
    healthy = rdd._fetch

    async def _fetch(url):
        if url == failing_url:
            raise ConnectionError("feed down")
        return await healthy(url)

    monkeypatch.setattr(rdd, "_fetch", _fetch)


@pytest.mark.asyncio
async def test_a_failed_feed_does_not_record_its_names_as_departed(monkeypatch, caplog):
    fake = _FakeRedis()
    already = "earlier-phish.example"
    fake.data[retention.LAST_SEEN_KEY] = {already: float(T0 - DAY)}
    assert await _run(monkeypatch, fake, [_url(TENANT_PHISH)], now=T0) == 0

    _stub_outage(monkeypatch, fake, rdd.OPENPHISH_FEED, [])
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0 + 6 * 3600) == 0

    stored = fake.data.get(retention.LAST_SEEN_KEY, {})
    assert TENANT_PHISH not in stored, "an outage must not be recorded as a departure"
    assert already in stored, "names retained before the outage keep their clock"
    assert "not recording departures" in caplog.text


def test_plan_retention_records_nothing_when_told_not_to():
    plan = retention.plan_retention(
        stored={"kept.example": float(T0 - DAY)},
        previous={"gone.example", "kept.example"},
        present=set(), now=T0, window_seconds=WINDOW, record_departures=False,
    )
    assert plan.departed == frozenset()
    assert plan.retained == {"kept.example"}
    assert plan.skipped


def test_plan_retention_refuses_a_departure_spike():
    previous = {f"p{i}.example" for i in range(6)}
    plan = retention.plan_retention(
        stored={"kept.example": float(T0 - DAY)},
        previous=previous | {"kept.example"},
        present=set(), now=T0, window_seconds=WINDOW, max_departures=5,
    )
    # A silently broken parser looks like "everything left at once".
    assert plan.departed == frozenset()
    assert plan.retained == {"kept.example"}
    assert "spike" in plan.skipped


def test_plan_retention_normal_departures_still_recorded_under_the_cap():
    plan = retention.plan_retention(
        stored={}, previous={"a.example", "b.example"}, present={"b.example"},
        now=T0, window_seconds=WINDOW, max_departures=5,
    )
    assert plan.departed == {"a.example"}
    assert not plan.skipped
