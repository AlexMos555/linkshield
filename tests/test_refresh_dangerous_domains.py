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
import json
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


def _stub_world(monkeypatch, fake, openphish_urls, top=frozenset(), extra=None) -> None:
    bodies = {
        rdd.OPENPHISH_FEED: "\n".join(openphish_urls),
        rdd.PHISHING_DATABASE: "\n".join(BASE),
        # A healthy MISP feed with no events — an unparseable body would be an
        # outage, which suppresses departure recording for every other feed.
        rdd.CSIRT_IT_MANIFEST: "{}",
        **(extra or {}),
    }

    async def _fetch(url):
        return bodies.get(url, "")

    async def _psl():
        return set(PSL)

    async def _verified(_sample):
        return []

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    monkeypatch.setattr(rdd, "_fetch_psl", _psl)
    monkeypatch.setattr(rdd, "_load_top_100k", lambda: set(top))
    monkeypatch.setattr(rdd, "verify_published", _verified)
    monkeypatch.setattr("redis.asyncio.from_url", lambda *_a, **_kw: fake)


async def _run(monkeypatch, fake, openphish_urls, now, dry_run=False, top=frozenset(), extra=None) -> int:
    _stub_world(monkeypatch, fake, openphish_urls, top, extra)
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


# ══════════════════════════════════════════════════════════════════════════
# 2026-09-21: four more feeds (Phishunt CC0, TweetFeed CC0, CERT Polska,
# CSIRT Italia TLP:CLEAR). Every sample below is a VERBATIM line from the
# live feed on the day it was wired in — a parser tested against invented
# input only proves the parser agrees with its author.
# ══════════════════════════════════════════════════════════════════════════

# https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv
TWEETFEED_SAMPLE = (
    "2025-09-22 00:00:08,urldna_bot,domain,loginsapo.weebly.com,#scam #phishing,"
    "https://x.com/urldna_bot/status/1969914576637399521\r\n"
    "2025-09-22 00:00:08,urldna_bot,url,https://loginsapo.weebly.com,#scam #phishing,"
    "https://x.com/urldna_bot/status/1969914576637399521\r\n"
    "2025-09-22 00:04:20,skocherhan,ip,91.107.87.85,,"
    "https://x.com/skocherhan/status/1969915633404973540\r\n"
    "2025-09-22 00:04:20,skocherhan,url,http://91.107.87.85,,"
    "https://x.com/skocherhan/status/1969915633404973540\r\n"
    "2025-09-22 00:17:24,fbgwls245,sha256,"
    "879523c832128a94b15d703d6a1611d3c6a7d0b61b9be9dcbcb1ea80c00309bf,#ransomware,"
    "https://x.com/fbgwls245/status/1969918917922410978\r\n"
    "2025-09-22 07:59:45,suyog41,md5,60df3ab3de912449d3889340cc6538d0,#stealer,"
    "https://x.com/suyog41/status/1970035276098466079\r\n"
    "2026-03-04 19:53:07,skocherhan,url,http://mantenimentgencatwebactualització.weebly.com,,"
    "https://x.com/skocherhan/status/2029284020593299462\r\n"
    "2026-03-04 19:53:07,skocherhan,domain,mantenimentgencatwebactualització.weebly.com,,"
    "https://x.com/skocherhan/status/2029284020593299462\r\n"
    "\r\n"
    "2026-09-01 00:00:00,truncated_row,domain\r\n"
)

# Attachment names the reporters post in the domain/url columns.
TWEETFEED_FILENAMES = (
    "2025-09-22 10:11:47,PrakkiSathwik,domain,Officers.pdf.zip,#phishing #APT,"
    "https://x.com/PrakkiSathwik/status/1970068501449810073\n"
    "2025-10-02 18:06:37,skocherhan,domain,Brussels.zip,,"
    "https://x.com/skocherhan/status/1973811876716068970\n"
    "2025-10-02 18:06:38,skocherhan,url,http://documents.zip,,"
    "https://x.com/skocherhan/status/1973811876716068971\n"
)

# https://phishunt.io/feed.txt — one full URL per line, no header, no comments.
PHISHUNT_SAMPLE = (
    "https://uvishnu.paypal-support.antimoney-laundering.org\r\n"
    "https://office365.internal-alerts.com/i/d5b9af0d256f14c03ab8396a78d3687bf\r\n"
    "http://support.m365-microsoft.com/i/ab041e84e499243eca3e98fb328201632\r\n"
    "\r\n"
    "https://rbxmodes.pro\r\n"
)

# https://hole.cert.pl/domains/v2/domains.txt — one host per line, punycode.
CERT_PL_SAMPLE = (
    "\ufeff0-ilxrc-w285.p9bckp.sbs\r\n"
    "xn--agiel-kursawnia-hkd.org\r\n"
    "xn--albilet-b9a.01289523rt.shop\r\n"
    "amberroseline1.wixsite.com\r\n"
    "\r\n"
)

# https://www.csirt.gov.it/feed-misp/<uuid>.json — MISP event, trimmed to the
# attribute shapes that matter. Tag names are verbatim.
CSIRT_EVENT = {
    "Event": {
        "info": "Warning: AsyncRAT IOCs 2026-09-19",
        "Tag": [{"name": 'rsit:malicious-code="malware-distribution"'},
                {"name": "tlp:clear"},
                {"name": 'misp-galaxy:rat="AsyncRAT"'}],
        "Attribute": [
            {"category": "Payload delivery", "type": "sha256",
             "value": "61539d1e98768dcb4843cb39e0c40625c015d8a2fce217beffe369349b6b8f1d"},
            {"category": "Network activity", "type": "domain", "value": "anarchy10.duckdns.org"},
            {"category": "Network activity", "type": "ip-dst", "value": "193.161.193.99"},
            {"category": "Network activity", "type": "hostname", "value": "C2.BiOscolombia.com.co."},
        ],
        "Object": [{"Attribute": [
            {"type": "domain|ip", "value": "evil-loader.example|203.0.113.7"},
            {"type": "url", "value": "http://evil-loader.example/payload"},
        ]}],
    }
}


def test_tweetfeed_parser_keeps_only_the_rows_that_carry_a_name():
    got = list(rdd._hosts_from_tweetfeed(TWEETFEED_SAMPLE))
    # domain + url rows, including the IP-literal url (build_blockset drops it)
    # and the Unicode host, which stays Unicode until _norm_host folds it.
    assert got == [
        "loginsapo.weebly.com",
        "loginsapo.weebly.com",
        "91.107.87.85",
        "mantenimentgencatwebactualització.weebly.com",
        "mantenimentgencatwebactualització.weebly.com",
    ]
    # ip / sha256 / md5 rows, the blank line and the truncated row yield nothing.
    assert not any(h.startswith("8795") or h == "60df3ab3de912449d3889340cc6538d0" for h in got)


def test_tweetfeed_url_rows_lose_the_path_and_the_scheme():
    row = ("2026-01-02 03:04:05,bot,url,https://office365.internal-alerts.com/i/deadbeef,#phishing,"
           "https://x.com/bot/status/1")
    assert list(rdd._hosts_from_tweetfeed(row)) == ["office365.internal-alerts.com"]


def test_tweetfeed_attachment_filenames_are_not_published_as_domains():
    """'documents.zip' is a malware attachment, not a host. .zip is a real TLD,
    so publishing it would block whoever registers documents.zip for real."""
    assert list(rdd._hosts_from_tweetfeed(TWEETFEED_FILENAMES)) == []


def test_phishunt_parser_takes_the_host_not_the_path():
    got = list(rdd._hosts_from_openphish(PHISHUNT_SAMPLE))
    assert got == ["uvishnu.paypal-support.antimoney-laundering.org",
                   "office365.internal-alerts.com",
                   "support.m365-microsoft.com",
                   "rbxmodes.pro"]


def test_cert_polska_parser_reads_one_host_per_line_including_punycode():
    got = list(rdd._hosts_from_domain_list(CERT_PL_SAMPLE))
    assert got == ["\ufeff0-ilxrc-w285.p9bckp.sbs", "xn--agiel-kursawnia-hkd.org",
                   "xn--albilet-b9a.01289523rt.shop", "amberroseline1.wixsite.com"]
    # The BOM is not whitespace, so it survives the parser — _norm_host is the
    # single place that has to make every consumer agree on the wire form.
    assert rdd._norm_host(got[0]) == "0-ilxrc-w285.p9bckp.sbs"


def test_misp_event_yields_names_and_nothing_else():
    got = list(rdd._hosts_from_misp_event(CSIRT_EVENT["Event"]))
    assert got == ["anarchy10.duckdns.org", "c2.bioscolombia.com.co",
                   "evil-loader.example"]  # domain|ip keeps the name half


@pytest.mark.parametrize("tags,expected", [
    ([{"name": "tlp:clear"}], True),
    ([{"name": "TLP:WHITE"}], True),
    ([{"name": 'misp-galaxy:rat="AsyncRAT"'}, {"name": "tlp:clear"}], True),
    ([{"name": "tlp:green"}], False),
    ([{"name": "tlp:amber+strict"}], False),
    ([{"name": "tlp:clear"}, {"name": "tlp:amber"}], False),  # mixed = not ours
    ([{"name": 'misp-galaxy:rat="AsyncRAT"'}], False),        # unmarked = not ours
    ([], False),
])
def test_tlp_marking_decides_whether_a_misp_event_is_ours_to_ship(tags, expected):
    """The redistribution grant for these feeds IS the TLP marking, so an
    unmarked or restricted event must not reach the artifact."""
    assert rdd._is_tlp_open(tags) is expected


@pytest.mark.asyncio
async def test_misp_feed_reads_newest_tlp_open_events_and_skips_the_rest(monkeypatch):
    manifest = {
        "aaa": {"date": "2026-09-20", "Tag": [{"name": "tlp:clear"}]},
        "bbb": {"date": "2026-09-19", "Tag": [{"name": "tlp:green"}]},   # not ours
        "ccc": {"date": "2026-09-18", "Tag": [{"name": "tlp:clear"}]},
        "ddd": {"date": "2026-09-17", "Tag": [{"name": "tlp:clear"}]},   # unreadable
    }
    bodies = {
        rdd.CSIRT_IT_MANIFEST: json.dumps(manifest),
        "https://www.csirt.gov.it/feed-misp/aaa.json": json.dumps(CSIRT_EVENT),
        "https://www.csirt.gov.it/feed-misp/ccc.json": json.dumps(
            {"Event": {"Tag": [{"name": "tlp:amber"}],  # manifest lied — event wins
                       "Attribute": [{"type": "domain", "value": "secret.example"}]}}),
        "https://www.csirt.gov.it/feed-misp/ddd.json": "<html>502</html>",
    }
    asked: list[str] = []

    async def _fetch(url):
        asked.append(url)
        return bodies[url]

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    monkeypatch.setattr(rdd, "MISP_EVENT_PAUSE", 0)
    got = await rdd._fetch_misp_feed(rdd.CSIRT_IT_MANIFEST)

    assert got == ["anarchy10.duckdns.org", "c2.bioscolombia.com.co", "evil-loader.example"]
    assert "https://www.csirt.gov.it/feed-misp/bbb.json" not in asked, "tlp:green was fetched"
    assert "secret.example" not in got, "an event marked amber must not be republished"


@pytest.mark.asyncio
async def test_misp_feed_caps_how_many_events_one_run_fetches(monkeypatch):
    manifest = {f"e{i:03d}": {"date": f"2026-09-{i % 28 + 1:02d}", "Tag": [{"name": "tlp:clear"}]}
                for i in range(500)}

    async def _fetch(url):
        if url == rdd.CSIRT_IT_MANIFEST:
            return json.dumps(manifest)
        return json.dumps({"Event": {"Tag": [{"name": "tlp:clear"}], "Attribute": []}})

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    monkeypatch.setattr(rdd, "MISP_EVENT_PAUSE", 0)
    calls = []
    real = rdd._fetch

    async def _counting(url):
        calls.append(url)
        return await real(url)

    monkeypatch.setattr(rdd, "_fetch", _counting)
    await rdd._fetch_misp_feed(rdd.CSIRT_IT_MANIFEST)
    assert len(calls) == rdd.MISP_MAX_EVENTS + 1  # + the manifest itself


@pytest.mark.asyncio
async def test_a_misp_manifest_that_is_not_an_object_raises(monkeypatch):
    """The caller turns this into 'feed down', which stops retention reading
    the feed's absence as every one of its names having left."""
    async def _fetch(_url):
        return "[]"

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    with pytest.raises(ValueError):
        await rdd._fetch_misp_feed(rdd.CSIRT_IT_MANIFEST)


# ── IDN: the feeds disagree about the wire form ──────────────────────────


@pytest.mark.parametrize("raw,wire", [
    ("mantenimentgencatwebactualització.weebly.com", "xn--mantenimentgencatwebactualitzaci-med.weebly.com"),
    ("автозаим.рф", "xn--80aafugyk5a.xn--p1ai"),
    ("sapzq.keró.hu", "sapzq.xn--ker-ina.hu"),
    ("XN--80AAFUGYK5A.xn--p1ai", "xn--80aafugyk5a.xn--p1ai"),  # already encoded
    ("example.com.", "example.com"),
    ("\ufeffexample.com", "example.com"),
])
def test_idn_hosts_are_folded_to_the_wire_form_every_guard_uses(raw, wire):
    """A resolver only ever asks for the xn-- form. is_hostname() is an ASCII
    regex, so before this the Unicode names TweetFeed ships were dropped in
    silence — the phone got no hash for the name it would actually query."""
    assert rdd._norm_host(raw) == wire
    assert rdd.is_hostname(rdd._norm_host(raw))


def test_an_idn_that_cannot_be_encoded_is_dropped_not_half_encoded():
    assert rdd._norm_host("​​.​") == ""


def test_an_idn_phishing_domain_survives_the_whole_build():
    out = rdd.build_blockset(["мвд-россия.рф"], TOP, public_suffixes={"com", "xn--p1ai"},
                             brand_owned=frozenset())
    assert out == {"xn----ctbgrqpnja5l.xn--p1ai"}


# ── Exact-host-only feeds ────────────────────────────────────────────────


def test_exact_only_hosts_never_promote_their_platform_apex():
    """CERT Polska's API spec: listing a.example.com must block a.example.com
    and b.a.example.com but NOT example.com. turbo.site, webnode.ru and com.nl
    are in its list only because one tenant on them is a scam."""
    psl = {"site", "com", "nl"}
    out = rdd.build_blockset(["townmoney.turbo.site", "actfinancial.com.nl"], TOP,
                             public_suffixes=psl, brand_owned=frozenset(),
                             exact_only={"townmoney.turbo.site", "actfinancial.com.nl"})
    assert out == {"townmoney.turbo.site", "actfinancial.com.nl"}
    assert "turbo.site" not in out and "com.nl" not in out


def test_the_same_host_from_a_promoting_feed_still_promotes():
    psl = {"site", "com", "nl"}
    out = rdd.build_blockset(["townmoney.turbo.site"], TOP, public_suffixes=psl,
                             brand_owned=frozenset(), exact_only=frozenset())
    assert out == {"townmoney.turbo.site", "turbo.site"}


def test_an_exact_only_host_still_meets_every_other_guard():
    """Exact-only narrows what we publish; it never widens it."""
    psl = {"com", "app", "vercel.app"}
    out = rdd.build_blockset(["github.com", "raw.githubusercontent.com", "evil.vercel.app"],
                             {"github.com", "vercel.app"}, public_suffixes=psl,
                             brand_owned=frozenset(),
                             exact_only={"github.com", "raw.githubusercontent.com", "evil.vercel.app"})
    assert out == {"evil.vercel.app"}


def test_present_names_does_not_claim_a_registrable_for_an_exact_only_host():
    """Otherwise a platform apex one tenant put in the feed would look 'still
    present' to retention and never age out."""
    psl = {"site", "com"}
    assert rdd.present_names(["townmoney.turbo.site"], psl) == {"townmoney.turbo.site", "turbo.site"}
    assert rdd.present_names(["townmoney.turbo.site"], psl,
                             exact_only={"townmoney.turbo.site"}) == {"townmoney.turbo.site"}


# ── End to end through refresh() ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_each_new_feed_reaches_the_published_set(monkeypatch):
    fake = _FakeRedis()
    extra = {
        rdd.PHISHUNT_FEED: "https://office365.internal-alerts.com/i/deadbeef",
        rdd.TWEETFEED_YEAR: ("2026-09-20 10:00:00,urldna_bot,domain,tweetfeed-phish.com,#phishing,"
                             "https://x.com/urldna_bot/status/1"),
        rdd.CERT_PL_DOMAINS: "certpl-phish.com\namberroseline1.wixsite.com",
        rdd.CSIRT_IT_MANIFEST: json.dumps({"aaa": {"date": "2026-09-20", "Tag": [{"name": "tlp:clear"}]}}),
        "https://www.csirt.gov.it/feed-misp/aaa.json": json.dumps(CSIRT_EVENT),
    }
    assert await _run(monkeypatch, fake, [], now=T0, extra=extra) == 0
    published = _published(fake)
    assert "office365.internal-alerts.com" in published      # Phishunt
    assert "tweetfeed-phish.com" in published                # TweetFeed
    assert "certpl-phish.com" in published                   # CERT Polska
    assert "anarchy10.duckdns.org" in published              # CSIRT Italia
    assert _phone_blocks(fake, "anarchy10.duckdns.org")


@pytest.mark.asyncio
async def test_cert_polska_tenant_sites_never_darken_the_platform(monkeypatch):
    fake = _FakeRedis()
    extra = {rdd.CERT_PL_DOMAINS: "amberroseline1.wixsite.com"}
    assert await _run(monkeypatch, fake, [], now=T0, extra=extra) == 0
    assert "amberroseline1.wixsite.com" in _published(fake)
    assert "wixsite.com" not in _published(fake)
    assert not _phone_blocks(fake, "someone-elses-site.wixsite.com")


@pytest.mark.asyncio
async def test_a_retained_exact_only_host_does_not_promote_later(monkeypatch):
    """A retained name is one NO feed still lists, so nothing vouches for its
    registrable. Without this, a CERT Polska tenant host would quietly darken
    its platform apex on the run after it left the feed."""
    fake = _FakeRedis()
    extra = {rdd.CERT_PL_DOMAINS: "shop-tenant.turbo.site"}
    monkeypatch.setattr(rdd, "PSL_URL", rdd.PSL_URL)
    await _run(monkeypatch, fake, [], now=T0, extra=extra)
    assert "shop-tenant.turbo.site" in _published(fake)
    await _run(monkeypatch, fake, [], now=T0 + 6 * 3600)  # CERT Polska drops it
    assert "shop-tenant.turbo.site" in _published(fake), "retention should still carry it"
    assert "turbo.site" not in _published(fake)


@pytest.mark.parametrize("failing", ["PHISHUNT_FEED", "TWEETFEED_YEAR", "CERT_PL_DOMAINS",
                                     "CSIRT_IT_MANIFEST"])
@pytest.mark.asyncio
async def test_a_new_feed_that_fails_to_download_does_not_break_the_publish(monkeypatch, caplog,
                                                                           failing):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    extra = {rdd.PHISHUNT_FEED: "https://phishunt-phish.com",
             rdd.CERT_PL_DOMAINS: "certpl-phish.com"}
    _stub_world(monkeypatch, fake, [], frozenset(), extra)
    healthy = rdd._fetch

    async def _fetch(url):
        if url == getattr(rdd, failing):
            raise ConnectionError("feed down")
        return await healthy(url)

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0) == 0
    assert "scam1.xyz" in _published(fake), "the healthy feeds still published"
    assert "fetch failed" in caplog.text
    # …and the outage guard fires, so retention does not read the missing
    # feed's names as having left.
    assert "not recording departures" in caplog.text


@pytest.mark.asyncio
async def test_a_feed_that_starts_with_a_byte_order_mark_does_not_lose_its_first_entry(monkeypatch):
    """A BOM decodes to a character, not nothing. Glued to 'https://' it makes
    urlparse() find no host at all, so a URL feed silently drops line 1."""
    class _Resp:
        text = "﻿https://first-phish.example/login\nhttps://second-phish.example\n"

        def raise_for_status(self):
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def get(self, _url):
            return _Resp()

    monkeypatch.setattr(rdd.httpx, "AsyncClient", lambda *_a, **_kw: _Client())
    text = await rdd._fetch("https://example.invalid/feed.txt")
    assert list(rdd._hosts_from_openphish(text)) == ["first-phish.example", "second-phish.example"]


@pytest.mark.asyncio
async def test_artifact_out_writes_the_exact_bytes_a_phone_would_download(monkeypatch, tmp_path):
    """The coverage benchmark scores a FILE. Without this the only artifact you
    could measure was whatever production already published."""
    fake = _FakeRedis()
    _stub_world(monkeypatch, fake, [_url(TENANT_PHISH)])
    out = tmp_path / "list.bin"
    assert await rdd.refresh("redis://fake", dry_run=True, now=T0, artifact_out=str(out)) == 0
    header, hashes = parse_artifact_v2(out.read_bytes())
    assert header["count"] == len(hashes)
    assert artifact_covers(set(hashes), TENANT_PHISH)
