"""confirmed_threats: which analyzer verdicts may reach every phone's blocklist.

Only while PUBLISH_CONFIRMED_THREATS is on (a licence decision), only a
DANGEROUS verdict that rests on a Google Safe Browsing phishing/malware
listing, and only the site's own name — a heuristic guess, a noisy source or a
per-recipient host must never become a DNS block on every phone. The
publisher side (guards, expiry) is pinned in test_refresh_dangerous_domains.py.
"""
from __future__ import annotations

import asyncio

import pytest

from api.services import confirmed_threats as ct

NOW = 1_790_000_000.0
GSB = {"safe_browsing_hit": True}


@pytest.fixture
def publishing_on(monkeypatch):
    monkeypatch.setenv(ct.ENABLE_ENV, "1")


def _gsb_types(monkeypatch, *types):
    async def _types(_host):
        return frozenset(types)

    monkeypatch.setattr(ct, "_safe_browsing_types", _types)


def test_safe_browsing_is_the_only_trusted_source():
    # Widening this list puts a new source's verdicts on every phone: it
    # needs its own licence and false-positive review first.
    assert ct.INTEL_SIGNALS == ("safe_browsing_hit",)
    assert ct.should_record("dangerous", GSB)


@pytest.mark.parametrize("signals", [
    {},                                                   # heuristics only
    {"phishtank_hit": True},                              # our held-out benchmark
    {"urlhaus_hit": True},                                # any host that ever had a URL
    {"threatfox_hit": True},                              # wildcard IOC search
    {"malware_bazaar_hit": True},                         # uploader-set tags
    {"feodo_hit": True},                                  # C2 IP addresses
    {"phishstats_hit": True},                             # substring match
    {"spamhaus_hit": True, "surbl_hit": True},            # spam lists
    {"alienvault_pulse_count": 12, "ipqs_phishing": True},
    {"watchtower_matched": True, "favicon_cloned": True},  # lookalike guesses
])
def test_heuristics_and_untrusted_sources_never_qualify(signals):
    assert not ct.should_record("dangerous", signals)


@pytest.mark.parametrize("level", ["caution", "safe"])
def test_an_intel_hit_that_did_not_end_dangerous_does_not_qualify(level):
    # e.g. a Safe Browsing hit on a site our scorer still called caution.
    assert not ct.should_record(level, GSB)


@pytest.mark.parametrize("raw,on", [("1", True), ("true", True), (" ON ", True), ("yes", True),
                                    ("", False), ("0", False), ("false", False), ("off", False)])
def test_publishing_is_off_unless_explicitly_switched_on(raw, on):
    assert ct.enabled({ct.ENABLE_ENV: raw}) is on
    assert ct.enabled({}) is False


@pytest.mark.parametrize("host", [
    "inwardatti-jp-etaxrefund.com",              # a registrable (production GSB catch)
    "www.evil.xyz",
    "paymentsecurelink.vercel.app",              # a tenant on a hosting platform
    "comcast2212.weebly.com",
    "allegro.pl-lokalna-ofeta95430458.sbs",      # one short word above the registrable
    "mts.gipinfosystems.com",
    "x.shop.com.tr",
])
def test_the_sites_own_name_is_recordable(host):
    assert ct.is_recordable_host(host)


@pytest.mark.parametrize("host", [
    "ivan-petrov-mail-ru.evil.xyz",              # a recipient's address in a wildcard label
    "ivanpetrov1984.evil.xyz",                   # digits: an ID or a birth year
    "averyveryverylongname.evil.xyz",            # longer than a plain word
    "login.secure.evil.xyz",                     # two labels deep
    "a8f3c2d9e1.evil.xyz",
])
def test_a_host_that_may_carry_a_person_is_never_recorded(host):
    assert not ct.is_recordable_host(host)


def test_split_by_window():
    entries = {"new.example": NOW - 3600, "old.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - 1}
    assert ct.split(entries, NOW) == ({"new.example"}, {"old.example"})


class _Pipe:
    def __init__(self, r):
        self.r, self.calls = r, []

    def __getattr__(self, name):
        def queue(*a, **kw):
            self.calls.append((name, a, kw))
            return self
        return queue

    async def execute(self):
        for name, a, kw in self.calls:
            await getattr(self.r, name)(*a, **kw)


class _Redis:
    def __init__(self):
        self.z: dict = {}
        self.ttl = None

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def zadd(self, key, mapping):
        self.z.update(mapping)

    async def zremrangebyrank(self, key, start, end):
        rows = sorted(self.z.items(), key=lambda kv: (kv[1], kv[0]))
        stop = len(rows) + end + 1 if end < 0 else end + 1  # Redis ranks are inclusive
        for name, _ in rows[start:max(stop, 0)]:
            del self.z[name]

    async def zremrangebyscore(self, key, low, high):
        cutoff = float(str(high).lstrip("("))
        for name in [n for n, s in self.z.items() if s < cutoff]:
            del self.z[name]

    async def expire(self, key, seconds):
        self.ttl = seconds

    async def zrange(self, key, start, end, withscores=False):
        return sorted(self.z.items(), key=lambda kv: kv[1])


def _redis(monkeypatch) -> _Redis:
    r = _Redis()

    async def _get():
        return r

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return r


@pytest.mark.asyncio
async def test_record_keeps_the_newest_up_to_the_cap_and_sets_a_ttl(monkeypatch):
    monkeypatch.setattr(ct, "CONFIRMED_MAX", 3)
    r = _Redis()
    for i in range(5):
        await ct.record(r, f"h{i}.example", NOW + i)
    assert set(r.z) == {"h2.example", "h3.example", "h4.example"}
    assert r.ttl == ct.KEY_TTL_SECONDS
    # A re-confirmation moves a host to the front of the line.
    await ct.record(r, "h2.example", NOW + 10)
    await ct.record(r, "h5.example", NOW + 11)
    assert set(r.z) == {"h2.example", "h4.example", "h5.example"}


@pytest.mark.asyncio
async def test_every_write_deletes_what_is_past_window_and_grace():
    """The PRIVACY.md promise must not depend on the publisher running: a
    stalled cron used to leave old hosts stored while new ones kept the key
    alive."""
    r = _Redis()
    r.z = {"keep.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - 3600,
           "drop.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - ct.EXPIRED_GRACE_SECONDS - 3600}
    await ct.record(r, "new.example", NOW)
    assert set(r.z) == {"keep.example", "new.example"}


@pytest.mark.asyncio
async def test_nothing_is_recorded_while_publishing_is_off(monkeypatch):
    monkeypatch.delenv(ct.ENABLE_ENV, raising=False)
    r = _redis(monkeypatch)
    _gsb_types(monkeypatch, "SOCIAL_ENGINEERING")
    assert not await ct.record_if_confirmed("evil.example", "dangerous", GSB, now=NOW)
    assert r.z == {}


@pytest.mark.asyncio
async def test_record_if_confirmed_normalises_and_records(monkeypatch, publishing_on):
    r = _redis(monkeypatch)
    _gsb_types(monkeypatch, "SOCIAL_ENGINEERING")
    assert await ct.record_if_confirmed("Login.Evil.Example.", "dangerous", GSB, now=NOW)
    assert r.z == {"login.evil.example": int(NOW)}
    assert not await ct.record_if_confirmed("guess.example", "dangerous", {}, now=NOW)
    assert "guess.example" not in r.z


@pytest.mark.parametrize("types,recorded", [
    (("SOCIAL_ENGINEERING",), True),
    (("MALWARE", "UNWANTED_SOFTWARE"), True),
    (("UNWANTED_SOFTWARE",), False),                 # a bundling download portal
    (("POTENTIALLY_HARMFUL_APPLICATION",), False),
    ((), False),                                     # Safe Browsing unavailable now
])
@pytest.mark.asyncio
async def test_only_a_phishing_or_malware_listing_is_recorded(monkeypatch, publishing_on, types, recorded):
    r = _redis(monkeypatch)
    _gsb_types(monkeypatch, *types)
    assert await ct.record_if_confirmed("download-portal.example", "dangerous", GSB, now=NOW) is recorded
    assert bool(r.z) is recorded


@pytest.mark.asyncio
async def test_a_per_recipient_host_is_never_stored(monkeypatch, publishing_on):
    r = _redis(monkeypatch)
    _gsb_types(monkeypatch, "SOCIAL_ENGINEERING")
    assert not await ct.record_if_confirmed("ivan-petrov-mail-ru.evil.xyz", "dangerous", GSB, now=NOW)
    assert r.z == {}


@pytest.mark.asyncio
async def test_record_if_confirmed_never_raises_and_never_waits_long(monkeypatch, publishing_on):
    _gsb_types(monkeypatch, "SOCIAL_ENGINEERING")

    async def _down():
        raise ConnectionError("redis down")

    monkeypatch.setattr("api.services.cache.get_redis", _down)
    assert not await ct.record_if_confirmed("evil.example", "dangerous", GSB)

    class _Slow(_Redis):
        async def zadd(self, key, mapping):
            await asyncio.sleep(5)

    async def _slow():
        return _Slow()

    monkeypatch.setattr("api.services.cache.get_redis", _slow)
    loop = asyncio.get_running_loop()
    started = loop.time()
    assert not await ct.record_if_confirmed("evil.example", "dangerous", GSB)
    assert loop.time() - started < 1.0


@pytest.mark.asyncio
async def test_the_threat_type_comes_from_the_analyzers_cached_lookup(monkeypatch):
    """No second call to Google: the Safe Browsing client answers from the
    Redis cache the analyzer's lookup just filled."""
    from api.services import safe_browsing as sb

    class _Client:
        async def check(self, domain):
            assert domain == "evil.example"
            return sb.CheckResult(status=sb.CheckStatus.threat, cached=True,
                                  matches=(sb.ThreatMatch(url="http://evil.example/",
                                                          threat_type="SOCIAL_ENGINEERING"),))

    monkeypatch.setattr(sb, "get_client", lambda: _Client())
    assert await ct._safe_browsing_types("evil.example") == {"SOCIAL_ENGINEERING"}


@pytest.mark.asyncio
async def test_prune_forgets_only_what_is_past_window_and_grace():
    r = _Redis()
    r.z = {"keep.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - 3600,
           "drop.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - ct.EXPIRED_GRACE_SECONDS - 3600}
    await ct.prune(r, NOW)
    assert set(r.z) == {"keep.example"}
