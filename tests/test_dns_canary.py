"""The guard that was missing on 2026-08-18 must fail when it should.

A canary that only ever passes is worse than none: it turns "we are watching"
into a claim nobody checked. These tests drive the three failure modes the
incident (and its predecessor) actually produced.

The opposite failure is a canary that cries wolf: measured 2026-09-02, 11 of
100 runs failed and every one was noise (a freshness threshold equal to the
publisher's cadence; a random Tranco sample full of adult/pirate names the
list legitimately blocks). The tests at the bottom pin those fixes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import pathlib
import re
import struct
import sys
import time
import urllib.error

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_SCRIPT = ROOT / "scripts" / "dns_canary.py"
_spec = importlib.util.spec_from_file_location("dns_canary", _SCRIPT)
canary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(canary)  # type: ignore[union-attr]


from api.services.blocklist_artifact import (  # noqa: E402
    HASH_BYTES, MAGIC, name_hash, render_artifact_v2,
)


def _artifact(names, generated=None, count=None) -> bytes:
    """v2 blob; `count` overrides the header so a mismatch can be tested."""
    gen = int(time.time()) if generated is None else generated
    blob = render_artifact_v2(set(names), generated=gen)
    if count is not None:
        nl = blob.index(b"\n", len(MAGIC))
        header = blob[len(MAGIC):nl + 1].decode()
        bad = re.sub(r"count=\d+", f"count={count}", header)
        blob = MAGIC + bad.encode() + blob[nl + 1:]
    return blob


class _FakeResponse(io.BytesIO):
    def __init__(self, blob: bytes, headers, status: int = 200):
        super().__init__(blob)
        self.headers = headers
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


HEALTH_OK = json.dumps({
    "status": "ok",
    "components": {"redis": {"ok": True}, "supabase": {"ok": True, "status": 401}},
}).encode()
HEALTH_DEGRADED = json.dumps({
    "status": "degraded",
    "components": {"redis": {"ok": False, "error": "ConnectionError"},
                   "supabase": {"ok": True, "status": 401}},
}).encode()


def _http(url: str, status: int, body: bytes):
    """What urllib does for a plain GET: a response for 2xx, HTTPError otherwise."""
    if status >= 400:
        raise urllib.error.HTTPError(url, status, "err", None, io.BytesIO(body))
    return _FakeResponse(body, {}, status=status)


UPSTREAM_SOA = "ns-cloud-a1.googledomains.com"  # a real zone's SOA, not ours


def _gateway_answer(rcode: int, soa=None):
    """What our gateway sends: its own NXDOMAIN carries the blocked.cleanway.ai
    SOA; anything else is a forwarded upstream answer."""
    if rcode == 3:
        return canary.DnsAnswer(3, 0, soa or canary.BLOCK_SOA_MNAME)
    return canary.DnsAnswer(rcode, 1 if rcode == 0 else 0, None)


def _install(monkeypatch, *, rcodes, artifact_text, etag=None, count_hdr=None,
             health=(200, HEALTH_OK), landing=(200, b"<html>"), requests=None,
             soa=None, public=None, live_feed=(200, b"")):
    """Stub every network call: DoH lookups (our gateway, and the public
    resolver the live probe asks), the artifact fetch, the live-probe feed,
    /health/deep and the landing page. `soa` overrides the SOA of a gateway
    NXDOMAIN per name; `public` maps name -> DnsAnswer from the public
    resolver. `requests` (a list) collects every urllib Request."""
    soa = soa or {}
    public = public or {}

    def _doh(base, name, timeout=10.0):
        if base == canary.PUBLIC_DOH_BASE:
            return public.get(name, canary.DnsAnswer(3, 0, UPSTREAM_SOA))
        return _gateway_answer(rcodes.get(name, 0), soa.get(name))

    monkeypatch.setattr(canary, "doh", _doh)
    blob = artifact_text
    sha = hashlib.sha256(blob).hexdigest()
    nl = blob.index(b"\n", len(MAGIC))
    entries = len(blob[nl + 1:]) // HASH_BYTES
    headers = {
        "ETag": f'"{etag or sha}"',
        "X-Cleanway-Blocklist-Count": str(count_hdr if count_hdr is not None else entries),
    }

    def _urlopen(req, timeout=30):
        if requests is not None:
            requests.append(req)
        url = req.full_url
        if url.endswith("/api/v1/blocklist/dns"):
            return _FakeResponse(blob, headers)
        if url.endswith("/health/deep"):
            return _http(url, *health)
        if url.endswith("/ru/android"):
            return _http(url, *landing)
        if url == canary.DEFAULT_LIVE_SOURCE:
            return _http(url, *live_feed)
        raise AssertionError(f"canary probed an unexpected URL: {url}")

    monkeypatch.setattr(canary.urllib.request, "urlopen", _urlopen)


def _run(monkeypatch, capsys, argv=(), **kw):
    _install(monkeypatch, **kw)
    monkeypatch.setattr("sys.argv", ["dns_canary.py", *argv])
    code = canary.main()
    return code, capsys.readouterr().out


HEALTHY = _artifact(["phish.example", "evil.example"])  # canary auto-injected


def test_healthy_surface_passes(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY)
    assert code == 0, out
    assert "DNS canary OK" in out


def test_a_popular_name_blocked_fails_loudly(monkeypatch, capsys):
    """The actual 2026-08-18 incident: github.com -> NXDOMAIN."""
    code, out = _run(monkeypatch, capsys,
                     rcodes={"github.com": 3, "list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY)
    assert code == 1
    assert "BLOCKED A POPULAR NAME: github.com" in out


def test_dead_blocklist_fails(monkeypatch, capsys):
    """The other failure mode: the set is empty/ignored and nothing is blocked
    (that state once lasted months unnoticed)."""
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 0}, artifact_text=HEALTHY)
    assert code == 1
    assert "LISTED NAME NOT BLOCKED" in out


def test_stale_artifact_fails(monkeypatch, capsys):
    old = _artifact(["phish.example"], generated=int(time.time()) - 14 * 3600)
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=old)
    assert code == 1
    assert "is the cron dead" in out


def test_artifact_not_matching_its_etag_fails(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY, etag="0" * 64)
    assert code == 1
    assert "does not match its ETag" in out


def test_count_mismatch_fails(monkeypatch, capsys):
    bad = _artifact(["phish.example"], count=99)
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=bad)
    assert code == 1
    assert "count mismatch" in out or "does not parse" in out


def test_missing_list_canary_fails(monkeypatch, capsys):
    """Without the canary a phone cannot prove its list is live. (The renderer
    always injects it, so this builds the blob by hand.)"""
    good = _artifact(["phish.example"])
    nl = good.index(b"\n", len(MAGIC))
    body = good[nl + 1:]
    canary_h = name_hash("list-canary.cleanway.ai").to_bytes(HASH_BYTES, "big")
    stripped = b"".join(body[i:i + HASH_BYTES] for i in range(0, len(body), HASH_BYTES)
                        if body[i:i + HASH_BYTES] != canary_h)
    header = good[len(MAGIC):nl + 1].decode()
    header = re.sub(r"count=\d+", f"count={len(stripped) // HASH_BYTES}", header)
    blob = MAGIC + header.encode() + stripped
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=blob)
    assert code == 1
    assert "missing its list canary" in out


def test_wire_query_ids_are_random_so_no_cache_can_answer():
    """A fixed transaction id would make the URL cacheable at the edge, and a
    cached answer proves nothing about the current blocklist."""
    ids = {canary.wire_query("example.com")[:2] for _ in range(50)}
    assert len(ids) > 40
    q = canary.wire_query("a.b.example")
    assert q[12:] == b"\x01a\x01b\x07example\x00\x00\x01\x00\x01"


# ── de-noising (measured 2026-09-02: 11/100 failures, all noise) ──

CURATED = [
    "gosuslugi.ru", "sberbank.ru", "tinkoff.ru", "vk.com", "yandex.ru", "mail.ru",
    "ozon.ru", "wildberries.ru", "google.com", "apple.com", "microsoft.com",
    "github.com", "cloudflare.com", "wikipedia.org",
]
PUBLISHER_CADENCE_S = 6 * 3600     # refresh-dangerous-domains.yml: cron '23 */6 * * *'
PHONE_STALE_AFTER_S = 48 * 3600    # BlockList.kt STALE_AFTER_MS


def test_freshness_threshold_clears_cron_drift_but_not_phone_tolerance():
    """6h == the publisher's own cadence, so ordinary GitHub cron drift tripped
    the canary 4 times in 100 runs while the publisher was 60/60 green."""
    assert canary.MAX_ARTIFACT_AGE_S == 13 * 3600
    assert canary.MAX_ARTIFACT_AGE_S >= 2 * PUBLISHER_CADENCE_S
    assert canary.MAX_ARTIFACT_AGE_S < PHONE_STALE_AFTER_S


def test_artifact_inside_cron_drift_window_passes(monkeypatch, capsys):
    """The exact noise case: a 7h-old artifact is one late cron, not an outage."""
    drifted = _artifact(["phish.example"], generated=int(time.time()) - 7 * 3600)
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=drifted)
    assert code == 0, out


def test_random_tranco_sample_is_gone():
    """7/100 failures were 'BLOCKED A POPULAR NAME' on adult/pirate/phishy
    Tranco names the list is right to block. Popularity is not innocence."""
    assert not hasattr(canary, "tranco_sample")


def test_must_resolve_list_lives_in_data_and_carries_the_curated_names():
    assert canary.MUST_RESOLVE_PATH == ROOT / "data" / "canary_must_resolve.txt"
    names = canary.load_must_resolve(canary.MUST_RESOLVE_PATH)
    assert names == CURATED


def test_load_must_resolve_ignores_comments_blank_lines_and_case(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("# header\n\nGosuslugi.RU  # inline\n  vk.com.\n\nvk.com\n")
    assert canary.load_must_resolve(f) == ["gosuslugi.ru", "vk.com"]


def test_empty_must_resolve_file_fails_loudly(monkeypatch, capsys, tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("# nothing but comments\n")
    monkeypatch.setattr(canary, "MUST_RESOLVE_PATH", f)
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY)
    assert code == 1
    assert "MUST-RESOLVE LIST BROKEN" in out and "empty" in out


def test_unreadable_must_resolve_file_fails_loudly(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(canary, "MUST_RESOLVE_PATH", tmp_path / "missing.txt")
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY)
    assert code == 1
    assert "MUST-RESOLVE LIST BROKEN" in out and "unreadable" in out


def test_curated_name_blocked_fails_loudly(monkeypatch, capsys):
    """The list is RU-first: gosuslugi.ru dark is the incident we now watch for."""
    code, out = _run(monkeypatch, capsys,
                     rcodes={"gosuslugi.ru": 3, "list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY)
    assert code == 1
    assert "BLOCKED A POPULAR NAME: gosuslugi.ru" in out


def test_publisher_guards_are_still_checked(monkeypatch, capsys):
    """NEVER_BLOCK_GUARDS (cleanway.ai, raw.githubusercontent.com, ...) stay in
    the resolve set alongside the curated file — nothing was dropped."""
    seen: list[str] = []
    _install(monkeypatch, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY)
    monkeypatch.setattr(canary, "doh",
                        lambda base, name, timeout=10.0: seen.append(name) or canary.DnsAnswer(0, 1, None))
    monkeypatch.setattr("sys.argv", ["dns_canary.py"])
    canary.main()
    for guard in canary.NEVER_BLOCK_GUARDS:
        assert guard in seen
    for name in CURATED:
        assert name in seen
    assert len(seen) == len(set(seen)), "a name was probed twice"


def test_health_deep_degraded_fails(monkeypatch, capsys):
    """/health is always-200; /health/deep is the honest probe (503 + degraded)."""
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY, health=(503, HEALTH_DEGRADED))
    assert code == 1
    assert "/health/deep" in out and "503" in out and "redis" in out


def test_health_deep_200_without_status_ok_fails(monkeypatch, capsys):
    body = json.dumps({"status": "degraded", "components": {}}).encode()
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY, health=(200, body))
    assert code == 1
    assert "/health/deep" in out and "degraded" in out


def test_health_deep_non_json_fails(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY, health=(200, b"<html>maintenance</html>"))
    assert code == 1
    assert "/health/deep" in out and "not JSON" in out


def test_landing_not_200_fails(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY, landing=(404, b"not found"))
    assert code == 1
    assert "LANDING DOWN" in out and "/ru/android" in out and "404" in out


def test_probes_use_get_never_head_and_hit_both_new_urls(monkeypatch, capsys):
    """Every API path answers HEAD with 405, so a HEAD probe would page on a
    healthy service. Default bases: api.cleanway.ai for the API, cleanway.ai
    for the landing page."""
    seen: list = []
    code, _ = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                   artifact_text=HEALTHY, requests=seen)
    assert code == 0
    assert all(r.get_method() == "GET" for r in seen)
    urls = [r.full_url for r in seen]
    assert "https://api.cleanway.ai/health/deep" in urls
    assert "https://cleanway.ai/ru/android" in urls


def test_landing_base_is_configurable_separately_from_api_base(monkeypatch, capsys):
    seen: list = []
    code, _ = _run(monkeypatch, capsys, argv=["--base", "https://api.staging.test/",
                                              "--landing-base", "https://staging.test/"],
                   rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY, requests=seen)
    assert code == 0
    urls = [r.full_url for r in seen]
    assert "https://api.staging.test/health/deep" in urls
    assert "https://staging.test/ru/android" in urls


def test_landing_base_env_var_is_honoured(monkeypatch, capsys):
    monkeypatch.setenv("CANARY_LANDING_BASE", "https://env.test")
    seen: list = []
    _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3}, artifact_text=HEALTHY, requests=seen)
    assert "https://env.test/ru/android" in [r.full_url for r in seen]


# ── 2026-09-26: the block probe must be able to fail ──────────────────────
# list-canary.cleanway.ai exists nowhere in public DNS. With the blocklist
# dead the gateway forwards the query and upstream says NXDOMAIN too — the
# old probe passed either way. Only our own SOA marker proves the block.


def test_upstream_nxdomain_for_the_canary_is_not_proof_of_blocking(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"list-canary.cleanway.ai": 3},
                     soa={"list-canary.cleanway.ai": UPSTREAM_SOA}, artifact_text=HEALTHY)
    assert code == 1
    assert "LISTED NAME NOT BLOCKED BY US: list-canary.cleanway.ai" in out


def test_a_gateway_that_resolves_nothing_fails(monkeypatch, capsys):
    """SERVFAIL for everything is not NXDOMAIN — and it is every phone on the
    DNS profile offline."""
    everything_servfail = {n: 2 for n in canary.must_resolve_names(canary.MUST_RESOLVE_PATH)}
    code, out = _run(monkeypatch, capsys, rcodes={**everything_servfail, "list-canary.cleanway.ai": 3},
                     artifact_text=HEALTHY)
    assert code == 1
    assert "GATEWAY RESOLVES ALMOST NOTHING" in out


def test_the_soa_marker_matches_what_the_gateway_really_sends():
    from api.services import doh_gateway
    assert canary.BLOCK_SOA_MNAME == doh_gateway._SOA_MNAME
    assert canary.PUBLIC_DOH_BASE + "/dns-query" == doh_gateway.CLOUDFLARE_DOH_URL
    ours = canary.parse_response(doh_gateway.make_nxdomain_response(canary.wire_query("evil.example")))
    assert ours == canary.DnsAnswer(3, 0, canary.BLOCK_SOA_MNAME)


def test_parse_response_follows_compressed_names_like_real_upstream_answers():
    # NXDOMAIN for x.cleanway.ai as a public resolver sends it: the SOA owner
    # and MNAME use compression pointers into the question.
    question = b"\x01x\x08cleanway\x02ai\x00\x00\x01\x00\x01"
    header = b"\x12\x34\x81\x83" + struct.pack("!HHHH", 1, 0, 1, 0)
    mname = b"\x03ns1\x0bdnsprovider\x03net\x00"
    rdata = mname + b"\xc0\x0e" + struct.pack("!IIIII", 1, 2, 3, 4, 5)   # RNAME -> cleanway.ai
    soa = b"\xc0\x0e" + struct.pack("!HHIH", 6, 1, 300, len(rdata)) + rdata
    answer = canary.parse_response(header + question + soa)
    assert answer == canary.DnsAnswer(3, 0, "ns1.dnsprovider.net")


def test_parse_response_refuses_a_pointer_loop():
    looped = b"\x00\x00\x81\x83" + struct.pack("!HHHH", 1, 0, 0, 0) + b"\xc0\x0c"
    with pytest.raises(ValueError):
        canary.parse_response(looped)


# The live probe: a real listed host that public DNS resolves.

LIVE_LISTED = "live-phish.example"
FEED = (f"https://{LIVE_LISTED}/login\nhttps://dead-listed.example/x\n"
        "https://not-on-our-list.example/\n").encode()
LISTED = _artifact([LIVE_LISTED, "dead-listed.example"])
RESOLVES = canary.DnsAnswer(0, 1, None)


def test_a_live_listed_host_that_our_gateway_blocks_passes(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, artifact_text=LISTED, live_feed=(200, FEED),
                     rcodes={"list-canary.cleanway.ai": 3, LIVE_LISTED: 3},
                     public={LIVE_LISTED: RESOLVES})
    assert code == 0, out
    assert "live-block-check: 1 listed names that resolve publicly (2 listed in the source, 1 resolve" in out


def test_a_live_listed_host_our_gateway_lets_through_fails(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, artifact_text=LISTED, live_feed=(200, FEED),
                     rcodes={"list-canary.cleanway.ai": 3, LIVE_LISTED: 0},
                     public={LIVE_LISTED: RESOLVES})
    assert code == 1
    assert f"LISTED NAME NOT BLOCKED: {LIVE_LISTED}" in out


@pytest.mark.parametrize("live_feed,note", [
    ((200, b""), "no host of the source is on our list"),
    ((503, b"down"), "source answered HTTP 503"),
])
def test_no_usable_live_host_is_a_note_not_a_failure(monkeypatch, capsys, live_feed, note):
    code, out = _run(monkeypatch, capsys, artifact_text=LISTED, live_feed=live_feed,
                     rcodes={"list-canary.cleanway.ai": 3})
    assert code == 0, out
    assert note in out


def test_the_live_probe_can_be_switched_off(monkeypatch, capsys):
    seen: list = []
    code, out = _run(monkeypatch, capsys, argv=["--live-source", ""], artifact_text=LISTED,
                     rcodes={"list-canary.cleanway.ai": 3}, requests=seen)
    assert code == 0
    assert "(disabled)" in out
    assert canary.DEFAULT_LIVE_SOURCE not in [r.full_url for r in seen]


def test_the_live_probe_asks_public_dns_a_bounded_number_of_times(monkeypatch):
    asked: list = []
    monkeypatch.setattr(canary, "doh", lambda base, name, timeout=10.0: asked.append(name) or
                        canary.DnsAnswer(3, 0, UPSTREAM_SOA))
    many = [f"h{i}.example" for i in range(50)]
    assert canary.pick_live_probes(many) == []
    assert len(asked) == canary.MAX_LIVE_LOOKUPS
