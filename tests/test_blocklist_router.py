"""GET /api/v1/blocklist/dns — the artifact the Android shield syncs.

The phone decides blocks locally on the FIRST lookup from this list; the
list is written by scripts/refresh_dangerous_domains.py into Redis
(`dangerous_domains:mobile:v1` + `:meta`) in the same transaction as the DoH
gateway's set. The router only serves bytes + validators — no per-request
computation, so it can never be the slow part.
"""
from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from api.services.blocklist_artifact import render_artifact_v2

# The artifact is binary (packed 48-bit hashes) and lives base64 in Redis.
BLOB = render_artifact_v2({"phish.example", "scotiabano.com"}, generated=1755530000)
ENCODED = base64.b64encode(BLOB).decode()
SHA = hashlib.sha256(BLOB).hexdigest()
COUNT = 3  # two names + the injected list canary


class _FakeRedis:
    def __init__(self, text=ENCODED, meta=None):
        self.text = text
        self.meta = meta if meta is not None else {
            "version": "1755530000", "sha256": SHA, "count": str(COUNT),
            "generated_at": "1755530000", "format": "v2",
        }
        self.calls = 0

    async def get(self, key):
        return self.text if key == "dangerous_domains:mobile:v1" else None

    async def hgetall(self, key):
        return self.meta if key == "dangerous_domains:mobile:v1:meta" else {}

    async def incr(self, k):
        self.calls += 1
        return 1

    async def expire(self, k, s):
        return True

    async def ttl(self, k):
        return 3600

    async def eval(self, *a, **kw):
        return 1

    async def evalsha(self, *a, **kw):
        return 1


@pytest.fixture
def client(monkeypatch):
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis()

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    return TestClient(app), fake


def test_serves_binary_with_validators(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/octet-stream")
    assert r.content == BLOB
    assert r.headers["etag"] == f'"{SHA}"'
    assert r.headers["x-cleanway-blocklist-version"] == "1755530000"
    assert r.headers["x-cleanway-blocklist-count"] == str(COUNT)
    assert "max-age=1800" in r.headers["cache-control"]


def test_served_artifact_parses_and_matches_like_the_phone(client):
    from api.services.blocklist_artifact import artifact_covers, parse_artifact_v2
    c, _ = client
    blob = c.get("/api/v1/blocklist/dns").content
    header, hashes = parse_artifact_v2(blob)
    assert header["version"] == "v2" and header["count"] == COUNT
    hs = set(hashes)
    assert artifact_covers(hs, "phish.example")
    assert artifact_covers(hs, "login.phish.example")
    assert not artifact_covers(hs, "example")
    assert not artifact_covers(hs, "nothing-here.test")


def test_if_none_match_returns_304(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns", headers={"If-None-Match": f'"{SHA}"'})
    assert r.status_code == 304
    assert r.headers["etag"] == f'"{SHA}"'
    assert r.content == b""


def test_weak_if_none_match_from_gzipping_edge_returns_304(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns", headers={"If-None-Match": f'W/"{SHA}"'})
    assert r.status_code == 304


def test_missing_artifact_is_503_with_retry_after(monkeypatch):
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis(text=None, meta={})

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    r = TestClient(app).get("/api/v1/blocklist/dns")
    assert r.status_code == 503
    assert r.headers["retry-after"] == "600"


def test_sha_mismatch_between_meta_and_body_is_503(monkeypatch):
    """A half-written or tampered artifact must never be served — the phone
    verifies sha256(text)==ETag and would reject it anyway; fail loudly here."""
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis(meta={"version": "1", "sha256": "0" * 64, "count": "3", "format": "v2"})

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    r = TestClient(app).get("/api/v1/blocklist/dns")
    assert r.status_code == 503


def test_health_reports_blocklist_age(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("blocklist_version") == "1755530000"
    assert isinstance(body.get("blocklist_age_s"), int)


def test_artifact_format_helper():
    """The publisher's format — one place that knows magic, header and packing."""
    from api.services.blocklist_artifact import (
        HASH_BYTES, LIST_CANARY, MAGIC, name_hash, parse_artifact_v2, parse_header, render_artifact_v2,
    )
    blob = render_artifact_v2({"b.example", "a.example"}, generated=1755530000)
    assert blob.startswith(MAGIC)
    nl = blob.index(b"\n", len(MAGIC))
    header = blob[len(MAGIC):nl + 1].decode()
    assert header == "# cleanway-dns-blocklist v2 generated=1755530000 count=3 status=ok\n"
    assert parse_header(header) == {"version": "v2", "generated": 1755530000, "count": 3, "status": "ok"}
    body = blob[nl + 1:]
    assert len(body) == 3 * HASH_BYTES          # canary always injected
    _, hashes = parse_artifact_v2(blob)
    assert hashes == sorted(hashes)             # sorted: the phone binary-searches
    assert name_hash(LIST_CANARY) in hashes
    revoked = render_artifact_v2(set(), generated=5, revoked=True)
    assert revoked == MAGIC + b"# cleanway-dns-blocklist v2 generated=5 count=0 status=revoked\n"


@pytest.mark.parametrize("mutate", [
    lambda b: b[1:],                       # bad magic
    lambda b: b[:-1],                      # truncated body
    lambda b: b.replace(b"count=3", b"count=9"),
    lambda b: b[:b.index(b"\n") + 1] + b"\xff" * 18,  # unsorted / wrong bytes
])
def test_malformed_artifacts_are_rejected(mutate):
    """The phone rejects a bad artifact whole; the server-side parser is the
    same contract, so both ends agree on what "malformed" means."""
    from api.services.blocklist_artifact import parse_artifact_v2, render_artifact_v2
    blob = render_artifact_v2({"a.example", "b.example"}, generated=1)
    with pytest.raises(Exception):
        parse_artifact_v2(mutate(blob))


# ─────────────────────────────────────────────────────────────────
# Deltas: 6 KB instead of 2.5 MB, and provably the same result
# ─────────────────────────────────────────────────────────────────

def test_delta_round_trip_lands_exactly_on_the_published_artifact():
    from api.services.blocklist_artifact import (
        apply_delta, parse_artifact_v2, parse_delta, render_artifact_v2, render_delta, sha256_bytes,
    )
    old_blob = render_artifact_v2({"a.example", "b.example", "gone.example"}, generated=100)
    new_blob = render_artifact_v2({"a.example", "b.example", "fresh.example"}, generated=200)
    _, old_h = parse_artifact_v2(old_blob)
    _, new_h = parse_artifact_v2(new_blob)

    delta = render_delta(old_h, new_h, from_gen=100, to_gen=200, target_sha=sha256_bytes(new_blob))
    header, added, removed = parse_delta(delta)
    assert header["from"] == 100 and header["to"] == 200
    assert (header["added"], header["removed"]) == (1, 1)
    assert apply_delta(old_h, added, removed) == new_h
    # …and the target sha is the published artifact's, which is what the
    # phone verifies after merging before it trusts a delta.
    assert header["sha256"] == sha256_bytes(new_blob)

    # The size claim, at a realistic scale: 5,000 names with 20 changed.
    big_old = {f"d{i}.example" for i in range(5_000)}
    big_new = (big_old - {f"d{i}.example" for i in range(10)}) | {f"n{i}.example" for i in range(10)}
    _, bo = parse_artifact_v2(render_artifact_v2(big_old, generated=1))
    nb = render_artifact_v2(big_new, generated=2)
    _, bn = parse_artifact_v2(nb)
    big_delta = render_delta(bo, bn, from_gen=1, to_gen=2, target_sha=sha256_bytes(nb))
    assert len(big_delta) * 50 < len(nb)


@pytest.mark.parametrize("mutate", [
    lambda b: b[1:],
    lambda b: b[:-1],
    lambda b: b.replace(b"added=1", b"added=5"),
    lambda b: b.replace(b"sha256=", b"sha256x"),
])
def test_malformed_deltas_are_rejected(mutate):
    from api.services.blocklist_artifact import parse_delta, render_delta
    d = render_delta([1, 2, 3], [2, 3, 4], from_gen=1, to_gen=2, target_sha="0" * 64)
    with pytest.raises(Exception):
        parse_delta(mutate(d))


def test_route_serves_a_delta_when_the_client_names_a_version_it_has(monkeypatch):
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    from api.services.blocklist_artifact import (
        DELTA_MAGIC, delta_key, parse_artifact_v2, render_artifact_v2, render_delta, sha256_bytes,
    )

    old_blob = render_artifact_v2({"a.example"}, generated=100)
    _, old_h = parse_artifact_v2(old_blob)
    _, new_h = parse_artifact_v2(BLOB)
    delta = render_delta(old_h, new_h, from_gen=100, to_gen=1755530000, target_sha=SHA)

    class _R(_FakeRedis):
        async def get(self, key):
            if key == delta_key(100):
                return base64.b64encode(delta).decode()
            return await super().get(key)

    fake = _R()

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    c = TestClient(app)

    r = c.get("/api/v1/blocklist/dns", params={"from": 100})
    assert r.status_code == 200
    assert r.content.startswith(DELTA_MAGIC)
    assert r.headers["x-cleanway-blocklist-delta"] == "1"
    # (the size win is asserted at realistic scale in the round-trip test;
    # at three-hash toy scale the header dominates)

    # No delta for that version → the full artifact, so a phone always has a
    # way forward instead of being stuck on an old list.
    r2 = c.get("/api/v1/blocklist/dns", params={"from": 999})
    assert r2.status_code == 200
    assert r2.content == BLOB
    assert "x-cleanway-blocklist-delta" not in r2.headers


def test_no_per_ip_rate_limit_survives_a_cgnat_burst(client):
    """The real first users are behind Tele2 CGNAT — thousands of phones on one
    IPv4. The blocklist GET must NOT 429 them: a signed public static file has
    nothing to protect per-IP, and a 429 leaves a fresh phone with an empty
    list = unprotected. Hammer it from one IP and require all 200/304."""
    c, _ = client
    for _ in range(120):
        r = c.get("/api/v1/blocklist/dns", headers={"x-forwarded-for": "10.11.12.13"})
        assert r.status_code in (200, 304), r.status_code
