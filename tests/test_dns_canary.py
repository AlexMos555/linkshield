"""The guard that was missing on 2026-08-18 must fail when it should.

A canary that only ever passes is worse than none: it turns "we are watching"
into a claim nobody checked. These tests drive the three failure modes the
incident (and its predecessor) actually produced.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import pathlib
import re
import sys
import time

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
    def __init__(self, blob: bytes, headers):
        super().__init__(blob)
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install(monkeypatch, *, rcodes, artifact_text, etag=None, count_hdr=None):
    """Stub the two network calls: DoH lookups and the artifact fetch."""
    monkeypatch.setattr(canary, "doh", lambda base, name, timeout=10.0: (rcodes.get(name, 0), 1))
    blob = artifact_text
    sha = hashlib.sha256(blob).hexdigest()
    nl = blob.index(b"\n", len(MAGIC))
    entries = len(blob[nl + 1:]) // HASH_BYTES
    headers = {
        "ETag": f'"{etag or sha}"',
        "X-Cleanway-Blocklist-Count": str(count_hdr if count_hdr is not None else entries),
    }

    def _urlopen(req, timeout=30):
        return _FakeResponse(blob, headers)

    monkeypatch.setattr(canary.urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(canary, "tranco_sample", lambda n: [])


def _run(monkeypatch, capsys, **kw):
    _install(monkeypatch, **kw)
    monkeypatch.setattr("sys.argv", ["dns_canary.py", "--sample", "0"])
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
    old = _artifact(["phish.example"], generated=int(time.time()) - 9 * 3600)
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
