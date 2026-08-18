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
import time

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "dns_canary.py"
_spec = importlib.util.spec_from_file_location("dns_canary", _SCRIPT)
canary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(canary)  # type: ignore[union-attr]


def _artifact(names, generated=None, count=None):
    gen = int(time.time()) if generated is None else generated
    body = list(names)
    n = len(body) if count is None else count
    return f"# cleanway-dns-blocklist v1 generated={gen} count={n} status=ok\n" + "\n".join(body) + "\n"


class _FakeResponse(io.BytesIO):
    def __init__(self, text, headers):
        super().__init__(text.encode())
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _install(monkeypatch, *, rcodes, artifact_text, etag=None, count_hdr=None):
    """Stub the two network calls: DoH lookups and the artifact fetch."""
    monkeypatch.setattr(canary, "doh", lambda base, name, timeout=10.0: (rcodes.get(name, 0), 1))
    sha = hashlib.sha256(artifact_text.encode()).hexdigest()
    headers = {
        "ETag": f'"{etag or sha}"',
        "X-Cleanway-Blocklist-Count": str(count_hdr if count_hdr is not None
                                          else len([l for l in artifact_text.split("\n")[1:] if l.strip()])),
    }

    def _urlopen(req, timeout=20):
        return _FakeResponse(artifact_text, headers)

    monkeypatch.setattr(canary.urllib.request, "urlopen", _urlopen)
    monkeypatch.setattr(canary, "tranco_sample", lambda n: [])


def _run(monkeypatch, capsys, **kw):
    _install(monkeypatch, **kw)
    monkeypatch.setattr("sys.argv", ["dns_canary.py", "--sample", "0"])
    code = canary.main()
    return code, capsys.readouterr().out


HEALTHY = _artifact(["list-canary.cleanway.ai", "phish.example", "evil.example"])


def test_healthy_surface_passes(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"phish.example": 3, "evil.example": 3}, artifact_text=HEALTHY)
    assert code == 0, out
    assert "DNS canary OK" in out


def test_a_popular_name_blocked_fails_loudly(monkeypatch, capsys):
    """The actual 2026-08-18 incident: github.com -> NXDOMAIN."""
    code, out = _run(monkeypatch, capsys,
                     rcodes={"github.com": 3, "phish.example": 3, "evil.example": 3},
                     artifact_text=HEALTHY)
    assert code == 1
    assert "BLOCKED A POPULAR NAME: github.com" in out


def test_dead_blocklist_fails(monkeypatch, capsys):
    """The other failure mode: the set is empty/ignored and nothing is blocked
    (that state once lasted months unnoticed)."""
    code, out = _run(monkeypatch, capsys, rcodes={}, artifact_text=HEALTHY)
    assert code == 1
    assert "LISTED NAME NOT BLOCKED" in out


def test_stale_artifact_fails(monkeypatch, capsys):
    old = _artifact(["list-canary.cleanway.ai", "phish.example"], generated=int(time.time()) - 9 * 3600)
    code, out = _run(monkeypatch, capsys, rcodes={"phish.example": 3}, artifact_text=old)
    assert code == 1
    assert "is the cron dead" in out


def test_artifact_not_matching_its_etag_fails(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, rcodes={"phish.example": 3, "evil.example": 3},
                     artifact_text=HEALTHY, etag="0" * 64)
    assert code == 1
    assert "does not match its ETag" in out


def test_count_mismatch_fails(monkeypatch, capsys):
    bad = _artifact(["list-canary.cleanway.ai", "phish.example"], count=99)
    code, out = _run(monkeypatch, capsys, rcodes={"phish.example": 3}, artifact_text=bad)
    assert code == 1
    assert "count mismatch" in out


def test_missing_list_canary_fails(monkeypatch, capsys):
    """Without the canary line a phone cannot prove its list is live."""
    body = _artifact(["phish.example", "evil.example"])
    code, out = _run(monkeypatch, capsys, rcodes={"phish.example": 3, "evil.example": 3}, artifact_text=body)
    assert code == 1
    assert "missing its list canary" in out


def test_wire_query_ids_are_random_so_no_cache_can_answer():
    """A fixed transaction id would make the URL cacheable at the edge, and a
    cached answer proves nothing about the current blocklist."""
    ids = {canary.wire_query("example.com")[:2] for _ in range(50)}
    assert len(ids) > 40
    q = canary.wire_query("a.b.example")
    assert q[12:] == b"\x01a\x01b\x07example\x00\x00\x01\x00\x01"
