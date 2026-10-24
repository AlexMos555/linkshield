"""/health/doh `stats.recent`: the latency of the last few minutes, next to
the lifetime histogram.

2026-10-24: the uptime monitor's `dns_latency` alert judged `stats.p95_ms_le`,
which counts every query since the worker process started. Its reaction
scaled with uptime: on a day-old worker every query had to be slow for over
an hour before that p95 moved, a slowdown of a fifth of the queries took ~8 h,
and after a two-hour slowdown it stayed high for ~14 h, so the "back to
normal" mail waited for a deploy. `recent` holds only the last
RECENT_SLOTS x RECENT_SLOT_S seconds; the lifetime fields are unchanged (the
capacity runbook reads them).
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from api.services import doh_metrics
from tests.doh_helpers import use_redis

FAST, SLOW = 0.003, 0.4  # the 5 ms and 500 ms buckets
WINDOW = doh_metrics.RECENT_SLOTS * doh_metrics.RECENT_SLOT_S


class Clock:
    def __init__(self, t: float = 1_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _metrics(t: float = 1_000_000.0):
    clock = Clock(t)
    return doh_metrics.Metrics(clock=clock), clock


def _traffic(m, clock, seconds: int, latency: float, per_second: int = 1) -> None:
    for _ in range(seconds):
        for _ in range(per_second):
            m.observe(latency)
        clock.t += 1


def test_a_long_lived_worker_that_turns_slow_shows_it_in_recent_at_once():
    m, clock = _metrics()
    _traffic(m, clock, 12 * 3600, FAST)
    _traffic(m, clock, 60, SLOW)
    snap = m.snapshot()
    assert snap["p95_ms_le"] == 5.0  # 60 slow of 43,260: the lifetime p95 has not moved
    assert snap["recent"]["p95_ms_le"] == 500.0


def test_a_worker_that_recovers_shows_it_one_window_later():
    m, clock = _metrics()
    _traffic(m, clock, 3600, FAST)
    _traffic(m, clock, 2 * 3600, SLOW)
    _traffic(m, clock, WINDOW, FAST)
    snap = m.snapshot()
    assert snap["p95_ms_le"] == 500.0  # lifetime: still latched
    recent = snap["recent"]
    assert (recent["p50_ms_le"], recent["p95_ms_le"], recent["p99_ms_le"]) == (5.0, 5.0, 5.0)
    assert recent["over_ms"] == {"5000": 0}


def test_recent_covers_the_current_slot_and_the_ones_before_it():
    m, clock = _metrics(0.0)
    m.observe(SLOW)
    clock.t = WINDOW - 1
    assert m.snapshot()["recent"]["queries"] == 1
    clock.t = WINDOW
    assert m.snapshot()["recent"]["queries"] == 0


def test_an_idle_worker_forgets_old_queries_without_new_ones():
    m, clock = _metrics()
    _traffic(m, clock, 60, SLOW)
    clock.t += 10 * 60
    recent = m.snapshot()["recent"]
    assert recent["queries"] == 0
    assert (recent["p50_ms_le"], recent["p95_ms_le"], recent["p99_ms_le"]) == (None, None, None)
    assert m.snapshot()["p95_ms_le"] == 500.0


def test_a_reused_slot_starts_empty():
    m, clock = _metrics(0.0)
    for _ in range(50):
        m.observe(SLOW)
    clock.t = WINDOW + 1  # the same position in the ring, one lap later
    m.observe(FAST)
    recent = m.snapshot()["recent"]
    assert recent["queries"] == 1
    assert recent["p95_ms_le"] == 5.0


def test_recent_quantiles_are_bucket_bounds_like_the_lifetime_ones():
    m, _clock = _metrics()
    for _ in range(98):
        m.observe(0.0015)
    m.observe(0.3)
    m.observe(7.0)
    snap = m.snapshot()
    recent = snap["recent"]
    assert recent["queries"] == 100
    assert (recent["p50_ms_le"], recent["p95_ms_le"], recent["p99_ms_le"]) == (2.0, 2.0, 500.0)
    assert recent["over_ms"] == {"5000": 1}
    for key in ("p50_ms_le", "p95_ms_le", "p99_ms_le", "over_ms"):
        assert recent[key] == snap[key]


def test_health_doh_reports_recent_next_to_the_lifetime_fields(monkeypatch):
    """Valid JSON past the last bucket too: null, never infinity."""
    use_redis(monkeypatch, None)
    for _ in range(5):
        doh_metrics.METRICS.observe(9.0)
    doh_metrics.METRICS.observe(0.003)
    from api.main import app
    resp = TestClient(app).get("/health/doh")
    assert resp.status_code == 200
    stats = resp.json()["stats"]
    assert {"since", "counts", "p50_ms_le", "p95_ms_le", "p99_ms_le", "over_ms"} <= set(stats)
    assert stats["recent"] == {
        "window_s": WINDOW, "queries": 6,
        "p50_ms_le": None, "p95_ms_le": None, "p99_ms_le": None, "over_ms": {"5000": 5},
    }
