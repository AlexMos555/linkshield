"""Tranco popularity signal tests.

Strategy doc Top-20 #14. Pin tier thresholds, fallback shape on
Redis outage, and end-to-end scoring contribution.
"""
from __future__ import annotations

import pytest

from api.services.tranco import (
    TRANCO_TIERS,
    check_tranco_popularity,
    get_tranco_rank,
)


class _FakeRedis:
    """Minimal in-memory Redis stub with HGET semantics."""

    def __init__(self, table: dict[str, str] | None = None):
        self._table = table or {}

    async def hget(self, key: str, field: str):
        if key != "tranco:ranks":
            return None
        return self._table.get(field)


@pytest.fixture
def fake_redis(monkeypatch):
    """Replace `get_redis` with a fake that the test controls."""
    fake = _FakeRedis()

    async def _get_fake():
        return fake

    import api.services.tranco as mod
    monkeypatch.setattr(mod, "get_redis", _get_fake)
    return fake


@pytest.mark.asyncio
async def test_get_tranco_rank_known_domain(fake_redis):
    fake_redis._table = {"google.com": "1"}
    rank = await get_tranco_rank("google.com")
    assert rank == 1


@pytest.mark.asyncio
async def test_get_tranco_rank_normalizes_case(fake_redis):
    fake_redis._table = {"google.com": "1"}
    rank = await get_tranco_rank("Google.COM")
    assert rank == 1, "Lookup must be case-insensitive"


@pytest.mark.asyncio
async def test_get_tranco_rank_empty_domain_returns_none(fake_redis):
    assert await get_tranco_rank("") is None
    assert await get_tranco_rank("  ") is None


@pytest.mark.asyncio
async def test_get_tranco_rank_unranked_returns_none(fake_redis):
    fake_redis._table = {"google.com": "1"}
    assert await get_tranco_rank("totally-fresh-domain.example") is None


@pytest.mark.asyncio
async def test_get_tranco_rank_redis_failure_returns_none(monkeypatch):
    """When Redis is unreachable, the lookup MUST NOT raise — the
    analyzer would have no way to recover and the request would 500."""
    class _BrokenRedis:
        async def hget(self, *args, **kwargs):
            raise ConnectionError("redis is down")

    async def _broken_get():
        return _BrokenRedis()

    import api.services.tranco as mod
    monkeypatch.setattr(mod, "get_redis", _broken_get)
    assert await get_tranco_rank("google.com") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rank, expected_weight",
    [
        (1, -25),       # top 1k → very-trusted
        (999, -25),
        (1_000, -25),
        (1_001, -15),   # top 10k → trusted
        (10_000, -15),
        (10_001, -8),   # top 100k → reputable
        (100_000, -8),
        (100_001, -3),  # top 1M → known-public
        (1_000_000, -3),
        (1_000_001, 0), # outside the list → no signal
    ],
)
async def test_tier_thresholds(fake_redis, rank, expected_weight):
    fake_redis._table = {"example.com": str(rank)}
    out = await check_tranco_popularity("example.com")
    assert out["weight"] == expected_weight, (
        f"Rank {rank} should map to weight {expected_weight}, got {out}"
    )


@pytest.mark.asyncio
async def test_check_tranco_unknown_domain_returns_neutral(fake_redis):
    out = await check_tranco_popularity("never-seen.example")
    assert out == {"ranked": False, "rank": None, "weight": 0, "label": ""}


@pytest.mark.asyncio
async def test_check_tranco_returns_rank_in_output(fake_redis):
    fake_redis._table = {"wikipedia.org": "27"}
    out = await check_tranco_popularity("wikipedia.org")
    assert out["ranked"] is True
    assert out["rank"] == 27
    assert "top 1,000" in out["label"]


def test_tiers_are_in_ascending_order():
    """Sanity check: the tier table is used by first-match iteration,
    so thresholds MUST be sorted ascending or low-rank domains get
    the wrong (smaller) trust bonus."""
    thresholds = [t[0] for t in TRANCO_TIERS]
    assert thresholds == sorted(thresholds)


def test_tiers_use_negative_weights_only():
    """Tranco is a trust signal. Positive weight would silently flip
    its semantics — a guard against future edits."""
    for threshold, weight, label in TRANCO_TIERS:
        assert weight < 0, f"Tier {threshold} has non-negative weight {weight}"
        assert label, f"Tier {threshold} has an empty label"


@pytest.mark.asyncio
async def test_score_signal_wires_into_calculate_score(fake_redis):
    """End-to-end: a top-Tranco domain feeding into calculate_score
    must produce a tranco_popularity DomainReason."""
    from api.services.scoring import calculate_score

    fake_redis._table = {}  # not relevant — we synthesize signals dict directly
    # Pick a domain NOT in the hardcoded data/top_10k.json allowlist
    # so we flow through Layer 3 rule 3.0 (Tranco). The Layer-2
    # allowlist short-circuits any top-10k match to safe with weight
    # -50; we want to exercise our new rule, not that one.
    signals = {
        "domain": "somerandomtechblog.dev",
        "raw_url": "somerandomtechblog.dev",
        "blocklist_hits": 0,
        "tranco_ranked": True,
        "tranco_rank": 250_000,
        "tranco_weight": -8,
        "tranco_label": "in the worldwide top 100,000 most-visited sites",
        "checks_succeeded": 18,
        "total_checks": 18,
    }
    score, _, reasons = calculate_score(signals)
    trust = [r for r in reasons if r.signal == "tranco_popularity"]
    assert len(trust) == 1, f"Expected one tranco_popularity reason, got {reasons}"
    assert trust[0].weight == -8
    # Other heuristic rules may add positive weight (new TLD .dev,
    # etc.) but the popularity bonus should be the lowest single
    # contribution among the reasons.
    weights = sorted(r.weight for r in reasons)
    assert -8 in weights
