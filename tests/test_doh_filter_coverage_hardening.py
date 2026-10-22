"""The in-process blocklist under hostile or broken artifacts.

The filter must refuse any artifact the phone would refuse (and keep the list
it already has), cope with a Redis that has nothing published, refresh itself
in the background, and report its state without leaking names.
"""
from __future__ import annotations

import asyncio

import pytest

from api.services import doh_filter
from api.services.blocklist_artifact import HASH_BYTES, MAGIC, sha256_bytes
from tests.doh_helpers import ArtifactRedis, use_redis

LISTED = {"phish.example"}


def _header(count: int, status: str = "ok") -> bytes:
    return f"# cleanway-dns-blocklist v2 generated=1700000000 count={count} status={status}\n".encode()


def _hashes(*values: int) -> bytes:
    return b"".join(v.to_bytes(HASH_BYTES, "big") for v in values)


# ── parse_filter: refuse what the phone refuses ─────────────────────

@pytest.mark.parametrize(
    "blob",
    [
        pytest.param(b"CWBL1\n" + _header(0), id="bad-magic"),
        pytest.param(MAGIC + b"no newline after the header", id="header-not-terminated"),
        pytest.param(MAGIC + b"# something else entirely\n", id="bad-header"),
        pytest.param(MAGIC + _header(1) + b"\x00" * (HASH_BYTES - 1), id="truncated-body"),
        pytest.param(MAGIC + _header(3) + _hashes(1, 2), id="count-mismatch"),
        pytest.param(MAGIC + _header(2) + _hashes(5, 1), id="unsorted-hashes"),
    ],
)
def test_parse_filter_refuses_a_malformed_artifact(blob):
    with pytest.raises(ValueError):
        doh_filter.parse_filter(blob, sha256_bytes(blob))


def test_parse_filter_accepts_a_minimal_valid_artifact():
    blob = MAGIC + _header(2) + _hashes(1, 7)
    f = doh_filter.parse_filter(blob, sha256_bytes(blob))
    assert f.count == 2 and not f.revoked and f.generated == 1700000000


# ── refresh_once against a broken publication ───────────────────────

@pytest.mark.asyncio
async def test_no_published_meta_means_no_list_and_a_reason(monkeypatch):
    fake = ArtifactRedis(LISTED)
    fake.meta = {}
    use_redis(monkeypatch, fake)
    assert await doh_filter.HOLDER.refresh_once() is False
    assert doh_filter.HOLDER.current is None
    assert doh_filter.HOLDER.last_error == "no_artifact"
    assert fake.calls["get"] == 0, "no body download without a sha to verify it against"


@pytest.mark.asyncio
async def test_meta_without_a_body_means_no_list(monkeypatch):
    fake = ArtifactRedis(LISTED)

    async def _missing(_key):
        return None

    fake.get = _missing
    use_redis(monkeypatch, fake)
    assert await doh_filter.HOLDER.refresh_once() is False
    assert doh_filter.HOLDER.current is None
    assert doh_filter.HOLDER.last_error == "no_artifact"


@pytest.mark.asyncio
async def test_bytes_keys_and_values_from_redis_are_understood(monkeypatch):
    fake = ArtifactRedis(LISTED)
    fake.meta = {k.encode(): v.encode() for k, v in fake.meta.items()}
    use_redis(monkeypatch, fake)
    assert await doh_filter.HOLDER.refresh_once() is True
    assert doh_filter.HOLDER.current.listed(["phish.example"]) == ["phish.example"]


@pytest.mark.asyncio
async def test_a_self_consistent_but_invalid_artifact_keeps_the_previous_list(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    assert await doh_filter.HOLDER.refresh_once() is True
    good = doh_filter.HOLDER.current
    # A publisher bug: unsorted body, but its sha256 matches. The phone
    # refuses it, so must we — a binary search over it would miss entries.
    bad = MAGIC + _header(2) + _hashes(9, 3)
    fake.blob = bad
    fake.meta = {**fake.meta, "sha256": sha256_bytes(bad)}
    assert await doh_filter.HOLDER.refresh_once() is False
    assert doh_filter.HOLDER.current is good
    assert doh_filter.HOLDER.last_error == "ValueError"
    assert (await doh_filter.decide("phish.example", ["phish.example"], 0.1))[0] is True


@pytest.mark.asyncio
async def test_a_redis_that_hangs_on_refresh_costs_only_the_deadline(monkeypatch):
    class _Hanging(ArtifactRedis):
        async def hgetall(self, key):
            await asyncio.sleep(10)

    use_redis(monkeypatch, _Hanging(LISTED))
    assert await asyncio.wait_for(doh_filter.HOLDER.refresh_once(timeout_s=0.05), 1.0) is False
    assert doh_filter.HOLDER.last_error == "TimeoutError"


# ── background refresher ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_refresher_loads_then_picks_up_a_new_publication(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    holder = doh_filter.HOLDER
    holder.start(0.01)
    task = holder._task
    holder.start(0.01)
    assert holder._task is task, "start() must not spawn a second refresher"
    try:
        for _ in range(500):
            if holder.current is not None:
                break
            await asyncio.sleep(0.01)
        assert holder.current is not None
        newer = ArtifactRedis(LISTED | {"new-phish.example"})
        fake.blob, fake.meta = newer.blob, newer.meta
        for _ in range(500):
            if holder.current.listed(["new-phish.example"]):
                break
            await asyncio.sleep(0.01)
        assert holder.current.listed(["new-phish.example"]) == ["new-phish.example"]
    finally:
        await holder.stop()
    assert task.done() and holder._task is None
    await holder.stop()  # stopping twice is harmless


@pytest.mark.asyncio
async def test_a_finished_refresher_is_restarted(monkeypatch):
    use_redis(monkeypatch, ArtifactRedis(LISTED))
    holder = doh_filter.HOLDER
    holder.start(30)
    first = holder._task
    first.cancel()
    await asyncio.wait({first})
    holder.start(30)
    assert holder._task is not first and not holder._task.done()
    await holder.stop()


# ── status and decide() edges ───────────────────────────────────────

@pytest.mark.asyncio
async def test_status_reports_the_loaded_list_without_names(monkeypatch):
    use_redis(monkeypatch, ArtifactRedis(LISTED))
    assert doh_filter.HOLDER.status() == {"loaded": False, "error": None}
    await doh_filter.HOLDER.refresh_once()
    st = doh_filter.HOLDER.status()
    assert st["loaded"] is True and st["count"] == len(LISTED) + 1 and st["revoked"] is False
    assert st["age_s"] >= 0 and st["version"].isdigit()
    assert "phish" not in str(st)


@pytest.mark.asyncio
@pytest.mark.parametrize("qname,candidates", [(None, ["x.example"]), ("", ["x.example"]), ("example", [])])
async def test_decide_without_a_name_or_candidates_blocks_nothing(qname, candidates):
    assert await doh_filter.decide(qname, candidates, 0.1) == (False, "none")


@pytest.mark.asyncio
async def test_members_of_nothing_asks_redis_nothing(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    assert await doh_filter.HOLDER.members([], 0.1) is None
    assert fake.calls["pipeline"] == 0
