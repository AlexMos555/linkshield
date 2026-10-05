"""Idempotency-Key handling (plan A.6): a key is reserved before the side effect runs."""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from api.billing import deps
from api.billing.deps import idempotent
from api.billing.service.errors import Conflict


@pytest.mark.asyncio
async def test_concurrent_requests_with_one_key_run_the_side_effect_once(ctx):
    calls = []

    async def compute():
        calls.append(1)
        await asyncio.sleep(0.05)          # the provider round trip
        return {"n": len(calls)}

    first, second = await asyncio.gather(
        idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=compute),
        idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=compute),
    )
    assert len(calls) == 1
    assert first == second == (201, {"success": True, "data": {"n": 1}, "error": None})


@pytest.mark.asyncio
async def test_a_failed_attempt_releases_the_key(ctx):
    async def failing():
        raise Conflict("no free seats on this plan", code="no_free_seats")

    async def succeeding():
        return {"ok": True}

    with pytest.raises(Conflict):
        await idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=failing)
    assert await idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=succeeding) == (
        201, {"success": True, "data": {"ok": True}, "error": None})


@pytest.mark.asyncio
async def test_a_request_still_in_flight_answers_409_after_the_wait(ctx, monkeypatch):
    monkeypatch.setattr(deps, "_IDEMPOTENCY_WAIT_STEPS", 2)
    monkeypatch.setattr(deps, "_IDEMPOTENCY_WAIT_SECONDS", 0.001)
    async with ctx.store.transaction() as tx:
        assert await tx.reserve_idempotency_key("dev-1", "k", now=ctx.now(), stale_before=ctx.now()) is None

    async def compute():
        raise AssertionError("must not run while another request holds the key")

    with pytest.raises(Conflict) as err:
        await idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=compute)
    assert err.value.code == "idempotency_in_progress"


@pytest.mark.asyncio
async def test_an_abandoned_reservation_is_taken_over(ctx, clock):
    async with ctx.store.transaction() as tx:
        assert await tx.reserve_idempotency_key("dev-1", "k", now=ctx.now(), stale_before=ctx.now()) is None
    clock.advance(minutes=10)

    async def compute():
        return {"ok": True}

    status, body = await idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=compute)
    assert status == 201 and body["data"] == {"ok": True}
    clock.advance(minutes=10)
    assert (await idempotent(ctx, scope="dev-1", key="k", status_code=201, compute=compute))[1] == body
    assert deps._IDEMPOTENCY_RESERVATION_TTL <= timedelta(minutes=10)
