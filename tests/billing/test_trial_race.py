"""One trial per phone even when two installs race (the unique-key backstop).

The memory store serialises transactions, so the race is staged: the second
start_trial's read is made to miss the row the first one already committed —
exactly what a concurrent Postgres transaction would see — and the store's
unique constraint (ConflictError) must turn into a clean 409, not a second
trial and not a 500.
"""
from __future__ import annotations

import pytest

from api.billing.service import trial as trial_service
from api.billing.service.errors import Conflict
from api.billing.store.memory import MemoryTx
from tests.billing.test_flows import _device


async def _device_audits(ctx, device_id):
    async with ctx.store.transaction() as tx:
        return [a.action for a in await tx.list_audit(f"device:{device_id}")]


@pytest.mark.asyncio
async def test_racing_second_trial_on_the_same_phone_is_a_409_and_changes_nothing(ctx, monkeypatch):
    first_device, _ = await _device(ctx)
    first = await trial_service.start_trial(ctx, first_device, fingerprint_input="android-id-race")

    async def stale_read(self, fingerprint_hmac):
        return None  # the concurrent transaction did not see the committed trial yet

    monkeypatch.setattr(MemoryTx, "get_trial_by_fingerprint", stale_read)
    second_device, _ = await _device(ctx)
    with pytest.raises(Conflict) as exc:
        await trial_service.start_trial(ctx, second_device, fingerprint_input="android-id-race")
    assert exc.value.code == "trial_already_used"
    assert exc.value.status_code == 409

    monkeypatch.undo()
    # The original trial is untouched (still bound to the first install, same dates),
    # and the failed attempt left no "trial.started" audit row behind.
    async with ctx.store.transaction() as tx:
        trials = [await tx.get_trial_for_device(first_device.id), await tx.get_trial_for_device(second_device.id)]
    assert trials[0] == first and trials[1] is None
    assert (await _device_audits(ctx, first_device.id)).count("trial.started") == 1
    assert "trial.started" not in await _device_audits(ctx, second_device.id)
