"""A wall-clock budget for one fresh domain analysis.

The first check of a new site used to take as long as its slowest source: 10
of 31 first checks ran past 5 s and one hit 10.9 s (report 2026-09-25 #6),
while the phone gives up after 5 s and the app after 6 s. So the person saw
"the server did not answer" for a check that was still running — and the
unfinished answer was then cached for everyone else.

Now the whole analysis gets one deadline (config.analysis_budget_seconds,
~3 s). Checks still running when it passes are cancelled and NAMED in the
verdict (`checks_incomplete`), so a partial verdict says it is partial
instead of pretending to be complete.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable

# The smallest slice a step gets even when the budget is spent, so a step
# that would finish instantly (a gate that returns None) still gets to run.
MIN_STEP_S = 0.05


class Deadline:
    """Monotonic deadline; `remaining()` never goes negative."""

    def __init__(self, budget_s: float) -> None:
        self._end = time.monotonic() + max(0.0, budget_s)

    def remaining(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def step(self, cap_s: float) -> float:
        """Time a single step may take: the remaining budget, capped."""
        return max(MIN_STEP_S, min(self.remaining(), cap_s))


async def run_within_budget(
    calls: dict[str, Awaitable[Any]], timeout_s: float,
) -> tuple[dict[str, Any], list[str]]:
    """Run named awaitables concurrently for at most `timeout_s`.

    Returns (results, unfinished): `results` holds the value of every call
    that completed, `unfinished` names every call that did not — cancelled at
    the deadline, or failed with an exception. Never raises for a call's
    sake, and never waits past the deadline for a straggler: a cancelled
    thread-backed call keeps its thread until its own socket timeout, but
    the verdict does not wait for it.
    """
    if not calls:
        return {}, []
    tasks = {name: asyncio.ensure_future(aw) for name, aw in calls.items()}
    done, pending = await asyncio.wait(tasks.values(), timeout=max(MIN_STEP_S, timeout_s))
    for task in pending:
        task.cancel()
    results: dict[str, Any] = {}
    unfinished: list[str] = []
    for name, task in tasks.items():
        if task in done and not task.cancelled() and task.exception() is None:
            results[name] = task.result()
        else:
            unfinished.append(name)
    return results, unfinished
