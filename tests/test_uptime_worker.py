"""The uptime Worker's own tests (ops/uptime-worker/worker.test.mjs), run from
pytest so CI's test job covers them without a workflow change.

The Worker is the only minute-level watcher of production. Pinned there: it
probes /health/deep (not /health), alerts per protection warning, tells our
DNS block from upstream's NXDOMAIN, retries a failed alert, writes a
heartbeat, and checks the newest backup's age when it has the R2 binding.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "ops" / "uptime-worker" / "worker.test.mjs"


def _node() -> str | None:
    node = shutil.which("node")
    if not node:
        return None
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout
    m = re.match(r"v(\d+)\.(\d+)", out.strip())
    # module.register() (the stub for cloudflare:email) needs Node 20.6+.
    return node if m and (int(m[1]), int(m[2])) >= (20, 6) else None


@pytest.mark.skipif(_node() is None, reason="Node 20.6+ not installed")
def test_uptime_worker_suite_passes():
    proc = subprocess.run(
        [_node(), "--test", str(TEST)], capture_output=True, text=True, cwd=ROOT, timeout=120, check=False,
    )
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]
    assert re.search(r"^# pass (\d+)", proc.stdout, re.M), proc.stdout[-2000:]
    assert re.search(r"^# fail 0$", proc.stdout, re.M), proc.stdout[-2000:]
