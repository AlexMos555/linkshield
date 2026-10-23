"""The mail-security Worker's own tests (ops/mail-security-worker/worker.test.mjs
and forged.test.mjs), run from pytest so CI's test job covers them without a
workflow change.

The Worker serves cleanway.ai's MTA-STS policy and reads the TLS-RPT reports
senders mail to tls-reports@cleanway.ai. Pinned there: the exact policy text
(CRLF, the three Cloudflare MX hosts, testing unless MTA_STS_MODE says
enforce), 404 for anything else, a gzip report counted per policy into a
30-day summary read in one KV read, an alert only when sessions failed (once
a day per known reporter), never the raw report, and malformed mail counted
instead of thrown. And against forged mail: dedup by content, separate
budgets for junk and reports, the alert claimed before it is sent, and no
sender text in the alert.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = [ROOT / "ops" / "mail-security-worker" / name for name in ("worker.test.mjs", "forged.test.mjs")]


def _node() -> str | None:
    node = shutil.which("node")
    if not node:
        return None
    out = subprocess.run([node, "--version"], capture_output=True, text=True, check=False).stdout
    m = re.match(r"v(\d+)\.(\d+)", out.strip())
    # module.register() (the stub for cloudflare:email) needs Node 20.6+.
    return node if m and (int(m[1]), int(m[2])) >= (20, 6) else None


@pytest.mark.skipif(_node() is None, reason="Node 20.6+ not installed")
def test_mail_security_worker_suite_passes():
    proc = subprocess.run(
        [_node(), "--test", "--test-reporter=tap", *map(str, TESTS)], capture_output=True, text=True, cwd=ROOT, timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]
    # TAP explicitly: newer Node prints its "spec" reporter even into a pipe.
    assert re.search(r"^# pass (\d+)", proc.stdout, re.M), proc.stdout[-2000:]
    assert re.search(r"^# fail 0$", proc.stdout, re.M), proc.stdout[-2000:]
