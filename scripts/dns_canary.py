#!/usr/bin/env python3
"""Watch the live DNS surface: are we blocking the right things, and only those?

This is the guard that was missing on 2026-08-18, when production
NXDOMAIN'd github.com (and every *.github.com) for everyone using our DNS
profile. Nothing noticed until a person went looking. It now runs every 15
minutes and fails loudly.

Three questions, all against the LIVE endpoint:
  1. Do names that must never be blocked resolve?  (github.com, google.com,
     apple.com, cleanway.ai, a rotating sample of Tranco's top domains)
  2. Does a name that IS on the published list get NXDOMAIN? — otherwise the
     blocklist is silently dead (that state lasted months once already).
  3. Is the phone artifact fresh, self-consistent, and carrying its canary?

Exit 0 = healthy. Exit 1 = something is wrong; the run fails and GitHub mails
the owner. Read-only: it never writes Redis.

Usage:
    python3 scripts/dns_canary.py [--base https://api.cleanway.ai] [--sample 25]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import struct
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = "https://api.cleanway.ai"

sys.path.insert(0, str(ROOT))
from api.services.blocklist_artifact import NEVER_BLOCK_GUARDS  # noqa: E402

# Names that must resolve, always. github.com is here because it did not.
MUST_RESOLVE = list(NEVER_BLOCK_GUARDS)
MAX_ARTIFACT_AGE_S = 6 * 60 * 60


def wire_query(name: str) -> bytes:
    """A minimal A query with a random transaction id (so no cache answers it)."""
    labels = b"".join(bytes([len(l)]) + l.encode("ascii") for l in name.split(".")) + b"\x00"
    return os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"


def doh(base: str, name: str, timeout: float = 10.0) -> tuple[int, int]:
    """(rcode, answer_count) from the live gateway."""
    q = base64.urlsafe_b64encode(wire_query(name)).decode().rstrip("=")
    req = urllib.request.Request(
        f"{base}/dns-query?dns={q}",
        headers={"accept": "application/dns-message", "user-agent": "cleanway-dns-canary"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    if len(body) < 12:
        raise ValueError(f"short DoH response for {name}: {len(body)} bytes")
    return body[3] & 0x0F, struct.unpack("!H", body[6:8])[0]


def tranco_sample(n: int) -> list[str]:
    """A rotating sample of popular domains — the blast radius we care about."""
    path = ROOT / "data" / "top_10k.json"
    try:
        raw = json.loads(path.read_text())
        names = list(raw.keys() if isinstance(raw, dict) else raw)
    except Exception:
        return []
    random.shuffle(names)
    # Skip public suffixes / shared platforms: a tenant name under them is
    # legitimately blockable, and the apex is covered by MUST_RESOLVE anyway.
    try:
        shared = set(json.loads((ROOT / "data" / "public_suffixes_in_top.json").read_text()))
    except Exception:
        shared = set()
    return [d for d in names if d not in shared][:n]


def check_artifact(base: str) -> list[str]:
    problems: list[str] = []
    req = urllib.request.Request(f"{base}/api/v1/blocklist/dns",
                                 headers={"user-agent": "cleanway-dns-canary"})
    with urllib.request.urlopen(req, timeout=20) as r:
        text = r.read().decode("utf-8")
        etag = (r.headers.get("ETag") or "").strip().removeprefix("W/").strip('"')
        count_hdr = r.headers.get("X-Cleanway-Blocklist-Count")
    if hashlib.sha256(text.encode()).hexdigest() != etag:
        problems.append("artifact body does not match its ETag sha256")
    lines = text.split("\n")
    header = lines[0] if lines else ""
    if not header.startswith("# cleanway-dns-blocklist v1 "):
        problems.append(f"bad artifact header: {header[:80]!r}")
        return problems
    fields = dict(p.split("=", 1) for p in header.split() if "=" in p)
    generated = int(fields.get("generated", 0))
    age = int(time.time()) - generated
    if age > MAX_ARTIFACT_AGE_S:
        problems.append(f"artifact is {age // 3600}h old (max {MAX_ARTIFACT_AGE_S // 3600}h) — is the cron dead?")
    names = [l for l in lines[1:] if l.strip()]
    if str(len(names)) != str(count_hdr) or str(len(names)) != fields.get("count"):
        problems.append(f"count mismatch: {len(names)} lines, header {fields.get('count')}, X-header {count_hdr}")
    if "list-canary.cleanway.ai" not in names:
        problems.append("artifact is missing its list canary — phones cannot prove the list is live")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("CANARY_BASE", DEFAULT_BASE))
    ap.add_argument("--sample", type=int, default=25, help="how many Tranco names to spot-check")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    problems: list[str] = []

    # 1. Nothing popular may be dark.
    for name in MUST_RESOLVE + tranco_sample(args.sample):
        try:
            rcode, answers = doh(base, name)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{name}: DoH request failed: {exc}")
            continue
        if rcode == 3:
            problems.append(f"BLOCKED A POPULAR NAME: {name} -> NXDOMAIN")
        elif rcode not in (0, 2):
            problems.append(f"{name}: unexpected rcode {rcode}")
    print(f"resolve-check: {len(MUST_RESOLVE) + args.sample} names")

    # 2. The blocklist must still block.
    try:
        req = urllib.request.Request(f"{base}/api/v1/blocklist/dns",
                                     headers={"user-agent": "cleanway-dns-canary"})
        with urllib.request.urlopen(req, timeout=20) as r:
            listed = [l for l in r.read().decode().split("\n")[1:] if l.strip()]
    except Exception as exc:  # noqa: BLE001
        problems.append(f"artifact fetch failed: {exc}")
        listed = []
    probes = [n for n in listed if n != "list-canary.cleanway.ai"][:3]
    for name in probes:
        try:
            rcode, _ = doh(base, name)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{name}: DoH request failed: {exc}")
            continue
        if rcode != 3:
            problems.append(f"LISTED NAME NOT BLOCKED: {name} -> rcode {rcode} (blocklist dead?)")
    print(f"block-check: {len(probes)} listed names")

    # 3. The artifact phones sync.
    try:
        problems += check_artifact(base)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"artifact check failed: {exc}")
    print("artifact-check: done")

    if problems:
        print("\nDNS CANARY FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nDNS canary OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
