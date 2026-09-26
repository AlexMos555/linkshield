#!/usr/bin/env python3
"""Watch the live DNS surface: are we blocking the right things, and only those?

This is the guard that was missing on 2026-08-18, when production
NXDOMAIN'd github.com (and every *.github.com) for everyone using our DNS
profile. Nothing noticed until a person went looking. It now runs every 15
minutes and fails loudly.

Five questions, all against the LIVE endpoints:
  1. Do names that must never be blocked resolve — and does the gateway
     resolve anything at all?  (the publisher's NEVER_BLOCK_GUARDS plus the
     curated list in data/canary_must_resolve.txt; at least half of them
     must come back with an answer, not just "not NXDOMAIN")
  2. Does a name that IS on the published list get NXDOMAIN *from us*? —
     otherwise the blocklist is silently dead (that state lasted months once
     already). The gateway's own NXDOMAIN carries an SOA naming
     blocked.cleanway.ai; an NXDOMAIN without it came from upstream. Until
     2026-09-26 this probe could not fail: list-canary.cleanway.ai exists
     nowhere, so upstream said NXDOMAIN too. Also probed: up to three hosts
     from a public phishing feed that are on our list AND resolve on the
     public internet (the gateway's own upstream) — the whole path, on real
     names. Best-effort: no such host right now is a note, not a failure.
  3. Is the phone artifact fresh, self-consistent, and carrying its canary?
  4. Is the API healthy end to end?  (/health/deep — /health is always-200)
  5. Is the landing page people install from up?  (/ru/android)

Schedule: GitHub runs '*/15' crons best-effort. Measured 2026-09-18..25:
46–47 runs in 7 days (about one every 3.5 h) instead of 672. Treat this as a
periodic audit, not paging; minute-level uptime needs an external monitor
(docs/runbooks/monitoring.md).

A canary that cries wolf is muted. Measured 2026-09-02: 11 of 100 runs failed
and every one was noise — 4 from a freshness threshold equal to the
publisher's cadence, 7 from a random Tranco sample full of names a blocklist
legitimately blocks. Both are fixed here; tests/test_dns_canary.py pins them.

Exit 0 = healthy. Exit 1 = something is wrong; the run fails and GitHub mails
the owner. Read-only: it never writes Redis.

Usage:
    python3 scripts/dns_canary.py [--base https://api.cleanway.ai]
                                  [--landing-base https://cleanway.ai]
                                  [--live-source https://phishunt.io/feed.txt]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE = "https://api.cleanway.ai"
DEFAULT_LANDING_BASE = "https://cleanway.ai"
LANDING_PATH = "/ru/android"
USER_AGENT = "cleanway-dns-canary"

# The SOA MNAME in every NXDOMAIN the gateway synthesises
# (api/services/doh_gateway.py _SOA_MNAME; a test pins the two together —
# this script runs on a bare runner without the API's dependencies).
BLOCK_SOA_MNAME = "blocked.cleanway.ai"
# Live phishing hosts to probe: Phishunt's hourly feed, CC0 1.0 ("released
# into the public domain", terms §7). Empty string disables the live probe.
DEFAULT_LIVE_SOURCE = "https://phishunt.io/feed.txt"
# Where "does the public internet resolve it" is asked: the gateway's own
# upstream (doh_gateway.CLOUDFLARE_DOH_URL), unfiltered 1.1.1.1.
PUBLIC_DOH_BASE = "https://cloudflare-dns.com"
MAX_LIVE_LOOKUPS = 10  # public-DNS questions per run, at most
MAX_LIVE_PROBES = 3

sys.path.insert(0, str(ROOT))
from api.services.blocklist_artifact import (  # noqa: E402
    LIST_CANARY, NEVER_BLOCK_GUARDS, name_hash, parse_artifact_v2,
)

# Curated names that must resolve; merged with NEVER_BLOCK_GUARDS at run time.
MUST_RESOLVE_PATH = ROOT / "data" / "canary_must_resolve.txt"

# The publisher (.github/workflows/refresh-dangerous-domains.yml) runs on
# cron '23 */6 * * *'. GitHub cron drifts, so a threshold equal to the cadence
# fails by construction whenever one run is late — 4 of 100 runs, publisher
# 60/60 green. 13h absorbs a whole missed slot plus drift, and is still far
# inside the 48h a phone tolerates (BlockList.kt STALE_AFTER_MS) before it
# calls its own copy stale.
MAX_ARTIFACT_AGE_S = 13 * 60 * 60


def wire_query(name: str) -> bytes:
    """A minimal A query with a random transaction id (so no cache answers it)."""
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"


class DnsAnswer(NamedTuple):
    rcode: int
    answers: int
    soa_mname: Optional[str]  # MNAME of the first SOA in the authority section


def _read_name(buf: bytes, pos: int) -> tuple[str, int]:
    """A (possibly compressed) domain name at `pos`: (name, offset after it)."""
    labels: list[str] = []
    after: Optional[int] = None
    for _ in range(128):  # bounded: a pointer loop must not hang the canary
        if pos >= len(buf):
            raise ValueError("name runs past the end of the message")
        length = buf[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            after = pos + 2 if after is None else after
            pos = ((length & 0x3F) << 8) | buf[pos + 1]
            continue
        if length == 0:
            return ".".join(labels), (pos + 1 if after is None else after)
        labels.append(buf[pos + 1:pos + 1 + length].decode("ascii", "replace").lower())
        pos += 1 + length
    raise ValueError("name too long or a compression loop")


def parse_response(body: bytes) -> DnsAnswer:
    """RCODE, answer count and the authority SOA's MNAME of a DNS response."""
    if len(body) < 12:
        raise ValueError(f"short DNS response: {len(body)} bytes")
    qdcount, ancount, nscount, _ = struct.unpack("!HHHH", body[4:12])
    pos = 12
    for _ in range(qdcount):
        pos = _read_name(body, pos)[1] + 4          # QTYPE + QCLASS
    for _ in range(ancount):
        pos = _read_name(body, pos)[1]
        pos += 10 + struct.unpack("!H", body[pos + 8:pos + 10])[0]
    soa: Optional[str] = None
    for _ in range(nscount):
        pos = _read_name(body, pos)[1]
        rtype, _cls, _ttl, rdlength = struct.unpack("!HHIH", body[pos:pos + 10])
        if rtype == 6 and soa is None:
            soa = _read_name(body, pos + 10)[0]
        pos += 10 + rdlength
    return DnsAnswer(body[3] & 0x0F, ancount, soa)


def doh(base: str, name: str, timeout: float = 10.0) -> DnsAnswer:
    """Ask the DoH endpoint at `base` (RFC 8484 GET) for `name`'s A record."""
    q = base64.urlsafe_b64encode(wire_query(name)).decode().rstrip("=")
    req = urllib.request.Request(
        f"{base}/dns-query?dns={q}",
        headers={"accept": "application/dns-message", "user-agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    return parse_response(body)


def http_get(url: str, timeout: float = 15.0) -> tuple[int, bytes]:
    """(status, body). GET, explicitly: every API path answers HEAD with 405,
    so a HEAD-based probe would page on a perfectly healthy service."""
    req = urllib.request.Request(url, method="GET", headers={"user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def known_blocked_samples() -> list[str]:
    """Names we know are published, to prove filtering is not silently dead.
    The publisher writes the list canary into every set it publishes. It
    exists nowhere in public DNS, so only our SOA marker proves the block."""
    return [LIST_CANARY]


def listed_hosts_in_feed(text: str, hashes: set[int]) -> list[str]:
    """Hosts of a URL-per-line feed that the artifact lists exactly, in feed
    order, without repeats. Exact hash only: such a name is in the gateway's
    set too (the artifact is a subset of it)."""
    out: list[str] = []
    for line in text.splitlines():
        host = (urlparse(line.strip()).hostname or "").lower().rstrip(".")
        if host and host not in out and name_hash(host) in hashes:
            out.append(host)
    return out


def pick_live_probes(candidates: list[str]) -> list[str]:
    """Up to MAX_LIVE_PROBES candidates the public internet resolves right
    now. A name that does not resolve publicly would be NXDOMAIN at our
    gateway even with filtering dead, so it proves nothing."""
    picked: list[str] = []
    for host in candidates[:MAX_LIVE_LOOKUPS]:
        try:
            answer = doh(PUBLIC_DOH_BASE, host)
        except Exception:  # noqa: BLE001
            continue
        if answer.rcode == 0 and answer.answers > 0:
            picked.append(host)
        if len(picked) == MAX_LIVE_PROBES:
            break
    return picked


def live_probes(source_url: str, hashes: set[int]) -> tuple[list[str], str]:
    """(listed hosts that resolve publicly, a note on how they were found).
    Best-effort by design: a quiet feed or an unreachable source is a note,
    never a failure — the list-canary check still guards the gateway."""
    if not source_url:
        return [], "disabled"
    if not hashes:
        return [], "skipped: no parsed artifact"
    try:
        status, body = http_get(source_url)
    except Exception as exc:  # noqa: BLE001
        return [], f"skipped: source unreachable ({exc})"
    if status != 200:
        return [], f"skipped: source answered HTTP {status}"
    candidates = listed_hosts_in_feed(body.decode("utf-8", "replace"), hashes)
    if not candidates:
        return [], "skipped: no host of the source is on our list right now"
    picked = pick_live_probes(candidates)
    note = f"{len(candidates)} listed in the source, {len(picked)} resolve publicly"
    return picked, note


def artifact_hashes(blob: bytes) -> set[int]:
    """The artifact's hashes, or an empty set if it does not parse (the
    artifact check reports that on its own)."""
    try:
        return set(parse_artifact_v2(blob)[1])
    except Exception:  # noqa: BLE001
        return set()


def load_must_resolve(path: Path) -> list[str]:
    """Curated must-resolve names: one per line, '#' comments, blank lines
    ignored, lowercased, deduplicated in file order. Raises ValueError when
    the file is unreadable or yields no names — a canary with an empty
    resolve list would be watching nothing."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"must-resolve list unreadable: {path}: {exc}") from exc
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().lower().rstrip(".")
        if line:
            names.append(line)
    if not names:
        raise ValueError(f"must-resolve list is empty: {path}")
    return list(dict.fromkeys(names))


def must_resolve_names(path: Path) -> list[str]:
    """Publisher guards first, then the curated file; no duplicates."""
    return list(dict.fromkeys([*NEVER_BLOCK_GUARDS, *load_must_resolve(path)]))


def check_resolves(base: str, names: list[str]) -> list[str]:
    """Nothing on the must-resolve list may be dark, and the gateway must
    actually resolve: a SERVFAIL for everything is not NXDOMAIN either, but
    it is every phone on the DNS profile offline."""
    problems: list[str] = []
    answered = 0
    for name in names:
        try:
            answer = doh(base, name)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{name}: DoH request failed: {exc}")
            continue
        if answer.rcode == 3:
            problems.append(f"BLOCKED A POPULAR NAME: {name} -> NXDOMAIN")
        elif answer.rcode not in (0, 2):
            problems.append(f"{name}: unexpected rcode {answer.rcode}")
        elif answer.rcode == 0 and answer.answers > 0:
            answered += 1
    if names and answered * 2 < len(names):
        problems.append(f"GATEWAY RESOLVES ALMOST NOTHING: {answered} of {len(names)} must-resolve names "
                        f"got an answer (upstream down?)")
    return problems


def check_blocked(base: str, probes: list[str]) -> list[str]:
    """Any name the publisher just wrote must be NXDOMAIN at the gateway, and
    the NXDOMAIN must be ours (SOA MNAME BLOCK_SOA_MNAME) — not upstream's
    honest "no such name"."""
    problems: list[str] = []
    for name in probes:
        try:
            answer = doh(base, name)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{name}: DoH request failed: {exc}")
            continue
        if answer.rcode != 3:
            problems.append(f"LISTED NAME NOT BLOCKED: {name} -> rcode {answer.rcode} (blocklist dead?)")
        elif answer.soa_mname != BLOCK_SOA_MNAME:
            problems.append(f"LISTED NAME NOT BLOCKED BY US: {name} -> NXDOMAIN from upstream "
                            f"(SOA {answer.soa_mname or 'none'}), not from our blocklist (blocklist dead?)")
    return problems


def fetch_artifact(base: str) -> tuple[bytes, str, str | None]:
    req = urllib.request.Request(f"{base}/api/v1/blocklist/dns", headers={"user-agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        blob = r.read()
        etag = (r.headers.get("ETag") or "").strip().removeprefix("W/").strip('"')
        count_hdr = r.headers.get("X-Cleanway-Blocklist-Count")
    return blob, etag, count_hdr


def check_artifact(blob: bytes, etag: str, count_hdr: str | None) -> list[str]:
    problems: list[str] = []
    if hashlib.sha256(blob).hexdigest() != etag:
        problems.append("artifact body does not match its ETag sha256")
    try:
        header, hashes = parse_artifact_v2(blob)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"artifact does not parse: {exc}")
        return problems
    age = int(time.time()) - header["generated"]
    if age > MAX_ARTIFACT_AGE_S:
        problems.append(f"artifact is {age // 3600}h old (max {MAX_ARTIFACT_AGE_S // 3600}h) — is the cron dead?")
    if count_hdr is not None and str(header["count"]) != str(count_hdr):
        problems.append(f"count mismatch: header {header['count']}, X-header {count_hdr}")
    if name_hash(LIST_CANARY) not in set(hashes):
        problems.append("artifact is missing its list canary — phones cannot prove the list is live")
    return problems


def _failing_components(payload: dict) -> list[str]:
    components = payload.get("components")
    if not isinstance(components, dict):
        return []
    return [k for k, v in components.items() if not (isinstance(v, dict) and v.get("ok"))]


def check_health_deep(base: str) -> list[str]:
    """/health/deep pings Redis + Supabase and answers 503 'degraded' when any
    is down. /health is always-200 by design (Railway's pod probe) and would
    hide exactly the outages we want to hear about."""
    url = f"{base}/health/deep"
    try:
        status, body = http_get(url)
    except Exception as exc:  # noqa: BLE001
        return [f"/health/deep: request failed: {exc}"]
    try:
        payload = json.loads(body)
    except ValueError:
        return [f"/health/deep: HTTP {status}, body is not JSON"]
    reported = payload.get("status") if isinstance(payload, dict) else None
    if status == 200 and reported == "ok":
        return []
    failing = _failing_components(payload) if isinstance(payload, dict) else []
    return [f"/health/deep: HTTP {status}, status={reported!r}, failing components: {failing or 'unknown'}"]


def check_landing(landing_base: str) -> list[str]:
    """The page Tele2 subscribers install from. 200 or it is an incident."""
    url = f"{landing_base}{LANDING_PATH}"
    try:
        status, _ = http_get(url)
    except Exception as exc:  # noqa: BLE001
        return [f"landing {LANDING_PATH}: request failed: {exc}"]
    if status != 200:
        return [f"LANDING DOWN: {url} -> HTTP {status}"]
    return []


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("CANARY_BASE", DEFAULT_BASE),
                    help="API base URL (env CANARY_BASE)")
    ap.add_argument("--landing-base", default=os.environ.get("CANARY_LANDING_BASE", DEFAULT_LANDING_BASE),
                    help="landing-page base URL (env CANARY_LANDING_BASE)")
    ap.add_argument("--live-source", default=os.environ.get("CANARY_LIVE_SOURCE", DEFAULT_LIVE_SOURCE),
                    help="URL-per-line phishing feed for the live block probe; '' disables "
                         "(env CANARY_LIVE_SOURCE)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    base = args.base.rstrip("/")
    landing_base = args.landing_base.rstrip("/")
    problems: list[str] = []

    # 1. Nothing on the must-resolve list may be dark.
    try:
        names = must_resolve_names(MUST_RESOLVE_PATH)
    except ValueError as exc:
        problems.append(f"MUST-RESOLVE LIST BROKEN: {exc}")
        names = []
    problems += check_resolves(base, names)
    print(f"resolve-check: {len(names)} names")

    # 2. The blocklist must still block — with OUR NXDOMAIN. The list canary
    #    always; plus real listed hosts that the public internet resolves.
    try:
        blob, etag, count_hdr = fetch_artifact(base)
    except Exception as exc:  # noqa: BLE001
        problems.append(f"artifact fetch failed: {exc}")
        blob, etag, count_hdr = b"", "", None
    probes = list(known_blocked_samples())
    problems += check_blocked(base, probes)
    print(f"block-check: {len(probes)} listed names")
    live, note = live_probes(args.live_source, artifact_hashes(blob))
    problems += check_blocked(base, live)
    print(f"live-block-check: {len(live)} listed names that resolve publicly ({note})")

    # 3. The artifact phones sync.
    if blob:
        try:
            problems += check_artifact(blob, etag, count_hdr)
            print(f"artifact-check: {len(blob)} bytes")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"artifact check failed: {exc}")
    else:
        print("artifact-check: skipped (fetch failed)")

    # 4 + 5. The API end to end, and the page people install from.
    problems += check_health_deep(base)
    print("health-check: /health/deep")
    problems += check_landing(landing_base)
    print(f"landing-check: {LANDING_PATH}")

    if problems:
        print("\nDNS CANARY FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nDNS canary OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
