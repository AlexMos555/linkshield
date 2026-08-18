"""The DNS blocklist artifact the Android shield syncs.

One text file, one format, two writers/readers:
  * scripts/refresh_dangerous_domains.py renders it (render_artifact) and
    stores it in Redis under REDIS_TEXT_KEY / REDIS_META_KEY in the SAME
    transaction as the DoH gateway's `dangerous_domains` set — so the phone
    and the gateway can never disagree about what is blocked.
  * api/routers/blocklist.py serves it with ETag = sha256(text).
  * mobile/modules/cleanway-vpn/.../BlockList.kt parses the same header.

Format (LF, UTF-8, lowercase punycode names, sorted, one per line):
  # cleanway-dns-blocklist v1 generated=<epoch> count=<n> status=ok|revoked
  <name>
  ...
Semantics: every name means "block this name and all its subdomains" — safe
because the publisher's guards guarantee each line is a dedicated phishing
registrable or one tenant's host under a shared suffix, never a platform
apex or a public suffix. `list-canary.cleanway.ai` is always present so the
phone can prove the loaded list is live. `status=revoked count=0` is the
kill switch: phones clear their list.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Iterable, Optional

# Names that must never be blocked, by anything, ever. Used by the publisher
# (post-publish verification, with rollback) and by the 15-minute DNS canary.
# github.com is on this list because on 2026-08-18 it was NXDOMAIN in
# production for everyone using our DNS profile.
NEVER_BLOCK_GUARDS = (
    "github.com",
    "www.github.com",
    "raw.githubusercontent.com",
    "google.com",
    "www.google.com",
    "apple.com",
    "microsoft.com",
    "cloudflare.com",
    "amazonaws.com",
    "wikipedia.org",
    "cleanway.ai",
    "api.cleanway.ai",
)

REDIS_TEXT_KEY = "dangerous_domains:mobile:v1"
REDIS_META_KEY = "dangerous_domains:mobile:v1:meta"
FORMAT_VERSION = "v2"

# ── v2: 48-bit hashes instead of names ──
#
# v1 shipped the names as text. With the feeds that give real coverage the
# list is ~516k names = 13 MB of text, and 516k Java strings in a HashSet is
# ~50 MB of heap inside a VpnService — not shippable. v2 ships the first
# HASH_BYTES bytes of SHA-256(name), sorted ascending, so the phone holds a
# 3 MB LongArray and answers by binary search.
#
# Why 6 bytes: with ~5·10^5 entries in a 2^48 space a random query collides
# with probability ~2·10^-9 per suffix lookup. At ~5 lookups per query and
# ~10^3 queries a day that is one spurious block per ~300 years per phone —
# and the phone's popular-domain veto (plaintext, on the query's registrable)
# still sits on top of it. 4 bytes would have been ~1 wrong block every 8
# days, which is not a trade we would make.
HASH_BYTES = 6
MAGIC = b"CWBL2\n"
LIST_CANARY = "list-canary.cleanway.ai"
# Sanity bounds a phone must also enforce (BlockList.kt).
MAX_ENTRIES = 50_000
MAX_BYTES = 2 * 1024 * 1024

_HEADER_RE = re.compile(
    r"^# cleanway-dns-blocklist (?P<version>v\d+) generated=(?P<generated>\d+) "
    r"count=(?P<count>\d+) status=(?P<status>ok|revoked)$"
)


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def name_hash(name: str) -> int:
    """The one definition of a blocklist entry's hash. Mirrored by
    BlockList.hashOf() in Kotlin; BlocklistArtifactParityTest pins the pair."""
    digest = hashlib.sha256(name.strip().lower().rstrip(".").encode("utf-8")).digest()
    return int.from_bytes(digest[:HASH_BYTES], "big")


def render_artifact_v2(names: Iterable[str], generated: Optional[int] = None, revoked: bool = False) -> bytes:
    """Binary artifact: magic + text header line + sorted packed hashes."""
    gen = int(generated if generated is not None else time.time())
    if revoked:
        header = f"# cleanway-dns-blocklist {FORMAT_VERSION} generated={gen} count=0 status=revoked\n"
        return MAGIC + header.encode("ascii")
    cleaned = {n.strip().lower().rstrip(".") for n in names if n and n.strip()} | {LIST_CANARY}
    hashes = sorted({name_hash(n) for n in cleaned})
    header = f"# cleanway-dns-blocklist {FORMAT_VERSION} generated={gen} count={len(hashes)} status=ok\n"
    body = b"".join(h.to_bytes(HASH_BYTES, "big") for h in hashes)
    return MAGIC + header.encode("ascii") + body


def parse_artifact_v2(blob: bytes) -> tuple[dict, list[int]]:
    """(header, hashes). Raises ValueError on anything malformed — the phone
    is equally strict, and a half-understood blocklist is not a blocklist."""
    if not blob.startswith(MAGIC):
        raise ValueError("bad magic")
    nl = blob.index(b"\n", len(MAGIC))
    header = parse_header(blob[len(MAGIC):nl + 1].decode("ascii", "replace"))
    if not header:
        raise ValueError("bad header")
    body = blob[nl + 1:]
    if len(body) % HASH_BYTES:
        raise ValueError("truncated body")
    hashes = [int.from_bytes(body[i:i + HASH_BYTES], "big") for i in range(0, len(body), HASH_BYTES)]
    if len(hashes) != header["count"]:
        raise ValueError(f"count mismatch: {len(hashes)} vs {header['count']}")
    if hashes != sorted(hashes):
        raise ValueError("hashes not sorted")
    return header, hashes


def artifact_covers(hashes: set[int], qname: str) -> bool:
    """The phone's match rule, for benchmarks and canaries: a listed name
    covers itself and all its subdomains."""
    parts = qname.lower().rstrip(".").split(".")
    return any(name_hash(".".join(parts[i:])) in hashes for i in range(len(parts) - 1))


def render_artifact(names: Iterable[str], generated: Optional[int] = None, revoked: bool = False) -> str:
    """Render the artifact text. Names are lowercased, deduplicated, sorted;
    the list canary is always injected unless revoked."""
    gen = int(generated if generated is not None else time.time())
    if revoked:
        return f"# cleanway-dns-blocklist {FORMAT_VERSION} generated={gen} count=0 status=revoked\n"
    body = sorted({n.strip().lower().rstrip(".") for n in names if n and n.strip()} | {LIST_CANARY})
    header = f"# cleanway-dns-blocklist {FORMAT_VERSION} generated={gen} count={len(body)} status=ok"
    return header + "\n" + "\n".join(body) + "\n"


def parse_header(line: str) -> Optional[dict]:
    """Parse the first line; None if it is not a valid header."""
    m = _HEADER_RE.match(line.strip())
    if not m:
        return None
    return {
        "version": m.group("version"),
        "generated": int(m.group("generated")),
        "count": int(m.group("count")),
        "status": m.group("status"),
    }


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def meta_for(text: str) -> dict:
    """The Redis hash stored next to a v1 (text) artifact."""
    header = parse_header(text.split("\n", 1)[0]) or {}
    return {
        "version": str(header.get("generated", int(time.time()))),
        "sha256": sha256_hex(text),
        "count": str(header.get("count", 0)),
        "generated_at": str(header.get("generated", int(time.time()))),
    }


def meta_for_v2(blob: bytes) -> dict:
    """The Redis hash stored next to a v2 (binary) artifact."""
    nl = blob.index(b"\n", len(MAGIC))
    header = parse_header(blob[len(MAGIC):nl + 1].decode("ascii", "replace")) or {}
    return {
        "version": str(header.get("generated", int(time.time()))),
        "sha256": sha256_bytes(blob),
        "count": str(header.get("count", 0)),
        "generated_at": str(header.get("generated", int(time.time()))),
        "format": FORMAT_VERSION,
    }
