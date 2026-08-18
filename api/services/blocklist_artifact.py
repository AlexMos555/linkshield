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
FORMAT_VERSION = "v1"
LIST_CANARY = "list-canary.cleanway.ai"
# Sanity bounds a phone must also enforce (BlockList.kt).
MAX_ENTRIES = 50_000
MAX_BYTES = 2 * 1024 * 1024

_HEADER_RE = re.compile(
    r"^# cleanway-dns-blocklist (?P<version>v\d+) generated=(?P<generated>\d+) "
    r"count=(?P<count>\d+) status=(?P<status>ok|revoked)$"
)


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
    """The Redis hash stored next to the text."""
    header = parse_header(text.split("\n", 1)[0]) or {}
    return {
        "version": str(header.get("generated", int(time.time()))),
        "sha256": sha256_hex(text),
        "count": str(header.get("count", 0)),
        "generated_at": str(header.get("generated", int(time.time()))),
    }
