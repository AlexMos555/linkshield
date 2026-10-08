"""Certificate Transparency, read the cheap way: static-ct-api tiles.

The Watchtower (api/services/watchtower.py) asks crt.sh for "every cert
whose name contains <brand>" — a LIKE query over Sectigo's mirror of all
logs, which answers in 20 s on a good day and 502s on a bad one. The
lookalike generator needs the opposite: every NEW certificate, once,
matched against our own rules. The modern logs serve exactly that as static
files (C2SP static-ct-api, https://c2sp.org/static-ct-api): a `checkpoint`
with the current tree size, and data tiles of 256 entries each at
`tile/data/<index>`. No API key, no rate limit beyond a CDN's, no query
language — and a tile of 256 certificates is one 500 KB GET (measured on
Let's Encrypt 'Sycamore2026h2', 2026-10-04: 0.12 s).

The RFC 6962 logs are not worth the requests: Google 'Argon' hands out 32
entries per get-entries call (measured), Cloudflare 'Nimbus' 192 — one
hour of Let's Encrypt issuance (~380k entries) would be 12,000 calls against
Argon and 1,500 tiles here.

What this module knows:

  * tile_path()         the tlog-tiles path encoding (x001/x234/067)
  * parse_checkpoint()  origin, tree size, root hash
  * iter_leaves()       the TileLeaf framing: timestamp, entry type, the
                        certificate (DER) or, for a precertificate, its
                        TBSCertificate — which is where the names are
  * dns_names()         the dNSName entries of the SubjectAltName extension,
                        found by walking the DER by hand (no `cryptography`
                        dependency in requirements.txt, and a precert's TBS
                        is not a certificate that library would load anyway)
  * select_tiled_logs() the logs to read today from Google's log list — every
                        shard a certificate issued now can land in (they
                        are split by expiry), so a roll-over needs no deploy

Nothing here decides what a name means; api/services/lookalike_generator.py
does that with the scorer's own rules.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

import httpx

logger = logging.getLogger("cleanway.ct_tiles")

TILE_WIDTH = 256
USER_AGENT = "Cleanway-lookalike/1.0 (+https://cleanway.ai)"
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
# Let's Encrypt issues the certificates phishing kits use (free, automated);
# its two logs carry nearly every one of them. Other operators' tiled logs
# (Google 'ParcelYard', Geomys, IPng) can be added through LOOKALIKE_CT_OPERATORS.
DEFAULT_OPERATORS = ("Let's Encrypt",)
TILE_TIMEOUT_S = 20.0
# A log that cannot be reached is skipped for the run; the position is kept.
CHECKPOINT_TIMEOUT_S = 10.0
# The longest a publicly trusted TLS certificate may be valid (CA/Browser
# Forum: 398 days) — the furthest shard a certificate issued today reaches.
MAX_CERT_VALIDITY = timedelta(days=398)

X509_ENTRY = 0
PRECERT_ENTRY = 1

_OID_SAN = bytes.fromhex("0603551d11")   # 2.5.29.17 subjectAltName
_OID_CN = bytes.fromhex("0603550403")    # 2.5.4.3 commonName
_TAG_DNS_NAME = 0x82                     # [2] IMPLICIT IA5String
_TAG_OCTET_STRING = 0x04
_TAG_SEQUENCE = 0x30
_TAG_BOOLEAN = 0x01
_STRING_TAGS = frozenset({0x0C, 0x13, 0x16, 0x14})  # UTF8, Printable, IA5, T61


class TileFormatError(ValueError):
    """A tile or checkpoint that does not follow the static-ct-api framing."""


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root_hash: str


@dataclass(frozen=True)
class TileLeaf:
    timestamp_ms: int
    entry_type: int
    certificate: bytes  # DER certificate (x509) or TBSCertificate (precert)


@dataclass(frozen=True)
class TiledLog:
    name: str
    monitoring_url: str  # ends with '/'

    def tile_url(self, index: int, width: int = TILE_WIDTH) -> str:
        return f"{self.monitoring_url}tile/data/{tile_path(index, width)}"

    @property
    def checkpoint_url(self) -> str:
        return f"{self.monitoring_url}checkpoint"


# ── Paths and checkpoints ──

def tile_path(index: int, width: int = TILE_WIDTH) -> str:
    """The tlog-tiles path of data tile `index`: three-digit groups, every
    group but the last prefixed with 'x' (1234067 → x001/x234/067, 67 →
    067); a partial tile of `width` < 256 entries appends '.p/<width>'."""
    if index < 0:
        raise ValueError("tile index must be >= 0")
    digits = str(index)
    groups: list[str] = []
    while len(digits) > 3:
        groups.insert(0, digits[-3:])
        digits = digits[:-3]
    groups.insert(0, digits.rjust(3, "0"))
    path = "/".join([f"x{g}" for g in groups[:-1]] + [groups[-1]])
    if width < TILE_WIDTH:
        path += f".p/{width}"
    return path


def parse_checkpoint(text: str) -> Checkpoint:
    """The signed note's first three lines: origin, tree size, root hash."""
    lines = (text or "").split("\n")
    if len(lines) < 3 or not lines[0] or not lines[1].isdigit():
        raise TileFormatError("checkpoint: expected '<origin>\\n<size>\\n<hash>'")
    return Checkpoint(origin=lines[0], size=int(lines[1]), root_hash=lines[2])


def tiles_covering(start: int, end: int) -> list[tuple[int, int]]:
    """(tile index, width) for the leaves in [start, end): full tiles, and
    a partial last tile when `end` is not on a 256 boundary — a partial
    tile is served only for the current tree size."""
    if end <= start:
        return []
    first, last = start // TILE_WIDTH, (end - 1) // TILE_WIDTH
    out = []
    for index in range(first, last + 1):
        width = TILE_WIDTH if (index + 1) * TILE_WIDTH <= end else end - index * TILE_WIDTH
        out.append((index, width))
    return out


# ── Tile framing ──

def _u(blob: bytes, pos: int, n: int) -> tuple[int, int]:
    if pos + n > len(blob):
        raise TileFormatError("tile: truncated integer")
    return int.from_bytes(blob[pos:pos + n], "big"), pos + n


def _opaque(blob: bytes, pos: int, length_bytes: int) -> tuple[bytes, int]:
    length, pos = _u(blob, pos, length_bytes)
    if pos + length > len(blob):
        raise TileFormatError("tile: truncated opaque")
    return blob[pos:pos + length], pos + length


def iter_leaves(blob: bytes) -> Iterator[TileLeaf]:
    """The TileLeaf records of one data tile, in order.

        timestamp(8) entry_type(2)
        x509:    certificate<1..2^24-1>
        precert: issuer_key_hash(32) tbs_certificate<1..2^24-1>
        extensions<0..2^16-1>
        precert: pre_certificate<1..2^24-1>
        certificate_chain<0..2^16-1>   (issuer fingerprints, 32 bytes each)

    Raises TileFormatError on a record that does not fit — a caller treats
    the whole tile as unreadable rather than trusting a half-parsed one.
    """
    pos = 0
    while pos < len(blob):
        timestamp, pos = _u(blob, pos, 8)
        entry_type, pos = _u(blob, pos, 2)
        if entry_type == X509_ENTRY:
            certificate, pos = _opaque(blob, pos, 3)
        elif entry_type == PRECERT_ENTRY:
            pos += 32  # issuer_key_hash
            certificate, pos = _opaque(blob, pos, 3)
        else:
            raise TileFormatError(f"tile: unknown entry type {entry_type}")
        _, pos = _opaque(blob, pos, 2)  # extensions
        if entry_type == PRECERT_ENTRY:
            _, pos = _opaque(blob, pos, 3)  # the precertificate itself
        _, pos = _opaque(blob, pos, 2)  # chain fingerprints
        yield TileLeaf(timestamp_ms=timestamp, entry_type=entry_type, certificate=certificate)


# ── Names out of DER ──

def _der_length(der: bytes, pos: int) -> tuple[int, int]:
    """(length, position of the content) for the length octets at `pos`."""
    if pos >= len(der):
        raise TileFormatError("der: truncated length")
    first = der[pos]
    if first < 0x80:
        return first, pos + 1
    n = first & 0x7F
    if n == 0 or n > 4 or pos + 1 + n > len(der):
        raise TileFormatError("der: bad length")
    return int.from_bytes(der[pos + 1:pos + 1 + n], "big"), pos + 1 + n


def _san_names_at(der: bytes, oid_pos: int) -> Optional[list[str]]:
    """dNSNames of a SubjectAltName extension whose OID starts at `oid_pos`,
    or None when the bytes there are not an extension after all."""
    try:
        pos = oid_pos + len(_OID_SAN)
        if der[pos] == _TAG_BOOLEAN:  # critical
            pos += 3
        if der[pos] != _TAG_OCTET_STRING:
            return None
        _, pos = _der_length(der, pos + 1)
        if der[pos] != _TAG_SEQUENCE:
            return None
        length, pos = _der_length(der, pos + 1)
        end = pos + length
        names: list[str] = []
        while pos < end:
            tag = der[pos]
            length, pos = _der_length(der, pos + 1)
            if tag == _TAG_DNS_NAME:
                names.append(der[pos:pos + length].decode("ascii", "replace"))
            pos += length
        return names
    except (IndexError, TileFormatError):
        return None


def _common_name(der: bytes) -> Optional[str]:
    pos = der.find(_OID_CN)
    while pos >= 0:
        try:
            tag_pos = pos + len(_OID_CN)
            if der[tag_pos] in _STRING_TAGS:
                length, start = _der_length(der, tag_pos + 1)
                return der[start:start + length].decode("utf-8", "replace")
        except (IndexError, TileFormatError):
            pass
        pos = der.find(_OID_CN, pos + 1)
    return None


def dns_names(der: bytes) -> list[str]:
    """Every dNSName of the certificate's SubjectAltName, in order; when it
    has none, its commonName if that looks like a host name. A certificate
    with a SAN but no dNSNames (IP-only) yields []."""
    pos = der.find(_OID_SAN)
    while pos >= 0:
        names = _san_names_at(der, pos)
        if names is not None:
            return names
        pos = der.find(_OID_SAN, pos + 1)
    cn = _common_name(der)
    return [cn] if cn and "." in cn and " " not in cn else []


def leaf_names(leaves: Iterable[TileLeaf]) -> Iterator[tuple[TileLeaf, str]]:
    """(leaf, name) for every name on every leaf's certificate."""
    for leaf in leaves:
        for name in dns_names(leaf.certificate):
            yield leaf, name


# ── Which logs, and fetching ──

def select_tiled_logs(log_list: dict, operators: Iterable[str] = DEFAULT_OPERATORS,
                      now: Optional[datetime] = None) -> list[TiledLog]:
    """The usable tiled logs of `operators` that can receive a certificate
    issued `now`, from a Google log_list.json v3 document.

    A log is sharded by the certificate's EXPIRY (notAfter), not by when it
    was issued: a 90-day certificate issued on 2026-10-05 expires in January
    and goes to the 2027h1 shard, not to 2026h2. So every shard whose
    interval overlaps (now, now + MAX_CERT_VALIDITY] is read. Measured
    2026-10-05: Sycamore2026h2 grew ~94k leaves an hour (short-lived
    certificates only), Sycamore2027h1 ~570k — reading the shard that covers
    `now` alone saw a seventh of Let's Encrypt's issuance. A shard whose
    interval has ended is not read; a new one is, with no code change."""
    wanted = {op.casefold() for op in operators}
    moment = now or datetime.now(timezone.utc)
    horizon = moment + MAX_CERT_VALIDITY
    out: list[TiledLog] = []
    for operator in log_list.get("operators", []):
        if str(operator.get("name", "")).casefold() not in wanted:
            continue
        for log in operator.get("tiled_logs", []):
            state = log.get("state") or {}
            if "usable" not in state:
                continue
            interval = log.get("temporal_interval") or {}
            try:
                start = datetime.fromisoformat(interval["start_inclusive"].replace("Z", "+00:00"))
                end = datetime.fromisoformat(interval["end_exclusive"].replace("Z", "+00:00"))
            except (KeyError, ValueError):
                continue
            url = str(log.get("monitoring_url", ""))
            if start <= horizon and end > moment and url.startswith("https://"):
                out.append(TiledLog(name=str(log.get("description", url)), monitoring_url=url.rstrip("/") + "/"))
    return out


def client() -> httpx.AsyncClient:
    """One client for a run. The CDN in front of Let's Encrypt's logs answers
    403 to Python's default User-Agent; a named one is also the polite
    thing for a reader that pulls a few hundred MB an hour."""
    return httpx.AsyncClient(timeout=TILE_TIMEOUT_S, headers={"User-Agent": USER_AGENT}, follow_redirects=True)


async def fetch_log_list(http: httpx.AsyncClient) -> Optional[dict]:
    try:
        resp = await http.get(LOG_LIST_URL, timeout=CHECKPOINT_TIMEOUT_S)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else None
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("ct log list unavailable: %s", exc)
        return None


async def fetch_checkpoint(http: httpx.AsyncClient, log: TiledLog) -> Optional[Checkpoint]:
    try:
        resp = await http.get(log.checkpoint_url, timeout=CHECKPOINT_TIMEOUT_S)
        resp.raise_for_status()
        return parse_checkpoint(resp.text)
    except (httpx.HTTPError, TileFormatError) as exc:
        logger.warning("ct checkpoint unavailable for %s: %s", log.name, exc)
        return None


async def fetch_tile(http: httpx.AsyncClient, log: TiledLog, index: int, width: int = TILE_WIDTH) -> Optional[bytes]:
    """The raw tile, or None when the log did not serve it (a partial tile
    that has since been completed answers 404 — the caller re-plans from a
    fresh checkpoint on the next run)."""
    try:
        resp = await http.get(log.tile_url(index, width))
        if resp.status_code != 200:
            logger.info("ct tile %s/%d.%d: HTTP %d", log.name, index, width, resp.status_code)
            return None
        return resp.content
    except httpx.HTTPError as exc:
        logger.warning("ct tile %s/%d: %s", log.name, index, exc)
        return None
