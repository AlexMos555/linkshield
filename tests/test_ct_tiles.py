"""ct_tiles: reading Certificate Transparency the static-ct-api way.

The fixtures in tests/data/ct were recorded from Let's Encrypt
'Sycamore2026h2' on 2026-10-05 (scratch recorder, no network in the tests):

  sycamore2026h2_leaves.bin       five whole TileLeaf records of data tile
                                  3881873 — three precertificates, two
                                  certificates, in log order
  sycamore2026h2_checkpoint.txt   the log's checkpoint (signed note)
  log_list_letsencrypt.json       the Let's Encrypt part of Google's log
                                  list v3, the fields select_tiled_logs reads

The certificate names in them are corporate canaries and wildcard
certificates, public CT data like every other name in the log.
"""
from __future__ import annotations

import asyncio
import json
import pathlib
from datetime import datetime, timezone

import pytest

from api.services import ct_tiles

DATA = pathlib.Path(__file__).parent / "data" / "ct"
LEAVES = (DATA / "sycamore2026h2_leaves.bin").read_bytes()
CHECKPOINT = (DATA / "sycamore2026h2_checkpoint.txt").read_text()
LOG_LIST = json.loads((DATA / "log_list_letsencrypt.json").read_text())


# ── Synthetic DER and tile records (for names the recorded tile lacks) ──

def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def san_extension(*names: str, critical: bool = False) -> bytes:
    general_names = b"".join(_der(0x82, n.encode("ascii")) for n in names)
    body = bytes.fromhex("0603551d11")
    if critical:
        body += bytes.fromhex("0101ff")
    return _der(0x30, body + _der(0x04, _der(0x30, general_names)))


def common_name(cn: str) -> bytes:
    return _der(0x30, bytes.fromhex("0603550403") + _der(0x0C, cn.encode("utf-8")))


def tbs(*parts: bytes) -> bytes:
    """Enough of a TBSCertificate for the name walk: a version, a serial,
    whatever subject/extension parts the test passes."""
    return _der(0x30, _der(0xA0, _der(0x02, b"\x02")) + _der(0x02, b"\x01\x23") + b"".join(parts))


def x509_record(cert: bytes, timestamp_ms: int = 1_791_191_640_606) -> bytes:
    return (timestamp_ms.to_bytes(8, "big") + (0).to_bytes(2, "big")
            + len(cert).to_bytes(3, "big") + cert
            + (0).to_bytes(2, "big")                      # extensions
            + (32).to_bytes(2, "big") + b"\x11" * 32)     # one chain fingerprint


def precert_record(tbs_cert: bytes, timestamp_ms: int = 1_791_191_640_606) -> bytes:
    pre = _der(0x30, tbs_cert)
    return (timestamp_ms.to_bytes(8, "big") + (1).to_bytes(2, "big") + b"\x22" * 32
            + len(tbs_cert).to_bytes(3, "big") + tbs_cert
            + (0).to_bytes(2, "big")
            + len(pre).to_bytes(3, "big") + pre
            + (0).to_bytes(2, "big"))


# ── Paths and checkpoints ──

@pytest.mark.parametrize("index, width, path", [
    (0, 256, "000"), (67, 256, "067"), (1234, 256, "x001/234"),
    (1234067, 256, "x001/x234/067"), (3881873, 256, "x003/x881/873"),
    (67, 13, "067.p/13"),
])
def test_tile_path_follows_tlog_tiles(index, width, path):
    assert ct_tiles.tile_path(index, width) == path


def test_tile_path_rejects_a_negative_index():
    with pytest.raises(ValueError):
        ct_tiles.tile_path(-1)


def test_the_recorded_checkpoint_parses():
    cp = ct_tiles.parse_checkpoint(CHECKPOINT)
    assert cp.origin == "log.sycamore.ct.letsencrypt.org/2026h2"
    assert cp.size == 993_762_193
    assert cp.root_hash == "jyxwm4JET2jNrW59hVnazZGuk37PoZhPzWdyalFptVI="


@pytest.mark.parametrize("text", ["", "origin\n", "origin\nnot-a-number\nhash\n", "\n12\nhash\n"])
def test_a_malformed_checkpoint_is_refused(text):
    with pytest.raises(ct_tiles.TileFormatError):
        ct_tiles.parse_checkpoint(text)


def test_tiles_covering_full_and_partial_tiles():
    assert ct_tiles.tiles_covering(0, 256) == [(0, 256)]
    assert ct_tiles.tiles_covering(100, 600) == [(0, 256), (1, 256), (2, 88)]
    assert ct_tiles.tiles_covering(512, 512) == []
    assert ct_tiles.tiles_covering(600, 100) == []


def test_tile_urls_use_the_monitoring_prefix():
    log = ct_tiles.TiledLog("Sycamore", "https://mon.sycamore.ct.letsencrypt.org/2026h2/")
    assert log.checkpoint_url == "https://mon.sycamore.ct.letsencrypt.org/2026h2/checkpoint"
    assert log.tile_url(3881873) == "https://mon.sycamore.ct.letsencrypt.org/2026h2/tile/data/x003/x881/873"
    assert log.tile_url(2, 88).endswith("/tile/data/002.p/88")


# ── The recorded tile ──

def test_the_recorded_leaves_parse_with_their_entry_types_and_times():
    leaves = list(ct_tiles.iter_leaves(LEAVES))
    assert [leaf.entry_type for leaf in leaves] == [1, 1, 1, 0, 0]
    assert [leaf.timestamp_ms for leaf in leaves] == [
        1_791_191_639_606, 1_791_191_640_606, 1_791_191_640_606, 1_791_191_640_606, 1_791_191_640_606]
    # A precertificate yields its TBSCertificate, a certificate its DER.
    assert all(leaf.certificate[0] == 0x30 for leaf in leaves)


def test_the_recorded_leaves_yield_their_san_names():
    names = [ct_tiles.dns_names(leaf.certificate) for leaf in ct_tiles.iter_leaves(LEAVES)]
    assert names == [
        ["998c28c1d6f1791191553113.akl.prod.canaries.quickbeam.acm.aws.dev",
         "san0.998c28c1d6f1791191553113.akl.prod.canaries.quickbeam.acm.aws.dev"],
        ["udkzS.carrs.canary.test.sfdc.net"],
        ["uuid65pej1.urawatchdog.sfdc.net"],
        ["*.xfpgmur-xyb21941.us-west-2.aws.privatelink.snowflake.app",
         "*.xfpgmur-xyb21941.us-west-2.aws.snowflake.app"],
        ["*.heobklh-vfa95340.eastus2.azure.privatelink.snowflake.app",
         "*.heobklh-vfa95340.eastus2.azure.snowflake.app"],
    ]
    pairs = list(ct_tiles.leaf_names(ct_tiles.iter_leaves(LEAVES)))
    assert len(pairs) == 8


@pytest.mark.parametrize("cut", [1, 9, 40, 1911 + 5, len(LEAVES) - 1])
def test_a_truncated_tile_is_unreadable_not_half_parsed(cut):
    with pytest.raises(ct_tiles.TileFormatError):
        list(ct_tiles.iter_leaves(LEAVES[:cut]))


def test_an_unknown_entry_type_is_unreadable():
    record = bytearray(x509_record(tbs(san_extension("example.com"))))
    record[8:10] = (7).to_bytes(2, "big")
    with pytest.raises(ct_tiles.TileFormatError):
        list(ct_tiles.iter_leaves(bytes(record)))


# ── Names out of DER ──

def test_synthetic_records_of_both_kinds_round_trip():
    blob = (precert_record(tbs(san_extension("sberbank-bonus.ru", "www.sberbank-bonus.ru")))
            + x509_record(tbs(san_extension("xn----etbaulcdt1aavc.xn--p1ai", critical=True))))
    leaves = list(ct_tiles.iter_leaves(blob))
    assert [leaf.entry_type for leaf in leaves] == [ct_tiles.PRECERT_ENTRY, ct_tiles.X509_ENTRY]
    assert [ct_tiles.dns_names(leaf.certificate) for leaf in leaves] == [
        ["sberbank-bonus.ru", "www.sberbank-bonus.ru"], ["xn----etbaulcdt1aavc.xn--p1ai"]]


def test_a_long_san_uses_long_form_lengths():
    names = [f"host{i}.sberbank-bonus.ru" for i in range(40)]
    assert ct_tiles.dns_names(tbs(san_extension(*names))) == names


def test_without_a_san_the_common_name_is_used_when_it_is_a_host():
    assert ct_tiles.dns_names(tbs(common_name("gosuslugi-lk.help"))) == ["gosuslugi-lk.help"]
    assert ct_tiles.dns_names(tbs(common_name("Some Organisation"))) == []
    assert ct_tiles.dns_names(tbs()) == []


def test_a_san_without_dns_names_yields_nothing_not_the_cn():
    ip_only = _der(0x30, bytes.fromhex("0603551d11") + _der(0x04, _der(0x30, _der(0x87, b"\x7f\x00\x00\x01"))))
    assert ct_tiles.dns_names(tbs(common_name("cn.example.com"), ip_only)) == []


def test_oid_bytes_inside_other_data_are_not_taken_for_the_extension():
    decoy = _der(0x04, bytes.fromhex("0603551d11") + b"\xff\xff")
    assert ct_tiles.dns_names(tbs(decoy, san_extension("ozon-priz.com"))) == ["ozon-priz.com"]


# ── Which logs ──

def test_every_shard_a_certificate_issued_now_can_land_in_is_selected():
    # Shards split by EXPIRY: today's 90-day certificates go to 2027h1, which
    # took ~570k leaves an hour on 2026-10-05 against 2026h2's ~94k.
    on = datetime(2026, 10, 5, tzinfo=timezone.utc)
    logs = ct_tiles.select_tiled_logs(LOG_LIST, now=on)
    assert [log.name for log in logs] == [
        "Let's Encrypt 'Sycamore2026h2'", "Let's Encrypt 'Sycamore2027h1'", "Let's Encrypt 'Sycamore2027h2'",
        "Let's Encrypt 'Willow2026h2'", "Let's Encrypt 'Willow2027h1'", "Let's Encrypt 'Willow2027h2'"]
    assert all(log.monitoring_url.endswith("/") for log in logs)


def test_a_shard_roll_over_needs_no_deploy():
    after = datetime(2027, 1, 2, tzinfo=timezone.utc)
    names = [log.name for log in ct_tiles.select_tiled_logs(LOG_LIST, now=after)]
    assert names == ["Let's Encrypt 'Sycamore2027h1'", "Let's Encrypt 'Sycamore2027h2'",
                     "Let's Encrypt 'Willow2027h1'", "Let's Encrypt 'Willow2027h2'"]


def test_a_shard_beyond_the_longest_certificate_is_not_read_yet():
    # 2027h2 starts 2027-06-18: out of reach of a 398-day certificate issued
    # before 2026-05-16.
    early = datetime(2026, 5, 1, tzinfo=timezone.utc)
    names = [log.name for log in ct_tiles.select_tiled_logs(LOG_LIST, now=early)]
    assert "Let's Encrypt 'Sycamore2027h2'" not in names
    assert "Let's Encrypt 'Sycamore2027h1'" in names


def test_other_operators_and_unusable_logs_are_not_selected():
    on = datetime(2026, 10, 5, tzinfo=timezone.utc)
    assert ct_tiles.select_tiled_logs(LOG_LIST, operators=("Google",), now=on) == []
    retired = json.loads(json.dumps(LOG_LIST))
    for log in retired["operators"][0]["tiled_logs"]:
        log["state"] = {"retired": {"timestamp": "2026-09-01T00:00:00Z"}}
    assert ct_tiles.select_tiled_logs(retired, now=on) == []
    assert ct_tiles.select_tiled_logs({}, now=on) == []


# ── Fetching (no network: a transport that serves the fixtures) ──

def _http(routes: dict):
    import httpx

    def handler(request):
        body = routes.get(str(request.url))
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, content=body if isinstance(body, bytes) else body.encode())

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_checkpoint_and_tile_fetch_against_recorded_bodies():
    log = ct_tiles.TiledLog("Sycamore", "https://mon.sycamore.ct.letsencrypt.org/2026h2/")

    async def go():
        async with _http({log.checkpoint_url: CHECKPOINT, log.tile_url(5): LEAVES}) as http:
            cp = await ct_tiles.fetch_checkpoint(http, log)
            tile = await ct_tiles.fetch_tile(http, log, 5)
            missing = await ct_tiles.fetch_tile(http, log, 6)
        return cp, tile, missing

    cp, tile, missing = asyncio.run(go())
    assert cp.size == 993_762_193
    assert tile == LEAVES
    assert missing is None  # e.g. a partial tile completed since: re-planned next run
