"""Client IP behind Cloudflare: client -> Cloudflare edge -> Railway edge -> app.

Cloudflare appends the address that connected to it to X-Forwarded-For and
sets CF-Connecting-IP; Railway's edge then appends the Cloudflare edge address
it saw. The app's TCP peer is Railway's edge (100.64.0.0/10). CF-Connecting-IP
is believed ONLY when the right-to-left X-Forwarded-For walk shows that the hop
in front of Railway's edge is a Cloudflare address — anyone can send the header
straight to the Railway origin.
"""
from __future__ import annotations

import ipaddress
import pathlib
import sys
from unittest.mock import MagicMock

import pytest

from api.services import proxy_trust
from api.services.rate_limiter import _extract_client_ip

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAILWAY_EDGE = "100.66.0.9"
CF_EDGE_V4 = "172.70.1.2"            # 172.64.0.0/13
CF_EDGE_V6 = "2a06:98c0:3600::103"   # 2a06:98c0::/29


@pytest.fixture(autouse=True)
def _clean():
    proxy_trust.reset_for_tests()
    yield
    proxy_trust.reset_for_tests()


@pytest.fixture
def trusted(monkeypatch):
    from api.config import get_settings

    def _set(value: str):
        monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", value)
    _set("100.64.0.0/10")
    return _set


def _req(xff=None, cf=None, peer=RAILWAY_EDGE):
    req = MagicMock()
    headers = {}
    if xff is not None:
        headers["x-forwarded-for"] = xff
    if cf is not None:
        headers["cf-connecting-ip"] = cf
    req.headers = headers
    req.client = MagicMock(host=peer) if peer else None
    return req


# ── Today: DNS-only, Railway's edge is the only proxy ──────────────────

def test_direct_request_is_unchanged(trusted):
    assert _extract_client_ip(_req("203.0.113.9")) == "203.0.113.9"
    assert proxy_trust.snapshot() == {"100.64.0.0/10|xff=1|trusted": 1}


# ── Through Cloudflare ─────────────────────────────────────────────────

def test_via_cloudflare_the_client_is_cf_connecting_ip(trusted):
    req = _req(f"198.51.100.7, {CF_EDGE_V4}", cf="198.51.100.7")
    assert _extract_client_ip(req) == "198.51.100.7"
    snap = proxy_trust.snapshot()
    assert snap["cloudflare|client=header"] == 1
    assert "198.51.100" not in repr(snap)


def test_via_cloudflare_a_prepended_xff_does_not_pick_the_key(trusted):
    # The client sent "X-Forwarded-For: 1.2.3.4"; Cloudflare appended the real
    # address, Railway appended the Cloudflare edge.
    req = _req(f"1.2.3.4, 198.51.100.7, {CF_EDGE_V4}", cf="198.51.100.7")
    assert _extract_client_ip(req) == "198.51.100.7"


def test_via_cloudflare_without_the_header_uses_the_address_cloudflare_appended(trusted):
    assert _extract_client_ip(_req(f"1.2.3.4, 198.51.100.7, {CF_EDGE_V4}")) == "198.51.100.7"
    assert proxy_trust.snapshot()["cloudflare|client=xff"] == 1


def test_via_cloudflare_a_garbage_header_falls_back_to_xff(trusted):
    req = _req(f"198.51.100.7, {CF_EDGE_V4}", cf="not-an-ip")
    assert _extract_client_ip(req) == "198.51.100.7"


def test_via_cloudflare_with_cloudflare_ranges_also_in_the_trust_list(trusted):
    # The older DoH runbook said to add Cloudflare's ranges to
    # TRUSTED_PROXY_CIDRS. Doing so must not change the answer.
    trusted("100.64.0.0/10,172.64.0.0/13")
    req = _req(f"6.6.6.6, 198.51.100.7, {CF_EDGE_V4}", cf="198.51.100.7")
    assert _extract_client_ip(req) == "198.51.100.7"


def test_only_one_cloudflare_hop_is_ever_skipped(trusted):
    # Left of the Cloudflare hop is what Cloudflare saw; anything further left
    # was written by the client, even when it looks like a Cloudflare address.
    xff = f"203.0.113.50, 104.16.0.1, {CF_EDGE_V4}"
    assert _extract_client_ip(_req(xff)) == "104.16.0.1"


# ── Spoofing: the header from anyone but Cloudflare is ignored ─────────

def test_spoofed_header_sent_straight_to_the_origin_is_ignored(trusted):
    # Attacker 203.0.113.9 calls the Railway origin directly, forging both
    # CF-Connecting-IP and a Cloudflare-looking X-Forwarded-For entry. Railway's
    # edge appends the attacker's real address, which the walk finds first.
    req = _req(f"{CF_EDGE_V4}, 203.0.113.9", cf="1.2.3.4")
    assert _extract_client_ip(req) == "203.0.113.9"
    snap = proxy_trust.snapshot()
    assert snap["cloudflare_header_ignored"] == 1
    assert "cloudflare|client=header" not in snap


def test_spoofed_header_from_an_untrusted_peer_is_ignored(trusted):
    req = _req(f"1.2.3.4, {CF_EDGE_V4}", cf="1.2.3.4", peer="203.0.113.9")
    assert _extract_client_ip(req) == "203.0.113.9"


def test_spoofed_header_without_any_xff_is_ignored(trusted):
    assert _extract_client_ip(_req(None, cf="1.2.3.4")) == RAILWAY_EDGE


def test_without_a_trust_list_the_header_is_never_read(trusted):
    # Dev/local keeps the legacy "leftmost XFF" behaviour.
    trusted("")
    assert _extract_client_ip(_req(f"203.0.113.5, {CF_EDGE_V4}", cf="1.2.3.4")) == "203.0.113.5"
    assert _extract_client_ip(_req(None, cf="1.2.3.4", peer="198.51.100.9")) == "198.51.100.9"


# ── IPv6 ───────────────────────────────────────────────────────────────

def test_ipv6_client_through_an_ipv4_cloudflare_edge(trusted):
    req = _req(f"2001:db8::42, {CF_EDGE_V4}", cf="2001:db8::42")
    assert _extract_client_ip(req) == "2001:db8::42"


def test_ipv6_cloudflare_edge(trusted):
    req = _req(f"198.51.100.7, {CF_EDGE_V6}", cf="198.51.100.7")
    assert _extract_client_ip(req) == "198.51.100.7"
    assert _extract_client_ip(_req(f"2001:db8::7, {CF_EDGE_V6}")) == "2001:db8::7"


def test_ipv6_header_is_normalised(trusted):
    req = _req(f"2001:db8::42, {CF_EDGE_V4}", cf=" 2001:DB8:0:0::42 ")
    assert _extract_client_ip(req) == "2001:db8::42"


def test_spoofed_header_from_an_ipv6_client_is_ignored(trusted):
    req = _req(f"{CF_EDGE_V6}, 2001:db8::bad", cf="2001:db8::1")
    assert _extract_client_ip(req) == "2001:db8::bad"


# ── Telemetry and the vendored ranges ──────────────────────────────────

def test_a_cloudflare_peer_is_bucketed_as_cloudflare():
    assert proxy_trust.peer_bucket(CF_EDGE_V4) == "cloudflare"
    assert proxy_trust.peer_bucket(CF_EDGE_V6) == "cloudflare"
    assert proxy_trust.peer_bucket("100.64.12.7") == "100.64.0.0/10"


def test_is_cloudflare():
    assert proxy_trust.is_cloudflare("104.16.0.1")
    assert proxy_trust.is_cloudflare("[2606:4700::1]")
    assert not proxy_trust.is_cloudflare("100.64.0.1")
    assert not proxy_trust.is_cloudflare("203.0.113.9")
    assert not proxy_trust.is_cloudflare("not-an-ip")
    assert not proxy_trust.is_cloudflare("")


def test_vendored_cloudflare_ranges_parse():
    nets = proxy_trust.cloudflare_networks()
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    assert len(v4) >= 10 and len(v6) >= 5
    assert ipaddress.ip_network("104.16.0.0/13") in nets
    assert ipaddress.ip_network("2606:4700::/32") in nets
    railway = ipaddress.ip_network("100.64.0.0/10")
    for net in nets:
        assert net.is_global, net
        assert not (net.version == 4 and net.overlaps(railway)), net


def test_refresh_script_renders_what_the_service_parses(tmp_path):
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_cloudflare_ips as refresh

    v4 = refresh.parse_ranges("173.245.48.0/20\n104.16.0.0/13\n", 4)
    v6 = refresh.parse_ranges("2400:cb00::/32\n", 6)
    out = tmp_path / "cf.txt"
    out.write_text(refresh.render(v4, v6))
    nets = proxy_trust.load_networks(out)
    assert [str(n) for n in nets] == ["173.245.48.0/20", "104.16.0.0/13", "2400:cb00::/32"]


@pytest.mark.parametrize("text,version", [
    ("<html>blocked</html>", 4),
    ("", 4),
    ("10.0.0.0/8\n", 4),          # never trust a private range
    ("2400:cb00::/32\n", 4),      # wrong family
    ("104.16.0.0/13\n", 6),
])
def test_refresh_script_refuses_bad_downloads(text, version):
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    import refresh_cloudflare_ips as refresh

    with pytest.raises(ValueError):
        refresh.parse_ranges(text, version)
