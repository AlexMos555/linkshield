"""The brand-owned false-positive sweep must not mistake a cloaker for a brand.

2026-09-19: www.roblox.com.hr, roblox.com.hr and www.roblox.ly were reported
as Roblox's own defensive registrations because `/` answers 302 to
https://www.roblox.com. They are not. Both zones sit on one Cloudflare
account (rory/raphaela) and one German VPS, roblox.ly was registered
2026-07-14 by a private person, roblox.com.hr on 2026-08-21 — and
/users/<id>/profile is served by the host itself (403) instead of
redirecting: the fake-profile phishing kit, with the root bounced to the real
site so a reviewer sees Roblox. Roblox's real ccTLDs (roblox.de, roblox.fr,
roblox.jp …) sit on Roblox's own nameservers (nspx*.roblox.*) or MarkMonitor.

So a redirect to the brand is NOT proof of ownership — any phisher can send
`/` to the real site. The sweep calls a host brand-owned only when the
redirect lands on the brand AND the zone's DNS is the brand's (shared
nameservers with the brand's apex, or a corporate brand-protection
registrar). Everything else that redirects to the brand is reported as a
cloaking suspect and is never a veto candidate.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_SCRIPT = ROOT / "scripts" / "sweep_brand_owned_fps.py"
_spec = importlib.util.spec_from_file_location("sweep_brand_owned_fps", _SCRIPT)
sweep = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep)  # type: ignore[union-attr]

from api.services.blocklist_artifact import name_hash  # noqa: E402

ROBLOX_NS = frozenset({"nspx1.roblox.com", "nspx2.roblox.net", "nspx3.roblox.us", "nspx4.roblox.co.uk"})
CLOUDFLARE_PAIR = frozenset({"rory.ns.cloudflare.com", "raphaela.ns.cloudflare.com"})


def test_brand_apexes_cover_keys_and_the_apex_label():
    apexes = sweep.brand_apexes({"roblox": "roblox.com", "steam": "store.steampowered.com",
                                 "barclays": "barclays.co.uk"})
    assert apexes["roblox"] == "roblox.com"
    assert apexes["steam"] == "steampowered.com"
    assert apexes["steampowered"] == "steampowered.com"  # the apex's own label is a brand name too
    assert apexes["barclays"] == "barclays.co.uk"


def test_candidates_cover_every_shape_for_every_cctld():
    got = set(sweep.candidates({"roblox": "roblox.com"}, ("hr", "ly")))
    assert {"roblox.hr", "www.roblox.hr", "roblox.com.hr", "www.roblox.com.hr", "roblox.co.hr",
            "roblox.ly", "www.roblox.ly", "roblox.com.ly", "www.roblox.com.ly", "roblox.co.ly"} == {c.host for c in got}
    assert all(c.apex == "roblox.com" and c.label == "roblox" for c in got)


def test_the_default_cctld_list_is_broad():
    for cc in ("hr", "ly", "bn", "et", "am", "bi", "mu", "ru", "de", "br", "uk", "us", "io", "cc"):
        assert cc in sweep.CCTLDS, cc


def test_covering_name_is_the_most_specific_listed_name():
    hashes = {name_hash("roblox.com.hr"), name_hash("co.pt")}
    assert sweep.covering_name(hashes, "www.roblox.com.hr") == "roblox.com.hr"
    assert sweep.covering_name(hashes, "roblox.co.pt") == "co.pt"
    assert sweep.covering_name(hashes, "roblox.de") is None


def test_a_generic_parent_is_not_a_brand_listing():
    # Every <brand>.co.pt is covered because co.pt itself is listed: vetoing
    # roblox.co.pt would change nothing, and the host is not the brand's.
    assert not sweep.is_brand_listing("co.pt", "roblox")
    assert sweep.is_brand_listing("roblox.com.hr", "roblox")
    assert sweep.is_brand_listing("www.roblox.ly", "roblox")


def test_lands_on_brand_is_exact_apex_or_subdomain_only():
    assert sweep.lands_on_brand("www.roblox.com", "roblox.com")
    assert sweep.lands_on_brand("roblox.com", "roblox.com")
    assert not sweep.lands_on_brand("roblox.com.evil.xyz", "roblox.com")
    assert not sweep.lands_on_brand("notroblox.com", "roblox.com")
    assert not sweep.lands_on_brand(None, "roblox.com")


def test_the_roblox_cloakers_are_not_brand_owned():
    # Observed 2026-09-19: / → 302 https://www.roblox.com/, zone on a Cloudflare pair Roblox does not use.
    got = sweep.verdict("www.roblox.com", None, CLOUDFLARE_PAIR, "roblox.com", ROBLOX_NS)
    assert got == sweep.CLOAKING_SUSPECT


def test_a_redirect_on_the_brands_own_nameservers_is_brand_owned():
    # roblox.de: / → https://www.roblox.com/de, NS nspx*.roblox.*
    assert sweep.verdict("www.roblox.com", None, ROBLOX_NS, "roblox.com", ROBLOX_NS) == sweep.BRAND_OWNED


def test_a_redirect_from_a_brand_protection_registrar_is_brand_owned():
    markmonitor = frozenset({"ns1.markmonitor.com", "ns2.markmonitor.com"})
    assert sweep.verdict("www.roblox.com", None, markmonitor, "roblox.com", ROBLOX_NS) == sweep.BRAND_OWNED


def test_brand_dns_without_a_redirect_is_flagged_for_review_not_confirmed():
    # americanexpress.io (2026-09-19): Amex's own tech blog — no redirect, but
    # the zone's nameservers ARE americanexpress.com's and WHOIS names Amex.
    # One signal is not proof; a human checks the registrant before listing it.
    amex_ns = frozenset({"a1-196.akam.net", "a13-65.akam.net"})
    got = sweep.verdict("americanexpress.io", None, amex_ns, "americanexpress.com", amex_ns)
    assert got == sweep.BRAND_DNS_REVIEW
    markmonitor = frozenset({"ns1.markmonitor.com"})
    assert sweep.verdict("roblox.com.br", None, markmonitor, "roblox.com", ROBLOX_NS) == sweep.BRAND_DNS_REVIEW


def test_landing_elsewhere_or_unreachable():
    assert sweep.verdict("parking.example", None, CLOUDFLARE_PAIR, "roblox.com", ROBLOX_NS) == sweep.NOT_BRAND
    assert sweep.verdict(None, "ConnectError", frozenset(), "roblox.com", ROBLOX_NS) == sweep.UNREACHABLE


def test_zone_of_a_candidate_drops_the_www_label():
    assert sweep.zone_of("www.roblox.com.hr") == "roblox.com.hr"
    assert sweep.zone_of("roblox.ly") == "roblox.ly"
