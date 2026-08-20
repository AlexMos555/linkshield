"""build_blockset() must never darken a shared or popular host.

2026-08-18: production /dns-query returned NXDOMAIN for github.com,
www.github.com, api.github.com and raw.githubusercontent.com — every GitHub
subdomain, for everyone using our DNS profile. URLhaus lists 869 malware URLs
hosted ON github.com; the script added the exact host unconditionally
(`out.add(h)`) and only guarded the *registrable promotion*, while the DoH
gateway also matches on the registrable base — so `github.com` in the set
blocked all of GitHub. Also darkened: zapier.app, od.lk, acusense.ae,
adclick.g.doubleclick.net, attach.mail.daum.net, 0zz0.com.

Rules pinned here (see build_blockset docstring):
  * hostnames that are path-shared by everyone (raw.githubusercontent.com,
    drive.google.com, storage.googleapis.com …) are never added;
  * a hostname whose registrable is popular (top-100k, or Tranco-1M via the
    optional rank lookup) is added ONLY if it sits under a shared suffix
    (github.io, blogspot.com, us.org, blob.core.windows.net …) — i.e. it is
    one tenant's site — and even then not when the feed shows many URLs on
    that one host (a shared host, not a tenant);
  * dedicated phishing domains get the exact host AND the registrable.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "refresh_dangerous_domains.py"
_spec = importlib.util.spec_from_file_location("refresh_dangerous_domains", _SCRIPT)
rdd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rdd)  # type: ignore[union-attr]

TOP = {"github.com", "githubusercontent.com", "googleapis.com", "google.com", "daum.net",
       "doubleclick.net", "windows.net", "bounceme.net", "us.org", "blogspot.com", "github.io",
       "zapier.app"}
SHARED = {"github.io", "blogspot.com", "us.org", "bounceme.net", "blob.core.windows.net",
          "githubusercontent.com", "googleapis.com"}


def _build(hosts, popular=None):
    return rdd.build_blockset(hosts, TOP, shared_suffixes=SHARED, is_popular=popular)


def test_github_com_is_never_added_even_with_hundreds_of_urls():
    hosts = ["github.com"] * 869 + ["www.github.com", "api.github.com"]
    out = _build(hosts)
    assert "github.com" not in out
    assert "www.github.com" not in out
    assert "api.github.com" not in out


def test_path_shared_hosts_are_never_added():
    for h in ["raw.githubusercontent.com", "gist.githubusercontent.com", "storage.googleapis.com",
              "drive.google.com", "docs.google.com", "sites.google.com", "cdn.discordapp.com",
              "s3.amazonaws.com"]:
        assert h not in _build([h] * 3), h


def test_popular_org_subdomains_are_skipped():
    out = _build(["attach.mail.daum.net", "adclick.g.doubleclick.net"])
    assert out == set()


def test_tenant_site_on_shared_platform_is_blocked_exactly_not_the_platform():
    out = _build(["evil-login.github.io", "secure.bounceme.net", "gwcu.us.org",
                  "mystore.blob.core.windows.net"])
    assert {"evil-login.github.io", "secure.bounceme.net", "gwcu.us.org",
            "mystore.blob.core.windows.net"} <= out
    for platform in ["github.io", "bounceme.net", "us.org", "blob.core.windows.net", "windows.net"]:
        assert platform not in out, platform


def test_shared_platform_apex_itself_is_never_added():
    assert _build(["github.io", "blogspot.com", "us.org"]) == set()


def test_many_urls_on_one_host_under_shared_suffix_means_shared_host_not_tenant():
    # 40 malware URLs on one hostname under githubusercontent.com: that is a
    # shared host (everyone's raw files), not one tenant's site.
    out = _build(["files.githubusercontent.com"] * (rdd.SHARED_URL_THRESHOLD + 5))
    assert "files.githubusercontent.com" not in out
    # …whereas a couple of URLs on a tenant site is the normal phishing shape.
    assert "evil.github.io" in _build(["evil.github.io"] * 2)


def test_dedicated_phishing_domain_blocks_host_and_registrable():
    out = _build(["www.paypal-security.891374.cfd", "login.scotiabano.com"])
    # registrable of www.paypal-security.891374.cfd is 891374.cfd (the
    # brand-looking label is a subdomain) — block host + registrable.
    assert {"www.paypal-security.891374.cfd", "891374.cfd",
            "login.scotiabano.com", "scotiabano.com"} <= out


def test_compound_tld_registrable_is_three_labels_heuristic():
    # No PSL available: the ccTLD heuristic must still refuse to promote com.am
    # (that promotion was LIVE in prod: every Armenian .com.am darkened).
    out = _build(["www.roblox.com.am", "beryl-bet365.com.cn", "roblox.com.ee"])
    assert {"roblox.com.am", "beryl-bet365.com.cn"} <= out
    for suffix in ["com.am", "com.cn", "com.ee"]:
        assert suffix not in out, suffix


def test_psl_registrable_and_never_promote_a_public_suffix():
    psl = {"com", "am", "com.am", "cfd", "io", "github.io", "uk", "co.uk", "*.ck", "ee", "com.ee"}
    out = rdd.build_blockset(["www.roblox.com.am", "evil.github.io", "a.b.co.uk", "x.www.ck", "roblox.com.ee"],
                             TOP, shared_suffixes=SHARED, public_suffixes=psl)
    assert "roblox.com.am" in out and "com.am" not in out
    assert "evil.github.io" in out and "github.io" not in out
    assert "b.co.uk" in out and "co.uk" not in out
    assert "x.www.ck" in out and "www.ck" not in out  # wildcard rule *.ck
    assert "roblox.com.ee" in out and "com.ee" not in out
    # PSL parsing keeps wildcards, drops exceptions and comments.
    assert rdd.parse_psl("// c\n*.ck\n!www.ck\n\nCOM.AM\n") == {"*.ck", "com.am"}


def test_optional_popularity_lookup_guards_tranco_1m_hosts():
    # 0zz0.com is a real file host (Tranco ~1M) that URLhaus lists malware on;
    # with a rank lookup it must not be blocked wholesale.
    def popular(d: str) -> bool:
        return d == "0zz0.com"
    out = _build(["0zz0.com", "www.0zz0.com"], popular=popular)
    assert "0zz0.com" not in out
    assert "www.0zz0.com" not in out


def test_verified_legit_shared_tenant_is_never_blocked():
    """A legit brand page on an org-scoped platform (metamask.github.io — the
    real MetaMask GitHub Pages, which a phisher cannot create because they do
    not own the "metamask" GitHub org) is false-flagged by OpenPhish's crypto
    heuristics. A curated allowlist skips it — the on-device escape hatch is
    not enough, since a MetaMask user hitting "site can't be reached" won't
    know to un-block it. Zero miss cost: only exact verified hosts are listed."""
    out = rdd.build_blockset(["metamask.github.io"] * 3, TOP, shared_suffixes=SHARED)
    assert "metamask.github.io" not in out
    # A brand-plus-tokens lookalike on the same platform is STILL blocked —
    # the allowlist is exact hosts, not brand substrings.
    out2 = rdd.build_blockset(["metamask-wallet-verify.github.io"], TOP, shared_suffixes=SHARED)
    assert "metamask-wallet-verify.github.io" in out2


def test_ip_literals_are_skipped():
    assert _build(["1.2.3.4", "10.0.0.1"]) == set()


# ─────────────────────────────────────────────────────────────────
# Publish gates — abort and keep the previous set rather than publish junk
# ─────────────────────────────────────────────────────────────────

def test_publish_gate_rejects_too_small_and_too_large():
    ok, why = rdd.publish_gate(set(f"d{i}.example" for i in range(10)), previous=None, popular=set(), shared=set())
    assert not ok and "small" in why
    huge = {f"d{i}.example" for i in range(rdd.MAX_ENTRIES + 1)}
    ok, why = rdd.publish_gate(huge, previous=None, popular=set(), shared=set())
    assert not ok and "large" in why


def test_publish_gate_rejects_popular_or_shared_intersection():
    names = {f"d{i}.example" for i in range(400)} | {"github.com"}
    ok, why = rdd.publish_gate(names, previous=None, popular={"github.com"}, shared=set())
    assert not ok and "github.com" in why
    names = {f"d{i}.example" for i in range(400)} | {"us.org"}
    ok, why = rdd.publish_gate(names, previous=None, popular=set(), shared={"us.org"})
    assert not ok and "us.org" in why


def test_publish_gate_rejects_excessive_churn_unless_forced():
    prev = {f"old{i}.example" for i in range(400)}
    new = {f"new{i}.example" for i in range(400)}
    ok, why = rdd.publish_gate(new, previous=prev, popular=set(), shared=set())
    assert not ok and "churn" in why
    ok, _ = rdd.publish_gate(new, previous=prev, popular=set(), shared=set(), force=True)
    assert ok


def test_publish_gate_accepts_normal_refresh():
    prev = {f"d{i}.example" for i in range(400)}
    new = prev - {"d1.example", "d2.example"} | {"fresh.example"}
    ok, why = rdd.publish_gate(new, previous=prev, popular={"github.com"}, shared={"us.org"})
    assert ok, why


# ─────────────────────────────────────────────────────────────────
# 2026-08-19: live false positives + gate bypasses found by the
# adversarial review of the shipped stack
# ─────────────────────────────────────────────────────────────────

def test_operator_infrastructure_is_never_blocked():
    """media.githubusercontent.com was NXDOMAIN in production: one URLhaus
    entry, and the tenant rule treated GitHub's own media CDN as "one
    tenant's site". There are no tenants under an operator suffix."""
    out = rdd.build_blockset(
        ["media.githubusercontent.com", "release-assets.githubusercontent.com",
         "lh3.googleusercontent.com", "storage.googleapis.com", "x.oaiusercontent.com"],
        TOP, shared_suffixes=SHARED | {"githubusercontent.com", "googleusercontent.com", "googleapis.com"},
    )
    assert out == set()
    # …and the operator suffixes are not tenant suffixes to begin with.
    assert rdd.OPERATOR_SUFFIXES & rdd.default_shared_suffixes() == set()


def test_a_ranked_tenant_site_is_not_blocked():
    """A tenant host people actually use (Tranco-ranked) is not one scammer's
    page; a single feed entry must not darken it."""
    def popular(d: str) -> bool:
        return d in {"docs.example.github.io", "github.io"}
    out = rdd.build_blockset(["docs.example.github.io", "scam.github.io"], TOP,
                             shared_suffixes=SHARED, is_popular=popular)
    assert "docs.example.github.io" not in out
    assert "scam.github.io" in out


def test_trailing_dot_hosts_are_normalised_before_every_guard():
    """'example.com.' kept its dot through build_blockset, the publish gate and
    the SADD, and only lost it in the renderer: the registrable became 'com.'
    (a bare TLD) and 'blogspot.com.' slipped past the shared-apex guard."""
    out = _build(["Evil-Shop.com.", "blogspot.com.", "gwcu.us.org."])
    assert "evil-shop.com" in out
    assert "com" not in out and "com." not in out
    assert "blogspot.com" not in out and "blogspot.com." not in out
    assert "gwcu.us.org" in out
    assert all(n == n.strip().lower().rstrip(".") for n in out)


@pytest.mark.asyncio
async def test_publish_is_refused_when_the_public_suffix_list_is_unavailable(monkeypatch):
    """Without the PSL the fallback heuristic promotes public suffixes
    (pe.kr, blog.br …) into the blocklist — a whole national zone dark on
    every phone. Keeping the previous set is the cheaper mistake."""
    async def _no_psl():
        return None

    monkeypatch.setattr(rdd, "_fetch_psl", _no_psl)

    async def _fetch(url):
        if "urlhaus" in url:
            return "\n".join(f'"{i}","d","https://ojang.pe.kr/x{i}"' for i in range(5))
        return "https://phish.example/a"

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    code = await rdd.refresh("redis://unused", dry_run=False)
    assert code == 4
