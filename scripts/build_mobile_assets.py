#!/usr/bin/env python3
"""Build the Android VPN module's bundled assets from data/.

  mobile/modules/cleanway-vpn/android/src/main/assets/popular_veto.txt
    The top-10k (data/top_10k.json: Majestic Million + Chrome UX Report,
    scripts/build_top_domains.py; Tranco's until 2026-10-23) PLUS the
    names of that rank a phishing feed reports (data/top_domains_reported.json,
    kept off the allowlist, not off the veto) PLUS the
    hand-curated internet infrastructure (data/infrastructure_domains.txt:
    DNS, CDN, OCSP, push and update names that no link- or visit-based
    list ranks) MINUS public suffixes / shared platforms, operators' own
    suffixes excepted. The phone's BlockList refuses to block any listed
    name whose registrable is here — a last line of defence against a bad
    publish. Public suffixes are removed on purpose: `github.io` is top-10k,
    but `evil.github.io` is one tenant's site and MUST stay blockable.

  mobile/modules/cleanway-vpn/android/src/main/assets/shared_suffixes.txt
    The publisher's shared suffixes (scripts/blocklist_shared_zones.py):
    a listed name under one is one tenant's site, and the veto above does not
    apply to it (evil-login.tilda.ws is blockable, tilda.ws is not). Then, as
    '!' lines, the platforms' own names under them, each with every name
    under it (!login.secureserver.net, !prod.iad2.secureserver.net,
    !app.netlify.com): not a tenant's, so the veto does apply, as it does to
    www.<suffix> (BlockList.isPlatformOwn). The publisher never lists them.

  mobile/modules/cleanway-vpn/android/src/main/assets/root_zone_tlds.txt
    Every TLD in the IANA root zone (data/iana_tlds.txt, a verbatim copy of
    https://data.iana.org/TLD/tlds-alpha-by-domain.txt), lowercased, with each
    IDN TLD also written in Unicode (xn--p1ai AND рф) because an SMS carries
    the Unicode form. The message check's LinkExtractor accepts a link written
    without http:// only when it ends in one of these. Refresh: download the
    IANA file over data/iana_tlds.txt, then rebuild.

popular_veto.txt and shared_suffixes.txt are adapted from the ranking and
start with its CC BY attribution ('# ' lines, from data/top_domains_sources.json).

Usage: python3 scripts/build_mobile_assets.py [--check]
"""
from __future__ import annotations

import codecs
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from blocklist_shared_zones import OPERATOR_SUFFIXES, default_shared_suffixes, platform_own_names  # noqa: E402

TOP10K = ROOT / "data" / "top_10k.json"
REPORTED = ROOT / "data" / "top_domains_reported.json"
SOURCES = ROOT / "data" / "top_domains_sources.json"
VETO_RANK = 10_000
INFRASTRUCTURE = ROOT / "data" / "infrastructure_domains.txt"
PSL_TOP = ROOT / "data" / "public_suffixes_in_top.json"
ASSETS = ROOT / "mobile" / "modules" / "cleanway-vpn" / "android" / "src" / "main" / "assets"
OUT = ASSETS / "popular_veto.txt"
OUT_SHARED = ASSETS / "shared_suffixes.txt"
IANA_TLDS = ROOT / "data" / "iana_tlds.txt"
OUT_TLDS = ASSETS / "root_zone_tlds.txt"

# Apexes from scripts/blocklist_shared_zones.py HOSTING_PLATFORMS ∪ scoring.HOSTING_PLATFORMS
# that are top-10k but whose subdomains are tenants: left out of the veto, as
# the public suffixes are (shared_suffixes.txt is the publisher's set itself).
SHARED_APEXES = {
    "github.io", "gitlab.io", "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
    "webflow.io", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "appspot.com", "azurewebsites.net", "herokuapp.com", "cloudfront.net",
    "myshopify.com", "notion.site", "carrd.co", "000webhostapp.com", "duckdns.org", "us.org",
}


def load_infrastructure() -> set[str]:
    names = set()
    for raw in INFRASTRUCTURE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if line:
            names.add(line)
    return names


def load_reported_popular(max_rank: int = VETO_RANK) -> set[str]:
    """The names data/top_domains_reported.json ranks in the first `max_rank`:
    popular, but a feed reports them, so build_top_domains kept them off the
    allowlist (top_10k.json). The veto is "never block on the phone", not
    "safe", so they are vetoed like any other name of their rank."""
    if not REPORTED.exists():
        return set()
    return {d.lower() for d, rank in json.loads(REPORTED.read_text()).items() if rank <= max_rank}


def attribution_header() -> str:
    """'# ' lines with the ranking's CC BY attribution (the phone skips '#' lines)."""
    from ranking_attribution import attribution_lines

    return "".join(f"# {line}\n" for line in attribution_lines(json.loads(SOURCES.read_text())))


def build_names() -> set[str]:
    """Every name the veto is cut from: the top 10k, the reported popular
    names and the infrastructure names."""
    raw = json.loads(TOP10K.read_text())
    return ({d.lower() for d in (raw.keys() if isinstance(raw, dict) else raw)} | load_infrastructure()
            | load_reported_popular())


def build() -> list[str]:
    """The veto: build_names() minus the public suffixes and shared platform
    apexes — but never an operator's own suffix (googleapis.com,
    githubusercontent.com, cloudfront.net): nothing under those is a tenant's,
    the publisher never lists a name there, and the veto keeps a bad publish
    from darkening one on the phone."""
    psl_top = {d.lower() for d in json.loads(PSL_TOP.read_text())} if PSL_TOP.exists() else set()
    return sorted(build_names() - ((psl_top | SHARED_APEXES) - OPERATOR_SUFFIXES))


def build_shared() -> list[str]:
    """Suffixes under which a name is ONE TENANT's site — exactly the
    publisher's (scripts/blocklist_shared_zones.py default_shared_suffixes).

    The phone needs these because the popular veto works on the registrable
    domain: `best10cdn.blob.core.windows.net` has registrable `windows.net`,
    which is top-10k, so the veto cancelled the block — 783 of the 1,548
    tenant suffixes the publisher targets were silently un-blockable on the
    phone (found 2026-08-19 by simulating the shipped veto over the live
    artifact). With this set the phone can tell "Microsoft's own name" from
    "someone's bucket on Microsoft's platform". A copy narrower than the
    publisher's set did the same to 66 top-10k platforms after #284 widened it
    (tilda.ws, narod.ru, godaddysites.com, blogspot.com.br …; 2026-10-25).

    After them, '!'-prefixed, the platforms' own names under those suffixes
    (blocklist_shared_zones.platform_own_names): taken over with the zones,
    GoDaddy's sign-in, Teachable's e-mail links and Thinkific's file CDN
    lost the veto they had on main, while DoH already blocked them from one
    feed listing (review of #336).
    """
    return sorted(default_shared_suffixes()) + sorted("!" + n for n in platform_own_names())


def build_root_zone() -> tuple[str, list[str]]:
    """The IANA root zone as the phone reads it: (IANA version line, TLDs).

    Each xn-- TLD is followed by its Unicode spelling — decoded with the
    punycode codec itself, not the idna one, which rejects some valid IDN
    labels — so the extractor matches "рф" as written without punycoding
    every dotted word in a message.
    """
    lines = IANA_TLDS.read_text().splitlines()
    version = lines[0].lstrip("# ").strip() if lines and lines[0].startswith("#") else "unknown"
    out: list[str] = []
    for line in lines:
        tld = line.strip().lower()
        if not tld or tld.startswith("#"):
            continue
        out.append(tld)
        if tld.startswith("xn--"):
            out.append(codecs.decode(tld[4:].encode("ascii"), "punycode"))
    if len(out) < 1000:
        raise SystemExit(f"{IANA_TLDS.relative_to(ROOT)}: only {len(out)} TLDs — truncated download?")
    return version, out


def main() -> int:
    lines = build()
    shared = build_shared()
    head = "# GENERATED by scripts/build_mobile_assets.py — do not edit\n" + attribution_header()
    shared_text = head + "\n".join(shared) + "\n"
    text = head + "\n".join(lines) + "\n"
    own = sum(1 for n in shared if n.startswith("!"))
    tld_version, tlds = build_root_zone()
    tlds_text = (
        "# GENERATED by scripts/build_mobile_assets.py from data/iana_tlds.txt — do not edit\n"
        f"# IANA {tld_version}\n" + "\n".join(tlds) + "\n"
    )
    if "--check" in sys.argv:
        stale = []
        if (OUT.read_text() if OUT.exists() else "") != text:
            stale.append(OUT)
        if (OUT_SHARED.read_text() if OUT_SHARED.exists() else "") != shared_text:
            stale.append(OUT_SHARED)
        if (OUT_TLDS.read_text() if OUT_TLDS.exists() else "") != tlds_text:
            stale.append(OUT_TLDS)
        if stale:
            for f in stale:
                print(f"STALE: {f.relative_to(ROOT)}")
            return 1
        print(f"OK: {len(lines)} popular names, {len(shared) - own} shared suffixes "
              f"(+{own} platform-own names), {len(tlds)} root-zone TLDs")
        return 0
    ASSETS.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    OUT_SHARED.write_text(shared_text)
    OUT_TLDS.write_text(tlds_text)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(lines)} names, {len(text)} bytes")
    print(f"wrote {OUT_SHARED.relative_to(ROOT)}: {len(shared) - own} suffixes + {own} platform-own names, "
          f"{len(shared_text)} bytes")
    print(f"wrote {OUT_TLDS.relative_to(ROOT)}: {len(tlds)} TLDs, {len(tlds_text.encode())} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
