"""Which names the blocklist publisher treats as one tenant's site.

The shared suffixes (github.io, tilda.ws, duckdns.org, ipfs.io …), under which
a name is one customer's site: blocked exactly, never promoted, and the zone
itself never listed. And the operators' own suffixes (githubusercontent.com,
googleapis.com …), under which no name is a tenant's and none is ever listed.

Two readers, one set: scripts/refresh_dangerous_domains.py (build_blockset,
the publish gate) and scripts/build_mobile_assets.py, which writes the same
set to the Android shield's assets/shared_suffixes.txt. The phone vetoes a
listed name whose registrable is a top-10k name unless the name sits under one
of these suffixes; when the copies differ, the phone cancels the tenant
entries the publisher blocks — after #284 it did for 66 top-10k platforms
(tilda.ws, narod.ru, godaddysites.com, blogspot.com.br …; audit 2026-10-25).

Standard library only (plus api/services/hosting_platforms.py, which is):
scripts/build_mobile_assets.py runs in CI with a bare python3, nothing
installed.
"""
from __future__ import annotations

import json
import logging
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from api.services import hosting_platforms as curated_platforms  # noqa: E402

logger = logging.getLogger("dangerous-domains-refresh")

_DATA_DIR = os.path.join(_ROOT, "data")

# Registrables we must NEVER add (blocking these blocks legit infra). Shared
# hosting / URL platforms where phishing lives on subdomains/paths.
HOSTING_PLATFORMS = frozenset({
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
    "appspot.com", "azurewebsites.net", "cloudfront.net", "onrender.com",
    "fly.dev", "railway.app", "blogspot.com", "wordpress.com", "wixsite.com",
    "wixstudio.com", "weebly.com", "webflow.io", "framer.app", "framer.website",
    "carrd.co", "notion.site", "myshopify.com", "replit.app", "webcindario.com",
    "000webhostapp.com", "000webhost.com", "glitch.me", "surge.sh", "duckdns.org",
    "run.app", "s3.amazonaws.com", "blob.core.windows.net", "sharepoint.com",
    "google.com", "microsoft.com", "amazonaws.com", "cloudflare.com",
})

# Big orgs whose subdomains are THEIR OWN services, not tenant sites. A
# subdomain of these is never a block target (the popular-registrable rule
# already skips them; listed here so they are never treated as tenant suffixes).
BIG_ORGS = frozenset({"google.com", "microsoft.com", "amazonaws.com", "cloudflare.com"})

# Suffixes where EVERY label belongs to the platform operator — there are no
# tenants under them, only the operator's own infrastructure. The tenant rule
# must never fire here: on 2026-08-19 it put media.githubusercontent.com
# (GitHub's own media CDN, one URLhaus entry) into production, so every phone
# and every DoH user got NXDOMAIN for it.
OPERATOR_SUFFIXES = frozenset({
    "githubusercontent.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "ggpht.com", "usercontent.goog", "withgoogle.com",
    "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net",
    "fbcdn.net", "cdninstagram.com", "licdn.com", "twimg.com",
    "wp.com", "gravatar.com", "shopifycdn.com", "cloudflarestorage.com",
    "linodeusercontent.com", "digitaloceanspaces.com", "oaiusercontent.com",
})


def _load_public_suffixes_in_top() -> set[str]:
    """PSL rules whose base is a top domain or an infrastructure name (us.org,
    github.io, blob.core.windows.net …) — built with the top list by
    scripts/build_top_domains.py.
    Subdomains of these are tenant sites; the apex is the platform."""
    try:
        with open(os.path.join(_DATA_DIR, "public_suffixes_in_top.json")) as f:
            return {d.lower() for d in json.load(f)}
    except Exception as e:  # noqa: BLE001
        logger.warning("public_suffixes_in_top.json not loaded (%s) — tenant guard weaker", e)
        return set()


# Multi-tenant domains no popularity list ranks: free dynamic-DNS zones
# (ChangeIP's free domains, as the provider lists them), IPFS gateways,
# webhook / function hosts and hosting providers' reverse-DNS zones. Until
# 2026-10-23 Tranco's top 100k — DNS-traffic lists averaged in — happened to
# hold most of them, and the popular-registrable guard kept their apexes
# from being promoted: a dry run of the licensed ranking against the same
# feed snapshot blocked 25u.com, zzux.com, ipfs.io, twil.io, softlayer.net
# and ~200 more whole (docs/THIRD_PARTY_FEEDS.md §2a). Shared, as the
# curated data/hosting_platforms.json suffixes are below: a tenant is
# blocked exactly, the apex never.
UNRANKED_SHARED_DOMAINS = frozenset({
    # ChangeIP free dynamic-DNS domains
    "25u.com", "2waky.com", "3-a.net", "4dq.com", "4mydomain.com", "4pu.com", "acmetoy.com",
    "almostmy.com", "americanunfinished.com", "authorizeddns.net", "authorizeddns.org",
    "authorizeddns.us", "bigmoney.biz", "changeip.biz", "changeip.co", "changeip.net", "changeip.org",
    "changeip.us", "cleansite.biz", "cleansite.info", "cleansite.us", "compress.to", "ddns.info",
    "ddns.me.uk", "ddns.mobi", "ddns.ms", "ddns.name", "ddns.us", "dhcp.biz", "dns-dns.com",
    "dns-report.com", "dns04.com", "dns05.com", "dns1.us", "dns2.us", "dnset.com", "dnsfailover.net",
    "dnsrd.com", "dsmtp.biz", "dsmtp.com", "dumb1.com", "dynamic-dns.net", "dynamicdns.biz",
    "dynns.com", "dynssl.com", "edns.biz", "epac.to", "esmtp.biz", "ezua.com", "faqserv.com",
    "fartit.com", "freeddns.com", "freetcp.com", "freewww.biz", "freewww.info", "ftp1.biz",
    "ftpserver.biz", "gettrials.com", "got-game.org", "gr8domain.biz", "gr8name.biz", "https443.net",
    "https443.org", "ikwb.com", "instanthq.com", "iownyour.biz", "iownyour.org", "isasecret.com",
    "itemdb.com", "itsaol.com", "jetos.com", "jkub.com", "jungleheart.com", "justdied.com",
    "lflink.com", "lflinkup.com", "lflinkup.net", "lflinkup.org", "longmusic.com", "mefound.com",
    "moneyhome.biz", "mrbasic.com", "mrbonus.com", "mrface.com", "mrslove.com", "my03.com",
    "mydad.info", "myddns.com", "myftp.info", "mylftv.com", "mymom.info", "mynetav.com",
    "mynetav.net", "mynetav.org", "mynumber.org", "mypicture.info", "mypop3.net", "mypop3.org",
    "mysecondarydns.com", "mywww.biz", "myz.info", "ninth.biz", "ns01.biz", "ns01.info", "ns01.us",
    "ns02.biz", "ns02.info", "ns02.us", "ns1.name", "ns2.name", "ns3.name", "ocry.com",
    "onedumb.com", "onmypc.biz", "onmypc.info", "onmypc.net", "onmypc.org", "onmypc.us", "otzo.com",
    "ourhobby.com", "pcanywhere.net", "port25.biz", "proxydns.com", "qhigh.com", "qpoe.com",
    "rebatesrule.net", "sendsmtp.com", "serveuser.com", "serveusers.com", "sexidude.com",
    "sexxxy.biz", "sixth.biz", "squirly.info", "ssl443.org", "toh.info", "toythieves.com",
    "trickip.net", "trickip.org", "vizvaz.com", "wikaba.com", "www1.biz", "wwwhost.biz",
    "x24hr.com", "xxuz.com", "xxxy.biz", "xxxy.info", "ygto.com", "youdontcare.com", "yourtrap.com",
    "zyns.com", "zzux.com",
    # …and three more of ChangeIP's (2026-10-23: RDAP registrant "changeip
    # operations", ChangeIP's name servers, its default server's 404 page)
    "b0tnet.com", "dubya.net", "misecure.com",
    # Other free dynamic-DNS zones
    "dvrlists.com", "dyna-ns.net", "easterndns.com", "freeddns.org", "us.to", "crabdance.com",
    "jumpingcrab.com", "chickenkiller.com", "mooo.com", "dns.army", "v6.rocks", "v6.navy",
    # 2026-10-23: FreeDNS (afraid.org) shared domains — qc.to is shared with
    # the owner's approval, by us.to's owner; Dynu's own zones (offered in its
    # "Use Our Domain Name" list, registrant handle 81245932-DYNU); No-IP's
    # viewdns.net (its Free list, registrar No-IP); Now-DNS's tftpd.net (in
    # its own domain list); PubYun's eatuo.com (its paid DDNS suffixes);
    # IPQuick's ipq.co and fdns.uk (free records since ~2014)
    "ftp.sh", "mine.bz", "qc.to", "soon.it", "undo.it", "zanity.net",
    "ezgateway.net", "flashhub.net", "remotewire.net", "xubi.org", "yyuyy.com",
    "viewdns.net", "tftpd.net", "eatuo.com", "ipq.co", "fdns.uk",
    # IPFS gateways, webhook and function hosts: one subdomain (or path) per user
    "ipfs.io", "dweb.link", "w3s.link", "nftstorage.link", "infura-ipfs.io", "eth.limo",
    "twil.io", "pipedream.net", "webhook.site", "koyeb.app", "localto.net", "loclx.io",
    "portmap.host", "test-app.link",
    # 2026-10-23: an ar.io gateway (ArDrive's node), one subdomain per Arweave
    # content id — arweave.net itself is in data/hosting_platforms.json
    "turbo-gateway.com",
    # Hosting providers' reverse-DNS, customer-server and name-server zones
    "softlayer.net", "sl-reverse.com", "bbox.fr", "romtelecom.net", "websiteservername.com",
    "mysecurecloudhost.com", "misitiohostgator.com", "hostwindsdns.com", "dns-parking.com",
    # 2026-10-23: Aruba Business (arubabiz.net), cyber_Folks (pro-linuxpl.com,
    # domeny.host), Domenomania, Infomaniak's Jelastic zone, Afrihost
    # (dedicated.co.za), BKNS, YUnet, MC-HOST24 (gamingcontrol.de,
    # gamingweb.de), S-HOST, SmartApe (smrtp.ru), ToWebs (toservers.com), Lanka
    # Communication Services, a server zone on Zomro's DNS (had.pm),
    # HIVELOCITY (hvvc.us), TurnKey Internet (as40244.net), IT7 (16clouds.com),
    # velia.net (startdedicated.com), HostPapa (secserverpros.com,
    # servername.online)
    "arubabiz.net", "pro-linuxpl.com", "domeny.host", "domenomania.eu", "ik-server.com",
    "dedicated.co.za", "bkns.biz", "yunethosting.rs", "gamingcontrol.de", "gamingweb.de",
    "s-host.net", "smrtp.ru", "toservers.com", "lankapanel.net", "had.pm", "hvvc.us",
    "as40244.net", "16clouds.com", "startdedicated.com", "secserverpros.com", "servername.online",
    # Microsoft's US government cloud: one subdomain per customer tenant
    "sharepoint.us", "sharepoint-mil.us", "mcas-gov.us",
    # Found by the 2026-10-23 dry run against Tranco's top-1M guard (the
    # zones it protected that the licensed ranking does not carry, with
    # several listed tenants each):
    # more free dynamic-DNS zones, tunnels and device DDNS
    "2mydns.net", "airdns.org", "anondns.net", "d-n-s.name", "dd-dns.de", "didns.ru", "diskstation.eu",
    "dns-stuff.com", "dns.navy", "dnsdyn.net", "duia.eu", "dynip.org", "dynnamn.ru", "laviewddns.com",
    "lndyn.com", "nowddns.com", "privatedns.org", "sieraddns.com", "v6.army", "myq-see.com",
    "lhr.life", "localhost.run", "loophole.site", "pagekite.me", "pktriot.net", "serveo.net",
    "serveousercontent.com", "mytunnel.org", "bore.pub", "dataplicity.io",
    "n-e.kr", "o-r.kr", "p-e.kr", "r-e.kr",
    "xn--2i0b10rqve.xn--3e0b707e", "xn--9i1b01onwqqzd.xn--3e0b707e", "xn--h32bi4v.xn--3e0b707e",
    "xn--hk3b17f.xn--3e0b707e", "xn--hu5b25b77nvwc.xn--3e0b707e", "xn--oi2b61z32a.xn--3e0b707e",
    "xn--yq5b.xn--3e0b707e",
    # hosting, site builders, staging and storage hosts: one subdomain per customer
    "000nethost.com", "4everland.io", "bero-webspace.de", "builderallwppro.com", "cloudlets.zone",
    "cloudworkstations.dev", "dreamwp.com", "freewebhostmost.com", "free.hr", "fornex.host",
    "fozzyhost.com", "hidora.com", "hidora.net", "hostenko.net", "instawp.site", "ionoscloud.com",
    "kinsta.page", "myhostgator.site", "prohoster.biz", "rollout.site", "staticdomains.app",
    "sviluppo.host", "teste.website", "tiiny.io", "webpages.one", "webspace.re", "wstd.io",
    "zap-webspace.com", "x10.network", "thehost.com.ua", "gtempurl.com", "justns.ru", "njalla.net",
    "nipa.cloud", "mtxserv.com", "b4a.app", "arvanstorage.com", "cubbit.eu", "ucarecd.net", "ufs.sh",
    "mailersend.net",
    # 2026-10-23, the feeds listing tenants only: free hosts (InfinityFree's
    # infy.click and infy.uk, ABA.ae's aba.ae and aba.vg, GoogieHost's whf.bz,
    # Poyraz Hosting's tr.ht with its com. and net. zones, mojweb.com.hr);
    # hosters' account and preview zones (fornex.org beside fornex.host,
    # cal.pl's stronawcal.pl, Websupport's wbsprt.com, GetLark, Convesio,
    # Hyperlane, bwpsites.com); site and app builders (WebsTriple, Floot, Omni
    # Coder, Mimo, Graphy's ongraphy.com, HostGator's simplo7.net, Tithely
    # Sites, Webauthor); one-instance-per-customer SaaS (Partoo store
    # locators, Earcu careers portals, Planview PPM Pro)
    "infy.click", "infy.uk", "aba.ae", "aba.vg", "whf.bz", "tr.ht", "com.tr.ht", "net.tr.ht",
    "mojweb.com.hr", "fornex.org", "stronawcal.pl", "wbsprt.com", "getlark.hosting", "conves.io",
    "hyperlane.co", "bwpsites.com", "webstriple.com", "floot.app", "omnicoder.app", "mimo.run",
    "ongraphy.com", "simplo7.net", "tithelysetup.com", "webauthor.com",
    "partoo-store-locator.co", "earcu.com", "ppmpro.com",
    # services Tranco's top-100k protected, one subdomain (or path) per customer:
    # Microsoft Defender for Cloud Apps (government), Skyhigh / McAfee cloud
    # proxy tenants, SpamExperts filtering, form / link-tracking / chatbot
    # endpoints, a shortener, wildcard DNS and a hoster's reverse zone
    "admin-mcas-df.ms", "admin-mcas-gov.ms", "mcas-gov.ms", "myshn.eu", "myshn.net", "antispamcloud.com", "submit-form.com",
    "emlnk.com", "rdtk.io", "chatbot.page", "sl.pt", "cloud-xip.com", "mschosting.com",
    # 2026-10-23: a public CORS proxy (corsproxy.io/?url=…, top-100k) and,
    # top-1M only: Skyhigh's government and proof-of-concept proxy zones,
    # Forcepoint CASB tenants (skyfencenet.com), Locaweb's e-mail click
    # tracker (emktlw.com.br) and Thinkst Canarytokens (one DNS token per
    # subdomain; its web-token host is in SHARED_HOSTNAMES)
    "corsproxy.io", "govshn.net", "shnpoc.net", "skyfencenet.com", "emktlw.com.br", "canarytokens.com",
    # 2026-10-23: Indonesian regency governments — each agency runs its own
    # subdomain site; the feeds list hacked agency hosts, never the portal
    "madiunkab.go.id", "tabalongkab.go.id",
    # 2026-10-23: a former free-subdomain zone, re-registered on 2026-02-22 by
    # Cinematic Apps (Line Budgeter). ~230 old tenant listings, none of which
    # resolves; the apex was never listed. Shared, the apex can no longer be
    # blocked: re-review if a listed tenant resolves again or a feed lists
    # line.pm or www.line.pm.
    "line.pm",
    # Blogger's country domains (blogspot.com and most are in data/hosting_platforms.json)
    "blogspot.ae", "blogspot.al", "blogspot.am", "blogspot.ba", "blogspot.be", "blogspot.bg", "blogspot.bj",
    "blogspot.ca", "blogspot.cf", "blogspot.ch", "blogspot.cl", "blogspot.co.at", "blogspot.co.id",
    "blogspot.co.il", "blogspot.co.ke", "blogspot.co.nz", "blogspot.co.uk", "blogspot.co.za",
    "blogspot.com.ar", "blogspot.com.au", "blogspot.com.br", "blogspot.com.by", "blogspot.com.co",
    "blogspot.com.cy", "blogspot.com.ee", "blogspot.com.eg", "blogspot.com.es", "blogspot.com.mt",
    "blogspot.com.ng", "blogspot.com.tr", "blogspot.com.uy", "blogspot.cv", "blogspot.cz", "blogspot.de",
    "blogspot.dk", "blogspot.fi", "blogspot.fr", "blogspot.gr", "blogspot.hk", "blogspot.hr", "blogspot.hu",
    "blogspot.ie", "blogspot.in", "blogspot.is", "blogspot.it", "blogspot.jp", "blogspot.kr", "blogspot.li",
    "blogspot.lt", "blogspot.lu", "blogspot.md", "blogspot.mk", "blogspot.mr", "blogspot.mx", "blogspot.my",
    "blogspot.nl", "blogspot.no", "blogspot.pe", "blogspot.pt", "blogspot.qa", "blogspot.re", "blogspot.ro",
    "blogspot.rs", "blogspot.ru", "blogspot.se", "blogspot.sg", "blogspot.si", "blogspot.sk", "blogspot.sn",
    "blogspot.td", "blogspot.tw", "blogspot.ug", "blogspot.vn",
})


def default_shared_suffixes() -> set[str]:
    """Suffixes under which a subdomain is ONE tenant's site (safe to block
    exactly) while the apex is a platform (never blocked): the hand list,
    the public suffixes in the top list, the curated
    data/hosting_platforms.json (tenant suffixes and dynamic DNS) and
    UNRANKED_SHARED_DOMAINS. Operator-only suffixes are excluded: a name
    under those is the operator's, not a tenant's, and blocking it breaks
    the platform for everyone."""
    return ((set(HOSTING_PLATFORMS) - BIG_ORGS) | _load_public_suffixes_in_top()
            | curated_platforms.TENANT_SUFFIXES | curated_platforms.DYNAMIC_DNS_SUFFIXES
            | UNRANKED_SHARED_DOMAINS) - OPERATOR_SUFFIXES
