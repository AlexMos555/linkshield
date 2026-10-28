/**
 * Credential-form Guardian — Cleanway's anti-phishing detector at the
 * MOMENT a password field appears on a page.
 *
 * Strategy doc Top-20 #1 (impact 9/10, differentiation 7/10, 4 weeks).
 * Matches Bitdefender TrafficLight credential warnings; beats Norton +
 * McAfee which are still URL-only.
 *
 * The classic phishing flow:
 *   1. User clicks a link from email/SMS/DM
 *   2. Lands on a page that LOOKS like paypal.com / chase.com / apple.com
 *   3. URL is something else (paypal-secure-login.com, attacker.tld/login)
 *   4. Page shows a familiar logo + a <form action="https://attacker.tld/steal"
 *      method="POST"> with a password field
 *   5. User types password → bytes go to attacker
 *
 * Cleanway's URL-level detector catches many of these via typosquat /
 * brand-impersonation / TLD heuristics, but the long tail of clever
 * phish slips through the URL alone. This script fires the second a
 * password input appears and asks: "does the form post somewhere
 * believable?" If not — flash a warning above the form and (in strict
 * mode) intercept the submit.
 *
 * Three signals stack into a verdict (any one of them ≥ "warn" → show):
 *   A. action-site vs visible-site mismatch — form posts to another site
 *      (registrable domain, see `_siteOf`) than the address bar's. Some
 *      legit cases exist (federated SSO, redirector flows), so we
 *      whitelist known identity providers — see `LEGIT_AUTH_HOSTS`.
 *   B. visible-host typosquat — the address bar site's name matches a
 *      known brand pattern (paypal0.com, paypa1.com, paypa1.co.uk),
 *      against the `BRAND_HOSTS` table below.
 *   C. high-risk TLD on a credential page — scammers favour .tk / .ml /
 *      .top / .xyz / etc. for throwaway login pages, but plenty of real
 *      sites live there too.
 *
 * A lone weak signal (C, or A with an HTTPS action) gets calmer copy —
 * "take care", not "this is a scam". Two signals, a typosquat, a password
 * posted over plain HTTP, or a page the URL check already blocked (strict
 * mode) get the full warning.
 *
 * Privacy: the script reads the DOM. The only network call is the
 * brand-name lookup below, made by the background (the brand, e.g.
 * "paypal" — never the URL, the page's origin or anything typed into the
 * form). Without it the warning still fires.
 */
(function () {
  "use strict";

  // ── Toggles ──
  // Strict mode: the background has shown this page's block page (the URL
  // check called the page itself dangerous) and the user may have clicked
  // past it. Then EVERY password field warns and every such form asks
  // before submitting, whether or not the form checks below fire.
  var _strictMode = false;
  // 0 = no banner yet, 1 = the calm "take care" banner, 2 = the full
  // warning. A stronger verdict replaces a weaker banner, never the reverse.
  var _bannerRank = 0;
  var _debugMode = false;

  function _log() {
    if (_debugMode) console.log.apply(console, ["[Cleanway-Guard]"].concat(Array.from(arguments)));
  }

  // ── Brand identity table ──
  // This file's own short list, not the scorer's brand table: its keys are
  // what the background's verified sign-in host lookup (VERIFIED_HOSTS,
  // api/routers/credentials.py) is keyed on. Where a site ends comes from
  // the scorer's name rules (see `_siteOf`).
  var BRAND_HOSTS = {
    paypal: "paypal.com",
    apple: "apple.com",
    google: "google.com",
    amazon: "amazon.com",
    microsoft: "microsoft.com",
    netflix: "netflix.com",
    facebook: "facebook.com",
    instagram: "instagram.com",
    whatsapp: "whatsapp.com",
    chase: "chase.com",
    coinbase: "coinbase.com",
    binance: "binance.com",
    dhl: "dhl.com",
    fedex: "fedex.com",
    ups: "ups.com",
    ebay: "ebay.com",
    discord: "discord.com",
    telegram: "telegram.org",
    linkedin: "linkedin.com",
    bank: "bank.com",
    citi: "citi.com",
    wellsfargo: "wellsfargo.com",
    capitalone: "capitalone.com",
    hsbc: "hsbc.com",
  };

  // Hosts where it's NORMAL for action !== window.location.host —
  // federated SSO, OAuth, SAML. Without this whitelist we'd false-
  // positive on every legitimate "Sign in with Google" page.
  var LEGIT_AUTH_HOSTS = new Set([
    "accounts.google.com",
    "appleid.apple.com",
    "login.microsoftonline.com",
    "login.live.com",
    "login.salesforce.com",
    "auth0.com",
    "okta.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "facebook.com",
    "www.facebook.com",
    "id.atlassian.com",
    "sso.zoom.us",
    "login.yahoo.com",
    "auth.tesla.com",
    "id.heroku.com",
    "discord.com",
    "discordapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "www.linkedin.com",
  ]);

  // Suspicious TLDs — duplicate of scorer._HR. A password page on
  // these is high-confidence hostile.
  var HIGH_RISK_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".buzz", ".icu", ".cam", ".live", ".loan", ".download",
  ];

  // Leet-speak normalisation for typosquat check.
  var CHAR_SWAPS = { "1": "l", "0": "o", "3": "e", "@": "a", "5": "s" };

  // ── Where one site ends ──
  // Both form checks ask it: Signal A whether the form posts to another
  // site, Signal B what the site is called. A site is the registrable
  // domain, by the server's rule (scoring.registrable_domain: the Public
  // Suffix List's ICANN rules with the Russian PSL zones and the registry
  // overlay on top), ported in utils/name-rules.js, which every manifest
  // loads before this file into the same content-script world.
  //
  // This file used to take the last two labels. Under a compound suffix
  // those are the suffix, so everyone there was one site:
  //   A. evil-login.co.uk posting a password to collector.co.uk stayed on
  //      "co.uk": no off-site warning, under com.br, co.jp, msk.ru … alike;
  //   B. paypa1.co.uk was named "co", which imitates no brand: of the 38,806
  //      hosts under a compound suffix in the 2026-10-24 phishing feed
  //      snapshot, Signal B flagged none;
  // and an IP address was its last two numbers (10.0.1.10 = 192.168.1.10).
  //
  // Until 2026-10-28 the server's rule was a compound-ccTLD heuristic (a
  // 2-letter ccTLD under co, com, gov, web, id …), which knew no other
  // suffix: under my.id, io.vn, hl.cn, me.uk everyone was still one site and
  // facebook-login.my.id was named "my". On that feed snapshot the PSL's
  // reading flags 64 more look-alikes by Signal B (adsmanager-facebook.my.id,
  // apiim-whatsapp.hl.cn: my.id 38, hl.cn 21) and none of the top-100k
  // names. It also took web.de and id.me for suffixes, which this file had
  // to correct with a list of its own; the PSL lists neither.
  //
  // Read by the ICANN section alone, the registries the heuristic split
  // rightly would have been one site each: co.ua, com.de, co.nl (the PSL
  // lists them in its PRIVATE section only) and co.vu, co.nf, com.tg (in no
  // section), so paypal-login.co.vu posting to collector.co.vu was "the same
  // site" and named "co". The server's registry overlay keeps them split
  // (public_suffix.REGISTRY_OVERLAY, registrySuffixes in scorer-data.js).
  // The rest of the PRIVATE section stays out (github.io, blogspot.com): the
  // server's curated platform lists decide those, and this file has none.
  var GUARD_ROOT = typeof self !== "undefined" ? self : globalThis;

  function _nameRules() {
    var rules = GUARD_ROOT.cleanwayNameRules;
    return rules && typeof rules.registrableDomain === "function" ? rules : null;
  }

  function _hostname(host) {
    return String(host || "").toLowerCase().replace(/\.+$/, "");
  }

  function _lastTwoLabels(host) {
    return host.split(".").slice(-2).join(".");
  }

  // URL hostnames: IPv4 in dotted decimal, IPv6 in brackets.
  function _isIpLiteral(host) {
    return host.charAt(0) === "[" || /^\d+\.\d+\.\d+\.\d+$/.test(host);
  }

  // The site of a hostname: an IP address is its own, a single label
  // (localhost) is itself. Without the name rules (a packaging bug, which
  // scripts/test-extension-core.mjs guards) the old last two labels.
  function _siteOf(host) {
    var name = _hostname(host);
    if (!name || _isIpLiteral(name)) return name;
    var rules = _nameRules();
    return rules ? rules.registrableDomain(name) : _lastTwoLabels(name);
  }

  // The restricted zone a site is in (gov.hr, ac.uk, go.jp, gov.ru), or "":
  // a public suffix whose owner hands its names out, nobody buys one there.
  // Its sites are one owner for the off-site check, as the last two labels
  // had them: a sibling in the zone is not an attacker's, and the PSL itself
  // does not split gov.hr, gov.hu, gov.cz or sch.gr (mojprofil.gov.hr signs
  // in at nias.gov.hr, Croatia's state sign-in; kau.gov.hu at idp.gov.hu).
  // The outermost such zone above the site: gov.uk for service.gov.uk, and
  // gov.br for detran.sp.gov.br, whose own suffix (sp.gov.br, one of the 27
  // state rules under gov.br the PSL reading of 2026-10-28 knows) carries no
  // restricted label — the heuristic before it had every sp.gov.br agency
  // one site. Outermost, not nearest: the state codes of Goiás and Acre are
  // restricted labels themselves (go, ac), and educacao.go.gov.br signs in
  // at sso.acesso.gov.br, the federal Login Único, like every other state.
  // In the ICANN section only go.gov.br and ac.gov.br nest a restricted
  // label under a restricted zone (2026-10-28).
  function _restrictedZoneOf(site) {
    var rules = _nameRules();
    if (!rules || typeof rules.isRestrictedZone !== "function" || _isIpLiteral(site)) return "";
    var zone = "";
    for (var suffix = site.slice(site.indexOf(".") + 1); suffix.indexOf(".") !== -1; suffix = suffix.slice(suffix.indexOf(".") + 1)) {
      if (rules.isRestrictedZone(suffix)) zone = suffix;
    }
    if (zone) return zone;
    // The zone's own site: gov.hr next to nias.gov.hr.
    return site.split(".").length === 2 && rules.isRestrictedZone(site) ? site : "";
  }

  function _sameSite(a, b) {
    var siteA = _siteOf(a);
    var siteB = _siteOf(b);
    if (!siteA || !siteB) return false;
    if (siteA === siteB) return true;
    var zone = _restrictedZoneOf(siteA);
    return zone !== "" && zone === _restrictedZoneOf(siteB);
  }

  function _normaliseLeet(s) {
    var out = String(s || "").toLowerCase();
    for (var c in CHAR_SWAPS) {
      out = out.split(c).join(CHAR_SWAPS[c]);
    }
    return out;
  }

  // ── HTML escape for any value that ends up inside innerHTML ──
  function _esc(s) {
    if (s == null) return "";
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // ── i18n ──
  // Text in the browser's language; it lives in packages/i18n-strings
  // (extension.credential_guard). scripts/test-extension-core.mjs fails CI
  // if a key used here is missing from any locale.
  function _t(key, subs) {
    try {
      return chrome.i18n.getMessage(key, subs || []) || key;
    } catch (e) {
      return key;
    }
  }

  // A translated sentence with page-supplied values in bold. The sentence
  // is escaped as a whole and every value on its own, so neither a hostile
  // hostname nor a translation can inject markup. \u0001N\u0001 markers
  // hold the values' places while the sentence is escaped.
  function _tHtml(key, values) {
    var markers = values.map(function (_v, i) { return "\u0001" + i + "\u0001"; });
    return _esc(_t(key, markers)).replace(/\u0001(\d+)\u0001/g, function (_m, i) {
      return "<strong>" + _esc(values[Number(i)]) + "</strong>";
    });
  }

  // ── Backend verified-host allowlist lookup ──
  //
  // The local LEGIT_AUTH_HOSTS covers federated SSO providers but
  // can't know every brand's own login hosts (paypal uses paypal.com,
  // chase uses secure01a.chase.com, etc.). The backend
  // /api/v1/credentials/verified endpoint returns that list per brand.
  // The background asks it (VERIFIED_HOSTS, background/page-lookups.js):
  // fetched from here, the request carried this page's origin and CORS
  // threw the answer away, so the list was always empty. Kept per page
  // load; the background keeps it per brand.
  var _brandHostCache = Object.create(null);

  function _fetchVerifiedHosts(brand) {
    if (_brandHostCache[brand]) return Promise.resolve(_brandHostCache[brand]);
    return new Promise(function (resolve) {
      try {
        chrome.runtime.sendMessage({ type: "VERIFIED_HOSTS", brand: brand }, function (reply) {
          void chrome.runtime.lastError; // no background: no list, the warning stands
          var hosts = reply && reply.ok && Array.isArray(reply.hosts) ? reply.hosts : [];
          if (reply && reply.ok) _brandHostCache[brand] = hosts;
          resolve(hosts);
        });
      } catch (e) {
        resolve([]);
      }
    });
  }

  // ── Signal A: form action host vs visible host ──
  function _classifyFormAction(form) {
    if (!form || !form.action) return { mismatch: false };
    var actionUrl;
    try {
      // form.action returns the RESOLVED URL string. Relative URLs
      // resolve against the current page so they end up same-host —
      // exactly what we want.
      actionUrl = new URL(form.action, window.location.href);
    } catch (e) {
      return { mismatch: false };
    }
    var pageHost = window.location.host.toLowerCase();
    var actionHost = actionUrl.host.toLowerCase();

    if (!actionHost || actionHost === pageHost) {
      return { mismatch: false, actionHost: actionHost };
    }

    // Same site? (paypal.com vs accounts.paypal.com, barclays.co.uk vs
    // online.barclays.co.uk — not evil.co.uk.) By hostname: the same name on
    // another port is the same site (the old comparison kept the port, so
    // example.com:8443 posting to example.com was "off-site"). A sibling
    // registrable domain is another site — bank.co.uk posting to
    // login.bankgroup.co.uk gets the calm one-sign warning, as bank.com
    // posting to login.bankgroup.com always has.
    var actionName = _hostname(actionUrl.hostname);
    if (_sameSite(window.location.hostname, actionName)) {
      return { mismatch: false, actionHost: actionHost };
    }

    // Legit auth providers — federated SSO etc.
    if (LEGIT_AUTH_HOSTS.has(actionName) || LEGIT_AUTH_HOSTS.has(_siteOf(actionName))) {
      return { mismatch: false, actionHost: actionHost, federated: true };
    }

    return {
      mismatch: true,
      actionHost: actionHost,
      pageHost: pageHost,
      scheme: actionUrl.protocol,
    };
  }

  // ── Signal B: visible-host typosquat against brand table ──
  // Under a compound suffix — the site is longer than the host's last two
  // labels, where the old code read "co" or "com" and never matched — only
  // the forms real sites do not take: the brand in look-alike characters
  // (paypa1.co.uk) or as a whole hyphenated word of the name
  // (paypal-login.co.uk, hot-binance.com.cn), and never the word "bank".
  // The plain-TLD rule (any name containing a brand) is how real names
  // carry brands there. Measured 2026-10-27 on the 10,757 names under a
  // compound suffix in data/top_100k.json: it flags 90, 14 of them in the
  // top 10k (bankofengland.co.uk, lloydsbank.co.uk, commbank.com.au,
  // mizuhobank.co.jp, upsc.gov.in, citizensadvice.org.uk …), each a full
  // warning and a stop at submit on its own sign-in form, with no verified
  // host to clear it. These forms flag 3, all "-bank" (rakuten-bank.co.jp
  // #5686, paypay-bank.co.jp, british-business-bank.co.uk), without "bank"
  // none. On the 2026-10-24 feed snapshot's 38,806 hosts under a compound
  // suffix: the old code flagged 0, the plain-TLD rule would flag 598,
  // these forms flag 193 (190 sites). Every other host is judged exactly as
  // before: its site is its last two labels.
  var NOT_A_BRAND_UNDER_COMPOUND = new Set(["bank"]);

  // Which BRAND_HOSTS brand the site's name imitates, or null.
  function _imitatedBrand(hostname) {
    var host = _hostname(hostname);
    if (!host || _isIpLiteral(host)) return null;
    var base = _siteOf(host);
    var nm = base.split(".")[0];
    var nmLeet = _normaliseLeet(nm);
    var compound = base !== _lastTwoLabels(host);
    var words = nmLeet.split("-");
    for (var brand in BRAND_HOSTS) {
      var legit = BRAND_HOSTS[brand];
      if (nm === brand || host === legit || base === legit) continue;
      if (compound) {
        if (!NOT_A_BRAND_UNDER_COMPOUND.has(brand) && words.indexOf(brand) >= 0) return brand;
      } else if (nmLeet === brand || nm.indexOf(brand) >= 0) {
        return brand;
      }
    }
    return null;
  }

  function _classifyVisibleHost() {
    var host = _hostname(window.location.hostname);
    var brand = _imitatedBrand(host);
    if (!brand) return { typosquat: false };
    return { typosquat: true, brand: brand, legit: BRAND_HOSTS[brand], host: host };
  }

  // ── Signal C: high-risk TLD ──
  function _classifyTld() {
    var host = window.location.hostname.toLowerCase();
    for (var i = 0; i < HIGH_RISK_TLDS.length; i++) {
      if (host.endsWith(HIGH_RISK_TLDS[i])) {
        return { suspicious: true, tld: HIGH_RISK_TLDS[i] };
      }
    }
    return { suspicious: false };
  }

  // ── Warning UI ──
  // Every flagged form is guarded at submit time; the banner shows once per
  // page load, upgraded in place if a stronger verdict arrives later.
  function _renderWarning(form, evidence) {
    _guardForm(form, evidence);
    var rank = evidence.weak ? 1 : 2;
    if (_bannerRank >= rank) return;
    _bannerRank = rank;
    var previous = document.getElementById("ls-credguard-banner");
    if (previous) previous.remove();
    _showBanner(evidence);
  }

  function _showBanner(evidence) {
    var flaggedLine = evidence.pageFlagged ? _esc(_t("credguard_page_flagged")) : "";
    var brandLine = evidence.typosquat
      ? _tHtml("credguard_banner_brand", [evidence.brand, evidence.host, evidence.legit])
      : "";
    var actionLine = evidence.mismatch
      ? _tHtml("credguard_banner_action", [evidence.actionHost])
      : "";
    var tldLine = evidence.tldSuspicious
      ? _tHtml("credguard_banner_tld", [evidence.tld])
      : "";

    var box = document.createElement("div");
    box.id = "ls-credguard-banner";
    box.setAttribute("role", "alert");
    box.setAttribute("aria-live", "assertive");
    box.style.cssText = [
      "position:fixed",
      "top:16px",
      "left:50%",
      // Start hidden+offset; CSS transition fades it down into view.
      // Combined transform deliberately overrides the X centering so
      // the initial state is also translated up; we restore in the
      // requestAnimationFrame callback below.
      "transform:translate(-50%,-12px)",
      "opacity:0",
      "transition:opacity 280ms ease-out,transform 280ms ease-out",
      "z-index:2147483646",
      "max-width:520px",
      "background:#0f172a",
      "color:#e2e8f0",
      "border:2px solid " + (evidence.weak ? "#f59e0b" : "#ef4444"),
      "border-radius:12px",
      "padding:14px 18px",
      "font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif",
      "font-size:14px",
      "line-height:1.5",
      "box-shadow:0 12px 32px rgba(0,0,0,0.5)",
    ].join(";");

    box.innerHTML = ''
      + '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px;">'
      + '  <span style="font-size:20px;line-height:1;" aria-hidden="true">⚠️</span>'
      + '  <strong style="color:' + (evidence.weak ? "#fde68a" : "#fecaca") + ';font-size:15px;">'
      + _esc(_t(evidence.weak ? "credguard_banner_title_weak" : "credguard_banner_title")) + '</strong>'
      + '</div>'
      + (flaggedLine ? '<div style="margin-top:6px;">' + flaggedLine + '</div>' : '')
      + (actionLine ? '<div style="margin-top:6px;">' + actionLine + '</div>' : '')
      + (brandLine ? '<div style="margin-top:6px;">' + brandLine + '</div>' : '')
      + (tldLine ? '<div style="margin-top:6px;">' + tldLine + '</div>' : '')
      + '<div style="margin-top:10px;color:#94a3b8;font-size:12px;">'
      + _esc(_t(evidence.weak ? "credguard_banner_advice_weak" : "credguard_banner_advice")) + '</div>'
      + '<div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">'
      + '  <button id="ls-credguard-dismiss" type="button" style="background:transparent;color:#94a3b8;border:1px solid #334155;border-radius:8px;padding:6px 12px;font-size:12px;cursor:pointer;">' + _esc(_t("credguard_dismiss")) + '</button>'
      + '</div>';

    (document.body || document.documentElement).appendChild(box);
    // rAF after append → next paint runs the transition.
    requestAnimationFrame(function () {
      box.style.opacity = "1";
      box.style.transform = "translate(-50%,0)";
    });
    var dismiss = box.querySelector("#ls-credguard-dismiss");
    if (dismiss) {
      dismiss.addEventListener("click", function () {
        box.style.opacity = "0";
        box.style.transform = "translate(-50%,-12px)";
        setTimeout(function () { if (box.parentNode) box.remove(); }, 280);
      });
    }
  }

  // Strategy doc Top-20 #7 — active credential guardian.
  // The passive banner is "early warning". This adds SUBMIT-TIME
  // interception with a confirmation modal so the user can't blow past the
  // warning by hitting Enter. We wire on ANY credential warning (mismatch /
  // typosquat / TLD / strict mode), because by the time a user typed their
  // password into a flagged form, the cost of one extra click is cheap
  // relative to credential theft. The modal reads the form's latest
  // evidence, so strict mode arriving later upgrades it too.
  function _guardForm(form, evidence) {
    if (!form) return;
    var current = form._lsGuardEvidence;
    if (!current || (current.weak && !evidence.weak) || (evidence.pageFlagged && !current.pageFlagged)) {
      form._lsGuardEvidence = evidence;
    }
    if (form._lsGuardWired) return;
    form._lsGuardWired = true;
    form.addEventListener(
      "submit",
      function (e) {
        if (form._lsGuardOverridden) {
          // User chose "submit anyway" in this tab — let it through.
          return;
        }
        e.preventDefault();
        e.stopPropagation();
        _renderConfirmModal(form, form._lsGuardEvidence);
      },
      true,
    );
  }

  // ── Strategy doc #7: confirmation modal at submit time ──
  // Modal blocks the form submit until the user makes an explicit
  // choice. Keyboard-trapped to the two buttons, ESC = cancel,
  // first focus on Cancel (the safer default). No transparent
  // overlay-tap-to-dismiss — phishing pages would close it instantly.
  function _renderConfirmModal(form, evidence) {
    if (document.getElementById("ls-credguard-modal")) return;

    // Each value is set whenever its flag is (see _evaluate), so no
    // "another host"-style fallbacks are needed.
    var reasons = [];
    if (evidence.pageFlagged) {
      reasons.push(_esc(_t("credguard_page_flagged")));
    }
    if (evidence.mismatch) {
      reasons.push(_esc(_t("credguard_reason_action", [evidence.actionHost, window.location.host])));
    }
    if (evidence.typosquat) {
      reasons.push(_esc(_t("credguard_reason_typosquat", [evidence.host || window.location.host, evidence.brand])));
    }
    if (evidence.tldSuspicious) {
      reasons.push(_esc(_t("credguard_reason_tld", [evidence.tld])));
    }

    var dialog = document.createElement("div");
    dialog.id = "ls-credguard-modal";
    dialog.setAttribute("role", "alertdialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "ls-credguard-modal-title");
    dialog.setAttribute("aria-describedby", "ls-credguard-modal-body");
    dialog.style.cssText = [
      "position:fixed",
      "inset:0",
      "z-index:2147483647",
      "background:rgba(2,6,23,0.78)",
      "display:flex",
      "align-items:center",
      "justify-content:center",
      "font:14px/1.55 -apple-system,system-ui,sans-serif",
    ].join(";");

    var card = document.createElement("div");
    card.style.cssText = [
      "background:#0f172a",
      "color:#f8fafc",
      "max-width:480px",
      "width:90%",
      "border-radius:14px",
      "padding:24px 24px 20px",
      "box-shadow:0 24px 80px rgba(0,0,0,0.6)",
      "border:1px solid " + (evidence.weak ? "#f59e0b" : "#ef4444"),
    ].join(";");

    var reasonsHtml = reasons
      .map(function (r) { return "<li style=\"margin-bottom:6px\">" + r + "</li>"; })
      .join("");
    var honeypotLabel = _t("credguard_button_honeypot");
    var honeypotHint = _t("credguard_button_honeypot_hint");

    card.innerHTML =
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
      '<span style="font-size:24px">⚠️</span>' +
      '<h2 id="ls-credguard-modal-title" style="margin:0;font-size:18px;font-weight:700;color:' +
      (evidence.weak ? "#fde68a" : "#fecaca") + '">' +
      _esc(_t(evidence.weak ? "credguard_modal_title_weak" : "credguard_modal_title")) +
      "</h2></div>" +
      '<div id="ls-credguard-modal-body" style="margin-bottom:14px;color:#cbd5e1">' +
      '<p style="margin:0 0 10px">' + _esc(_t("credguard_modal_intro")) + '</p>' +
      (reasons.length ? '<ul style="padding-left:18px;margin:0;color:#e2e8f0">' + reasonsHtml + "</ul>" : "") +
      "</div>" +
      // Strategy #8 — three buttons: cancel (safest, default focus),
      // honeypot shield (the form carries a random throwaway instead of
      // the real password), full override (user explicitly accepts the
      // risk). The honeypot cannot take back what the page may have read
      // while the user typed, and its toast says so.
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap">' +
      '<button id="ls-credguard-cancel" style="background:#22c55e;color:#052e16;border:0;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer">' + _esc(_t("credguard_button_cancel")) + '</button>' +
      // Grandma-test copy: "Send fake password" reads as "lie / cheat".
      // "Keep my password safe" reads as the user's intent.
      // The blue background was failing WCAG AA contrast on grey text;
      // we now use a deeper navy with light text (verified 7.4:1).
      '<button id="ls-credguard-honeypot" aria-label="' + _esc(honeypotLabel + ". " + honeypotHint) + '" style="background:#0c4a6e;color:#f0f9ff;border:0;padding:10px 14px;border-radius:8px;font-weight:700;cursor:pointer" title="' + _esc(honeypotHint) + '">🛡️ ' + _esc(honeypotLabel) + '</button>' +
      '<button id="ls-credguard-override" style="background:transparent;color:#fca5a5;border:1px solid #7f1d1d;padding:10px 14px;border-radius:8px;font-weight:600;cursor:pointer">' + _esc(_t("credguard_button_override")) + '</button>' +
      "</div>";

    dialog.appendChild(card);
    document.documentElement.appendChild(dialog);

    var cancelBtn = card.querySelector("#ls-credguard-cancel");
    var honeypotBtn = card.querySelector("#ls-credguard-honeypot");
    var overrideBtn = card.querySelector("#ls-credguard-override");

    function _close() {
      if (dialog.parentNode) dialog.parentNode.removeChild(dialog);
      document.removeEventListener("keydown", _onKey, true);
    }
    function _onKey(e) {
      if (e.key === "Escape") { e.preventDefault(); _close(); }
      if (e.key === "Tab") {
        var focusable = [cancelBtn, honeypotBtn, overrideBtn];
        var idx = focusable.indexOf(document.activeElement);
        if (idx === -1) {
          e.preventDefault();
          focusable[0].focus();
          return;
        }
        var next = e.shiftKey
          ? focusable[(idx - 1 + focusable.length) % focusable.length]
          : focusable[(idx + 1) % focusable.length];
        e.preventDefault();
        next.focus();
      }
    }
    document.addEventListener("keydown", _onKey, true);

    cancelBtn.addEventListener("click", function () { _close(); });

    honeypotBtn.addEventListener("click", function () {
      _close();
      _submitWithHoneypot(form);
    });

    overrideBtn.addEventListener("click", function () {
      _close();
      form._lsGuardOverridden = true;
      // Bump local-only counter so the popup can show "blocked X
      // credentials this week" — host never leaves the device.
      try {
        chrome.storage.local.get(["credguard_override_count"]).then(function (d) {
          var next = (d.credguard_override_count || 0) + 1;
          chrome.storage.local.set({ credguard_override_count: next }).catch(function () {});
        }).catch(function () {});
      } catch (_e) { /* ignore */ }
      // Re-submit. requestSubmit() preserves the form's submitter
      // button semantics; if unavailable (older browsers), fall back.
      if (typeof form.requestSubmit === "function") {
        try { form.requestSubmit(); return; } catch (_e) {}
      }
      try { form.submit(); } catch (_e) {}
    });

    // Default focus on Cancel — safer default.
    setTimeout(function () { cancelBtn.focus(); }, 0);
  }

  // ── Strategy doc #8 — Honeypot Shield (hardened 2026-06-17) ──
  // Replace every password input in the form with a fresh
  // cryptographically-random throwaway, force-submit, and show a
  // non-blocking toast inside a CLOSED shadow root so a hostile
  // page can't read it.
  //
  // Adversarial-review fixes applied here:
  //   * NO restore. The 1.5s restore was a vector — phishing kits
  //     fail-and-retry, which re-read the framework state at t=2s
  //     and got the original password. The honest contract is:
  //     once you press the shield button, the real password never
  //     touches the page again. If you're on a legit site you
  //     mis-flagged, retype it.
  //   * Per-input UNIQUE honeypot. Multi-password forms (signup,
  //     confirm-password, change-password) used to receive the
  //     SAME value across inputs, which both broke the form for
  //     legit cases and made detection trivial.
  //   * No fixed watermark prefix. A constant 'Cwx9p_' was a
  //     perfect Cleanway-installed fingerprint and a kit-side
  //     regex filter. We now ship pure random ASCII that's
  //     indistinguishable from a real password the user typed.
  //   * Shadow DOM for the toast — page MutationObservers no
  //     longer see the "shield activated" text in the live tree.
  //   * No HTTP report — the previous fetch surfaced in the page's
  //     PerformanceObserver as a Cleanway-installed signal. The
  //     counter lives in chrome.storage.local only; the
  //     transparency report uses opt-in aggregated extension
  //     telemetry instead.
  function _submitWithHoneypot(form) {
    if (!form) return;

    // querySelectorAll on `form` already pierces nested elements
    // including most webcomponent slots. For closed shadow roots
    // we walk the composed tree (best-effort — closed roots
    // remain inaccessible by design; we accept the gap).
    var pwInputs = _collectPasswordInputs(form);
    for (var i = 0; i < pwInputs.length; i++) {
      // EACH input gets its own value. A signup form's password
      // and confirm-password get distinct strings; the form's
      // "passwords don't match" client-side check will fail
      // gracefully on legit-but-flagged pages.
      _setInputValueWithFrameworkSync(pwInputs[i], _generateHoneypotValue());
    }

    form._lsGuardOverridden = true;
    try {
      chrome.storage.local.get(["honeypot_used_count"]).then(function (d) {
        var next = (d.honeypot_used_count || 0) + 1;
        chrome.storage.local.set({ honeypot_used_count: next }).catch(function () {});
      }).catch(function () {});
    } catch (_e) { /* ignore */ }

    _showHoneypotToast();

    if (typeof form.requestSubmit === "function") {
      try { form.requestSubmit(); return; } catch (_e) {}
    }
    try { form.submit(); } catch (_e) {}
  }

  function _collectPasswordInputs(root) {
    // Pierce open shadow roots we can see. Closed roots stay
    // inaccessible — kits using a closed root to hide a password
    // field also can't read it from page-world JS, so the threat
    // model there is narrower.
    var out = [];
    function walk(node) {
      if (!node) return;
      var inputs = node.querySelectorAll
        ? node.querySelectorAll('input[type="password"]')
        : [];
      for (var i = 0; i < inputs.length; i++) out.push(inputs[i]);
      var all = node.querySelectorAll ? node.querySelectorAll("*") : [];
      for (var j = 0; j < all.length; j++) {
        if (all[j].shadowRoot) walk(all[j].shadowRoot);
      }
    }
    walk(root);
    return out;
  }

  function _generateHoneypotValue() {
    // 24 random bytes → 32-char base64-ish output that looks like
    // a real high-entropy password the user typed. No fixed
    // prefix — would be a Cleanway-installed fingerprint. Mixed
    // case + digits keeps complexity rules happy on most forms.
    var CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    var out = "";
    var len = 18 + Math.floor(Math.random() * 4); // 18..21 chars
    if (window.crypto && window.crypto.getRandomValues) {
      var bytes = new Uint8Array(len);
      window.crypto.getRandomValues(bytes);
      for (var i = 0; i < bytes.length; i++) {
        out += CHARS[bytes[i] % CHARS.length];
      }
      return out;
    }
    for (var k = 0; k < len; k++) {
      out += CHARS[Math.floor(Math.random() * CHARS.length)];
    }
    return out;
  }

  function _setInputValueWithFrameworkSync(input, value) {
    if (!input) return;
    // React (and Preact, and most React-shaped form libraries) own
    // the input value via a synthetic setter that bypasses the
    // native setter. We have to call the prototype setter directly
    // and then dispatch an 'input' event so the framework's
    // controlled-component state syncs.
    var proto = window.HTMLInputElement && window.HTMLInputElement.prototype;
    var desc = proto && Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && typeof desc.set === "function") {
      desc.set.call(input, value);
    } else {
      input.value = value;
    }
    try {
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    } catch (_e) { /* ignore */ }
  }

  function _showHoneypotToast() {
    if (document.getElementById("ls-honeypot-host")) return;
    // Render INSIDE a closed shadow root so the page can't read
    // the toast contents via MutationObserver on documentElement.
    // The host element is generic-named and contains no text —
    // observers see only an empty <div id="ls-honeypot-host">.
    var host = document.createElement("div");
    host.id = "ls-honeypot-host";
    host.style.cssText = "all:initial;position:fixed;top:16px;right:16px;z-index:2147483646;";
    var shadow;
    try {
      shadow = host.attachShadow({ mode: "closed" });
    } catch (_e) {
      // Browsers that pre-date attachShadow shouldn't be in scope
      // for this product. Fall back to plain DOM — the page can
      // observe it, but the shield itself still worked.
      shadow = host;
    }
    var toast = document.createElement("div");
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.style.cssText = [
      "background:#082f49",
      "color:#e0f2fe",
      "padding:14px 18px",
      "border-radius:10px",
      "box-shadow:0 12px 32px rgba(0,0,0,0.45)",
      "border:1px solid #0ea5e9",
      "font:13px/1.5 -apple-system,system-ui,sans-serif",
      "max-width:340px",
    ].join(";");
    toast.innerHTML =
      '<strong>🛡️ ' + _esc(_t("credguard_toast_title")) + '</strong>' +
      '<div style="margin-top:6px;color:#bae6fd">' +
      _esc(_t("credguard_toast_body")) +
      "</div>";
    shadow.appendChild(toast);
    document.documentElement.appendChild(host);
    setTimeout(function () {
      if (host.parentNode) host.parentNode.removeChild(host);
    }, 8000);
  }

  // ── Evaluate one password input ──
  function _evaluate(passwordInput) {
    if (!passwordInput || passwordInput._lsGuardSeen) return;
    passwordInput._lsGuardSeen = true;

    var form = passwordInput.form;
    var actionCheck = form ? _classifyFormAction(form) : { mismatch: false };
    var brandCheck = _classifyVisibleHost();
    var tldCheck = _classifyTld();

    var triggers = 0;
    if (actionCheck.mismatch && actionCheck.scheme === "https:") triggers += 1;
    // HTTP action on a password page is its own escalation — always warn.
    if (actionCheck.mismatch && actionCheck.scheme === "http:") triggers += 2;
    if (brandCheck.typosquat) triggers += 2;
    if (tldCheck.suspicious) triggers += 1;
    if (_strictMode) triggers += 2;

    var evidence = {
      pageFlagged: _strictMode,
      // One weak signal on its own: a real site on a .top address, or a
      // login that posts to the company's other domain, looks like this too.
      weak: triggers === 1,
      mismatch: actionCheck.mismatch,
      actionHost: actionCheck.actionHost,
      scheme: actionCheck.scheme,
      typosquat: brandCheck.typosquat,
      brand: brandCheck.brand,
      legit: brandCheck.legit,
      host: brandCheck.host,
      tldSuspicious: tldCheck.suspicious,
      tld: tldCheck.tld,
    };

    _log("evaluate", { triggers: triggers, evidence: evidence });

    if (triggers < 1) return;

    // If the typosquat brand is known, defer the render so we can
    // double-check the backend allowlist. The local LEGIT_AUTH_HOSTS
    // covers federated SSO; the backend list covers brand-specific
    // verified login hosts (paypal → paypal.com, chase → secure01a.
    // chase.com). If the FORM ACTION hits the brand's verified list,
    // the form is plausibly legitimate even though the host looks
    // like a typosquat — skip the warning for those cases.
    // Not when the URL check already blocked this page: a kit that relays
    // the password to the real brand's host is still a scam page.
    if (evidence.typosquat && evidence.brand && actionCheck.actionHost && !evidence.pageFlagged) {
      _fetchVerifiedHosts(evidence.brand).then(function (hosts) {
        if (hosts && hosts.indexOf(actionCheck.actionHost) >= 0) {
          _log("brand verified host match — skipping warning", evidence.brand);
          return;
        }
        _renderWarning(form, evidence);
      });
    } else {
      _renderWarning(form, evidence);
    }
  }

  // ── Page scan + MutationObserver ──
  function _scanForPasswordFields(root) {
    var inputs = (root || document).querySelectorAll(
      'input[type="password"]:not([data-ls-guard-seen])',
    );
    for (var i = 0; i < inputs.length; i++) {
      inputs[i].setAttribute("data-ls-guard-seen", "1");
      _evaluate(inputs[i]);
    }
  }

  function _observeDom() {
    var mo = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (node && node.nodeType === 1) {
            if (node.tagName === "INPUT" && node.type === "password") {
              _evaluate(node);
            } else if (typeof node.querySelectorAll === "function") {
              _scanForPasswordFields(node);
            }
          }
        }
      }
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
  }

  // ── Background-script integration ──
  // The background promotes us into strict mode once this page's block
  // page has been shown (PAGE_BLOCKED). Password fields already on the
  // page are evaluated again with that knowledge.
  function _enterStrictMode() {
    if (_strictMode) return;
    _strictMode = true;
    _log("strict mode enabled");
    var inputs = document.querySelectorAll('input[type="password"]');
    for (var i = 0; i < inputs.length; i++) {
      inputs[i]._lsGuardSeen = false;
      _evaluate(inputs[i]);
    }
  }

  try {
    chrome.runtime.onMessage.addListener(function (msg) {
      if (msg && msg.type === "CREDGUARD_STRICT") _enterStrictMode();
    });
  } catch (e) { /* not in extension context */ }

  // For the table tests in scripts/test-extension-core.mjs. A content
  // script's globals live in the extension's isolated world; the page never
  // sees them.
  GUARD_ROOT.cleanwayCredentialGuard = Object.freeze({
    siteOf: _siteOf,
    sameSite: _sameSite,
    imitatedBrand: _imitatedBrand,
  });

  // ── Entry ──
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      _scanForPasswordFields();
      _observeDom();
    });
  } else {
    _scanForPasswordFields();
    _observeDom();
  }
})();
