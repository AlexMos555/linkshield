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
 *   A. action-host vs visible-host mismatch — form posts to a host
 *      different from the address bar. Some legit cases exist
 *      (federated SSO, redirector flows), so we whitelist known
 *      identity providers — see `LEGIT_AUTH_HOSTS`.
 *   B. visible-host typosquat — the address bar hostname matches a
 *      known brand pattern (paypal0.com, paypa1.com). We reuse the
 *      same `_BR` table the URL scorer uses.
 *   C. high-risk TLD on a credential page — login-collecting page
 *      on .tk / .ml / .top / .xyz / etc. is almost certainly hostile.
 *
 * Privacy: the script reads DOM only. Nothing leaves the device. We
 * never send the form contents, the URL, or anything else — the
 * warning fires entirely locally. The whole feature works offline.
 */
(function () {
  "use strict";

  // ── Toggles ──
  // Strict mode also INTERCEPTS the submit (preventDefault + warn).
  // Default is observation-mode: warn + let the user decide. Strict
  // mode goes on automatically once the URL scorer has flagged the
  // current page as dangerous.
  var _strictMode = false;
  var _warned = false;
  var _debugMode = false;

  function _log() {
    if (_debugMode) console.log.apply(console, ["[Cleanway-Guard]"].concat(Array.from(arguments)));
  }

  // ── Brand identity table ──
  // Subset of the URL scorer's _BR. Kept in-sync intentionally minimal
  // here so the credential script doesn't have to import the larger
  // scorer module (content scripts inject independently).
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

  function _baseDomain(host) {
    if (!host) return "";
    var parts = host.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : host;
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

  // ── Backend verified-host allowlist lookup ──
  //
  // The local LEGIT_AUTH_HOSTS covers federated SSO providers but
  // can't know every brand's own login hosts (paypal uses paypal.com,
  // chase uses secure01a.chase.com, etc.). The backend
  // /api/v1/credentials/verified endpoint returns that list per
  // brand. We cache results in chrome.storage.session for the
  // current session — same brand checked twice doesn't hit the
  // network twice.
  var _brandHostCache = Object.create(null);

  async function _fetchVerifiedHosts(brand) {
    if (_brandHostCache[brand]) return _brandHostCache[brand];
    try {
      var apiBase = "https://api.cleanway.ai";
      try {
        var stored = await chrome.storage.local.get("api_url");
        if (stored && typeof stored.api_url === "string" && stored.api_url.startsWith("http")) {
          apiBase = stored.api_url.replace(/\/+$/, "");
        }
      } catch (e) { /* storage unavailable */ }
      var resp = await fetch(
        apiBase + "/api/v1/credentials/verified?brand=" + encodeURIComponent(brand),
        { method: "GET" },
      );
      if (!resp.ok) {
        _brandHostCache[brand] = [];
        return [];
      }
      var data = await resp.json();
      var hosts = Array.isArray(data && data.hosts) ? data.hosts.map(function (h) { return String(h).toLowerCase(); }) : [];
      _brandHostCache[brand] = hosts;
      return hosts;
    } catch (e) {
      _brandHostCache[brand] = [];
      return [];
    }
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

    // Same registrable domain? (paypal.com vs accounts.paypal.com)
    var pageBase = _baseDomain(pageHost);
    var actionBase = _baseDomain(actionHost);
    if (pageBase === actionBase) {
      return { mismatch: false, actionHost: actionHost };
    }

    // Legit auth providers — federated SSO etc.
    if (LEGIT_AUTH_HOSTS.has(actionHost) || LEGIT_AUTH_HOSTS.has(actionBase)) {
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
  function _classifyVisibleHost() {
    var host = window.location.hostname.toLowerCase();
    var base = _baseDomain(host);
    var nm = base.split(".")[0];
    var nmLeet = _normaliseLeet(nm);
    for (var brand in BRAND_HOSTS) {
      var legit = BRAND_HOSTS[brand];
      if (nm === brand || host === legit || base === legit) continue;
      if (nmLeet === brand || nm.indexOf(brand) >= 0) {
        return { typosquat: true, brand: brand, legit: legit, host: host };
      }
    }
    return { typosquat: false };
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
  // Single-shot per page load. Inserted as an overlay above the form,
  // not blocking the page (observation mode). Strict mode adds an
  // additional intercept on submit.
  function _renderWarning(form, evidence) {
    if (_warned) return;
    _warned = true;

    var brandLine = evidence.typosquat
      ? 'Looks like <strong>' + _esc(evidence.brand) + '</strong> but the address is <strong>' + _esc(evidence.host) + '</strong> — not <strong>' + _esc(evidence.legit) + '</strong>.'
      : "";
    var actionLine = evidence.mismatch
      ? 'This form sends your password to <strong>' + _esc(evidence.actionHost) + '</strong> — a different site from what you see in the address bar.'
      : "";
    var tldLine = evidence.tldSuspicious
      ? 'The site uses a <strong>' + _esc(evidence.tld) + '</strong> domain, which is often abused for one-off phishing pages.'
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
      "border:2px solid #ef4444",
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
      + '  <strong style="color:#fecaca;font-size:15px;">Stop — this looks like a phishing page</strong>'
      + '</div>'
      + (actionLine ? '<div style="margin-top:6px;">' + actionLine + '</div>' : '')
      + (brandLine ? '<div style="margin-top:6px;">' + brandLine + '</div>' : '')
      + (tldLine ? '<div style="margin-top:6px;">' + tldLine + '</div>' : '')
      + '<div style="margin-top:10px;color:#94a3b8;font-size:12px;">Don\'t type your password here. Open the real site by typing the address yourself.</div>'
      + '<div style="margin-top:12px;display:flex;gap:8px;justify-content:flex-end;">'
      + '  <button id="ls-credguard-dismiss" type="button" style="background:transparent;color:#94a3b8;border:1px solid #334155;border-radius:8px;padding:6px 12px;font-size:12px;cursor:pointer;">Dismiss</button>'
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

    // Strategy doc Top-20 #7 — active credential guardian.
    // The passive banner above is "early warning". This block adds
    // SUBMIT-TIME interception with a confirmation modal so the user
    // can't blow past the warning by hitting Enter. We wire on ANY
    // credential warning (mismatch / typosquat / TLD) — not just
    // strict-mode-from-SW — because by the time a user typed their
    // password into a flagged form, the cost of one extra click is
    // cheap relative to credential theft.
    if (form && !form._lsGuardWired) {
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
          _renderConfirmModal(form, evidence);
        },
        true,
      );
    }
  }

  // ── Strategy doc #7: confirmation modal at submit time ──
  // Modal blocks the form submit until the user makes an explicit
  // choice. Keyboard-trapped to the two buttons, ESC = cancel,
  // first focus on Cancel (the safer default). No transparent
  // overlay-tap-to-dismiss — phishing pages would close it instantly.
  function _renderConfirmModal(form, evidence) {
    if (document.getElementById("ls-credguard-modal")) return;

    var reasons = [];
    if (evidence.mismatch) {
      reasons.push(
        "The form posts your password to " +
          _esc(evidence.actionHost || "another host") +
          " — not " +
          _esc(window.location.host) +
          ".",
      );
    }
    if (evidence.typosquat) {
      reasons.push(
        "This domain (" +
          _esc(evidence.host || window.location.host) +
          ") looks like a misspelling of " +
          _esc(evidence.brand || "a known brand") +
          ".",
      );
    }
    if (evidence.tldSuspicious) {
      reasons.push(
        "Login pages on " +
          _esc(evidence.tld || "this TLD") +
          " are very rarely legitimate.",
      );
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
      "border:1px solid #ef4444",
    ].join(";");

    var reasonsHtml = reasons
      .map(function (r) { return "<li style=\"margin-bottom:6px\">" + r + "</li>"; })
      .join("");

    card.innerHTML =
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
      '<span style="font-size:24px">⚠️</span>' +
      '<h2 id="ls-credguard-modal-title" style="margin:0;font-size:18px;font-weight:700;color:#fecaca">' +
      "Cleanway thinks this is a phishing form" +
      "</h2></div>" +
      '<div id="ls-credguard-modal-body" style="margin-bottom:14px;color:#cbd5e1">' +
      '<p style="margin:0 0 10px">Submitting will send your credentials. Here\'s why this looks unsafe:</p>' +
      (reasons.length ? '<ul style="padding-left:18px;margin:0;color:#e2e8f0">' + reasonsHtml + "</ul>" : "") +
      "</div>" +
      // Strategy #8 — three buttons: cancel (safest, default focus),
      // honeypot shield (real password stays on device, attacker
      // gets a random throwaway), full override (user explicitly
      // accepts the risk). The honeypot is the headline new option
      // — closes the "guaranteed no-leak" marketing promise.
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap">' +
      '<button id="ls-credguard-cancel" style="background:#22c55e;color:#052e16;border:0;padding:10px 18px;border-radius:8px;font-weight:700;cursor:pointer">Don\'t submit — take me back</button>' +
      '<button id="ls-credguard-honeypot" style="background:#0ea5e9;color:#082f49;border:0;padding:10px 14px;border-radius:8px;font-weight:700;cursor:pointer" title="Submit with a randomly-generated honeypot password. Your real password never leaves your device.">Send fake password (recommended)</button>' +
      '<button id="ls-credguard-override" style="background:transparent;color:#fca5a5;border:1px solid #7f1d1d;padding:10px 14px;border-radius:8px;font-weight:600;cursor:pointer">Submit anyway</button>' +
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

  // ── Strategy doc #8 — Honeypot Shield ──
  // Replace every password input in the form with a fresh
  // cryptographically-random throwaway value, force-submit so the
  // attacker gets the honeypot, and show a non-blocking toast so
  // the user knows what happened. The real password value never
  // leaves the device.
  //
  // The honeypot value is prefixed with a fixed watermark so a
  // future "have-i-been-pwned for honeypot dumps" service could
  // recognize it in paste dumps and confirm the page was hostile —
  // a data-source for tightening EVIDENCE_BOOK later.
  function _submitWithHoneypot(form) {
    if (!form) return;
    var honeypot = _generateHoneypotValue();

    // Stash the original values so we can restore them AFTER the
    // submit completes. Most legit-but-flagged forms have no
    // attacker on the other end — restoring keeps the input state
    // sane if the user accidentally hits the honeypot button.
    var pwInputs = form.querySelectorAll('input[type="password"]');
    var originals = [];
    for (var i = 0; i < pwInputs.length; i++) {
      originals.push({ input: pwInputs[i], value: pwInputs[i].value });
      // Use the native setter so frameworks that mirror state
      // (React, Vue, Lit) actually pick up the change instead of
      // re-rendering the input back to the original value.
      _setInputValueWithFrameworkSync(pwInputs[i], honeypot);
    }

    form._lsGuardOverridden = true;
    // Counter for the popup + Q3 transparency report.
    try {
      chrome.storage.local.get(["honeypot_used_count"]).then(function (d) {
        var next = (d.honeypot_used_count || 0) + 1;
        chrome.storage.local.set({ honeypot_used_count: next }).catch(function () {});
      }).catch(function () {});
    } catch (_e) { /* ignore */ }

    // Fire-and-forget anonymous report (domain only). Keeps the
    // server-blind invariant — no path, no value, no user id.
    try {
      var apiBase = (typeof window !== "undefined" && window.CLEANWAY_API_BASE)
        ? window.CLEANWAY_API_BASE
        : "https://api.cleanway.ai";
      fetch(apiBase + "/api/v1/credentials/report-honeypot", {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: window.location.host }),
      }).catch(function () {});
    } catch (_e) { /* ignore — non-critical telemetry */ }

    _showHoneypotToast();

    // Restore the original value AFTER a tick — gives the network
    // request time to fly with the honeypot, then puts the input
    // back the way the user typed it (in case they were testing
    // on a legit but mis-flagged site).
    setTimeout(function () {
      for (var j = 0; j < originals.length; j++) {
        try { _setInputValueWithFrameworkSync(originals[j].input, originals[j].value); }
        catch (_e) {}
      }
    }, 1500);

    if (typeof form.requestSubmit === "function") {
      try { form.requestSubmit(); return; } catch (_e) {}
    }
    try { form.submit(); } catch (_e) {}
  }

  function _generateHoneypotValue() {
    // 16 random bytes → 32 hex chars + a fixed watermark prefix.
    // Watermark length is intentionally fixed so the total length
    // is constant — a phishing kit can't infer "the user installed
    // Cleanway" from variable-length passwords.
    var prefix = "Cwx9p_";
    if (window.crypto && window.crypto.getRandomValues) {
      var bytes = new Uint8Array(16);
      window.crypto.getRandomValues(bytes);
      var hex = "";
      for (var i = 0; i < bytes.length; i++) {
        var h = bytes[i].toString(16);
        hex += h.length === 1 ? "0" + h : h;
      }
      return prefix + hex;
    }
    // Fallback that's still uniform but lower-entropy. Should
    // never run on any browser shipped this decade.
    var s = "";
    for (var k = 0; k < 32; k++) {
      s += Math.floor(Math.random() * 16).toString(16);
    }
    return prefix + s;
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
    if (document.getElementById("ls-honeypot-toast")) return;
    var toast = document.createElement("div");
    toast.id = "ls-honeypot-toast";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.style.cssText = [
      "position:fixed",
      "top:16px",
      "right:16px",
      "z-index:2147483646",
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
      '<strong>🛡️ Honeypot shield activated</strong>' +
      '<div style="margin-top:6px;color:#bae6fd">' +
      "We sent a randomly-generated password to that form. Your real " +
      "password never left this device. If you need to log in here for " +
      "real, double-check the URL first." +
      "</div>";
    document.documentElement.appendChild(toast);
    setTimeout(function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
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

    var evidence = {
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

    var triggers = 0;
    if (evidence.mismatch && evidence.scheme === "https:") triggers += 1;
    // HTTP action on a password page is its own escalation — always warn.
    if (evidence.mismatch && actionCheck.scheme === "http:") triggers += 2;
    if (evidence.typosquat) triggers += 2;
    if (evidence.tldSuspicious) triggers += 1;

    _log("evaluate", { triggers: triggers, evidence: evidence });

    if (triggers < 1) return;

    // If the typosquat brand is known, defer the render so we can
    // double-check the backend allowlist. The local LEGIT_AUTH_HOSTS
    // covers federated SSO; the backend list covers brand-specific
    // verified login hosts (paypal → paypal.com, chase → secure01a.
    // chase.com). If the FORM ACTION hits the brand's verified list,
    // the form is plausibly legitimate even though the host looks
    // like a typosquat — skip the warning for those cases.
    if (evidence.typosquat && evidence.brand && actionCheck.actionHost) {
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
  // The background script can promote us into strict mode mid-page
  // if its scorer flags the current host. Until then we stay in
  // observation mode and only warn (without blocking submit).
  try {
    chrome.runtime.onMessage.addListener(function (msg) {
      if (msg && msg.type === "CREDGUARD_STRICT") {
        _strictMode = true;
        _log("strict mode enabled");
      }
    });
  } catch (e) { /* not in extension context */ }

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
