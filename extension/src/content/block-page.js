/**
 * Block Page — full-screen warning overlay for scam sites.
 *
 * The most critical UX moment in Cleanway: user is about to lose money
 * to a scammer. Plain language, no jargon, 5-second countdown before
 * "I understand the risk" option becomes clickable.
 *
 * Localized via chrome.i18n.getMessage (_locales/<lang>/messages.json).
 * Falls back to English if chrome.i18n is unavailable (preview mode).
 */

// ─── i18n helper with English fallback ────────────────────────
const BLOCK_EN = {
  block_title: "STOP",
  block_subtitle_scam: "This is a scam site",
  block_explanation: "$DOMAIN$ is pretending to be someone else so it can steal your information.",
  block_brand_impersonation: "This site pretends to be $BRAND$",
  block_scheme_heading: "How scammers use sites like this:",
  block_scheme_step1: "You will be asked for your password or bank details",
  block_scheme_step2: "The scammer steals what you type",
  block_scheme_step3: "They drain your account or steal your identity",
  block_back_button: "Go back to safety",
  block_proceed_button: "I understand the risk — open anyway",
  block_proceed_countdown: "Wait $N$ seconds…",
  block_trust_footer: "Protected by Cleanway. Your data stays on your device.",
  block_voice_alert: "Stop. The site $DOMAIN$ is dangerous. Do not type your password.",
  // Strategy Top-20 #4 — Annotated Evidence cards
  block_evidence_heading: "Why we blocked this site",
};

// Per-signal evidence cards. The block page renders the top 4 of
// these matching the verdict's reasons array — the user sees the
// concrete signals that fired with plain-language explanations they
// can act on. Anything not in this map falls back to the raw
// `reason.detail` string from the backend.
//
// Each row: {
//   icon: emoji or unicode glyph (rendered aria-hidden),
//   title: short headline (≤ 3 words),
//   body:  one-sentence explanation calibrated for non-technical
//          users — describe WHAT it means, not WHY the algorithm
//          fired.
// }
// All English; locale extension happens via the i18n keys above. The
// signal keys here mirror the analyzer's reason.signal field.
const EVIDENCE_BOOK = {
  blocklist: {
    icon: "⛔",
    title: "Reported to global blocklists",
    body: "Security researchers have already flagged this site for phishing or malware.",
  },
  safe_browsing: {
    icon: "🔎",
    title: "Google flagged it",
    body: "Google Safe Browsing — used by Chrome/Firefox/Safari — marks this site as unsafe.",
  },
  phishtank: {
    icon: "🎣",
    title: "PhishTank reported it",
    body: "The community-run PhishTank database has matching phishing reports.",
  },
  urlhaus: {
    icon: "💀",
    title: "URLhaus malware host",
    body: "abuse.ch URLhaus has this host on its malware-distribution list.",
  },
  threatfox: {
    icon: "🦊",
    title: "ThreatFox IOC match",
    body: "abuse.ch ThreatFox links this host to an active threat indicator.",
  },
  malware_bazaar: {
    icon: "🦠",
    title: "MalwareBazaar samples",
    body: "MalwareBazaar has malware samples tied to this host.",
  },
  feodo: {
    icon: "📡",
    title: "Active botnet C2",
    body: "Feodo Tracker lists this host as an active botnet command-and-control server.",
  },
  spamhaus_dbl: {
    icon: "📧",
    title: "Spamhaus DBL listed",
    body: "Spamhaus' domain blocklist — used by email providers worldwide — has this host.",
  },
  surbl: {
    icon: "🔗",
    title: "SURBL URI blocklist",
    body: "SURBL flags this host as appearing in unsolicited mail.",
  },
  alienvault: {
    icon: "👽",
    title: "OTX threat pulse",
    body: "AlienVault OTX has open threat pulses referencing this host.",
  },
  ipqs: {
    icon: "📊",
    title: "IPQS risk score high",
    body: "IPQualityScore rates this host as high-risk for phishing.",
  },
  typosquatting: {
    icon: "✏️",
    title: "Imitates a real brand",
    body: "The address looks like a well-known brand — but it isn't owned by them.",
  },
  brand_impersonation: {
    icon: "🎭",
    title: "Brand impersonation",
    body: "Page content imitates a known brand's login or checkout flow.",
  },
  suspicious_tld: {
    icon: "🌐",
    title: "Disposable domain",
    body: "This TLD (.tk, .xyz, etc.) is often abused for one-off phishing pages.",
  },
  homograph: {
    icon: "🔠",
    title: "Look-alike letters",
    body: "Some characters are visual swaps (1→l, 0→o) hiding the real address.",
  },
  no_https: {
    icon: "🔓",
    title: "No HTTPS",
    body: "The site uses plain HTTP — anything you type is sent unencrypted.",
  },
  free_ssl: {
    icon: "🪪",
    title: "Throwaway certificate",
    body: "The SSL certificate is from a free issuer often used by short-lived sites.",
  },
  young_domain: {
    icon: "🐣",
    title: "Brand-new domain",
    body: "The site was registered very recently — a strong phishing signal.",
  },
  fast_flux: {
    icon: "🌀",
    title: "Fast-flux hosting",
    body: "DNS records change rapidly — characteristic of bulletproof hosting.",
  },
  redirect_chain: {
    icon: "↪️",
    title: "Suspicious redirect chain",
    body: "Multiple hops before landing here — often used to hide the real destination.",
  },
  url_pii_leak: {
    icon: "🕵️",
    title: "Leaks private data in URL",
    body: "The address itself carries your email or auth token — anyone who can see the link can grab them.",
  },
  malware_bazaar: {
    icon: "🦠",
    title: "Distributes malware",
    body: "abuse.ch MalwareBazaar has seen this host shipping known malware samples.",
  },
  feodo: {
    icon: "📡",
    title: "Active botnet C2 server",
    body: "abuse.ch Feodo Tracker confirms this host is currently controlling a botnet.",
  },
  favicon_brand_clone: {
    icon: "🎭",
    title: "Brand-clone phishing",
    body: "This page serves a real brand's favicon but is hosted on an unrelated domain — a classic credential-theft signature.",
  },
  tranco_popularity: {
    icon: "✅",
    title: "Among the most-visited sites",
    body: "This domain is in the worldwide top sites — counted as a trust signal here, but other risks above still apply.",
  },
  invalid: {
    icon: "❌",
    title: "Invalid address",
    body: "The address itself is malformed; it might be a copy-paste trap.",
  },
};

function _evidenceCardFor(reason) {
  if (!reason) return null;
  var key = reason.signal || "";
  var card = EVIDENCE_BOOK[key];
  if (card) {
    return { icon: card.icon, title: card.title, body: card.body };
  }
  // Unknown signal: use raw detail as body, generic icon.
  return {
    icon: "⚠️",
    title: "Risk signal",
    body: String(reason.detail || "Detected by Cleanway's scoring engine."),
  };
}

function bt(key, subs) {
  try {
    if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
      const msg = chrome.i18n.getMessage(key, subs || []);
      if (msg) return msg;
    }
  } catch (_) { /* preview mode */ }
  let out = BLOCK_EN[key] || key;
  if (subs && subs.length) {
    out = out.replace(/\$(DOMAIN|BRAND|N)\$/g, () => subs[0]);
  }
  return out;
}

// HTML escape (XSS safety for domain + brand substitution)
function e(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function isRTL() {
  try {
    if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getUILanguage) {
      return /^ar(-|$)/i.test(chrome.i18n.getUILanguage());
    }
  } catch (_) {}
  return document.documentElement.dir === "rtl";
}

// ── Grandma Mode (Strategy Top-20 #3) ────────────────────────────
//
// Calibrated for users 65+: oversized text, voice-narrated warnings,
// simplified copy. We don't change the verdict, just the way the
// verdict is delivered. The skill_level read is synchronous from
// chrome.storage; we cache it so a slow storage round-trip on a
// busy page doesn't delay the block overlay paint.
let _cachedSkillLevel = null;

function _readSkillLevel(cb) {
  if (_cachedSkillLevel !== null) {
    cb(_cachedSkillLevel);
    return;
  }
  try {
    chrome.storage.local.get(["skill_level"], function (data) {
      _cachedSkillLevel = (data && data.skill_level) || "regular";
      cb(_cachedSkillLevel);
    });
  } catch (_) {
    cb("regular");
  }
}

/**
 * Speak a phrase via the Web Speech API, in the user's UI language
 * when available. Picks a voice from the platform's installed set;
 * if none match the locale we fall back to whatever the browser
 * picks by default. Voice picks vary widely across OS/browser so we
 * keep the phrase short and don't depend on any particular SSML
 * features — plain text works everywhere.
 */
function _speakAlert(text) {
  if (typeof window === "undefined" || !window.speechSynthesis) return;
  try {
    var utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 0.95; // slightly slower for clarity
    utterance.pitch = 1.0;
    utterance.volume = 1.0;
    // Locale hint — Web Speech picks the closest match.
    if (chrome && chrome.i18n && chrome.i18n.getUILanguage) {
      utterance.lang = chrome.i18n.getUILanguage();
    }
    // Cancel any in-flight utterance from a previous block so we don't
    // queue up multiple warnings if the user clicks through several
    // dangerous links quickly.
    window.speechSynthesis.cancel();
    window.speechSynthesis.speak(utterance);
  } catch (_) {
    /* Some browsers (Brave with shields up, Firefox with TTS disabled)
       throw on the synthesis call. Non-fatal — the visual warning
       still appears. */
  }
}

// Detect impersonated brand from scoring reasons
function extractBrand(reasons) {
  if (!reasons || !Array.isArray(reasons)) return null;
  for (const r of reasons) {
    if (!r || !r.detail) continue;
    const m = String(r.detail).match(/(?:typosquat|imitat|pretend|mimic)[^\w]*([A-Z][\w.-]+)/i);
    if (m) return m[1];
  }
  return null;
}

/**
 * Show full-screen block page overlay.
 * @param {{domain: string, score?: number, reasons?: Array<{detail: string}>}} result
 */
export function showBlockPage(result) {
  if (document.getElementById("ls-block-overlay")) return;

  const { domain = "", reasons = [] } = result || {};
  const brand = extractBrand(reasons);
  const rtl = isRTL();

  const overlay = document.createElement("div");
  overlay.id = "ls-block-overlay";
  overlay.setAttribute("role", "alertdialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "ls-block-title");
  if (rtl) overlay.setAttribute("dir", "rtl");

  const brandLine = brand
    ? `<p class="ls-block-brand">${e(bt("block_brand_impersonation", [brand]))}</p>`
    : "";

  // Strategy Top-20 #4 — Annotated Evidence Cards.
  //
  // Pick the top 4 distinct signals from the verdict's reasons array
  // (the scorer already ranks them by weight). De-duplicate by signal
  // so we don't show two "typosquatting" cards if the scorer flagged
  // it twice (e.g. local + remote). Less is more — 4 cards keep the
  // block page readable without scrolling on a phone-sized viewport.
  const _seenSig = new Set();
  const evidenceCards = (reasons || [])
    .filter((r) => r && r.signal && !_seenSig.has(r.signal) && _seenSig.add(r.signal))
    .slice(0, 4)
    .map((r) => _evidenceCardFor(r))
    .filter(Boolean);
  const evidenceHTML = evidenceCards.length
    ? `<div class="ls-block-evidence" aria-label="${e(bt("block_evidence_heading"))}">
         <h2 class="ls-block-evidence-heading">${e(bt("block_evidence_heading"))}</h2>
         <div class="ls-block-evidence-grid">
           ${evidenceCards
             .map(
               (c) => `
                 <div class="ls-block-evidence-card">
                   <span class="ls-block-evidence-icon" aria-hidden="true">${e(c.icon)}</span>
                   <div class="ls-block-evidence-text">
                     <div class="ls-block-evidence-title">${e(c.title)}</div>
                     <div class="ls-block-evidence-body">${e(c.body)}</div>
                   </div>
                 </div>`,
             )
             .join("")}
         </div>
       </div>`
    : "";

  overlay.innerHTML = `
    <style id="ls-block-styles">
      #ls-block-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        background-image:
          radial-gradient(ellipse at top, rgba(239,68,68,0.4) 0%, transparent 60%),
          radial-gradient(ellipse at bottom, rgba(15,23,42,0.8) 0%, transparent 50%),
          linear-gradient(180deg, #7f1d1d 0%, #450a0a 100%);
        color: #fef2f2;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans Arabic", sans-serif;
        display: flex; align-items: center; justify-content: center;
        padding: 40px 24px; overflow-y: auto;
        animation: ls-fade-in 0.3s ease-out;
      }
      @keyframes ls-fade-in { from { opacity: 0; } to { opacity: 1; } }
      #ls-block-overlay * { box-sizing: border-box; }
      .ls-block-card {
        max-width: 560px; width: 100%; text-align: center;
        background: rgba(15, 23, 42, 0.75);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-radius: 20px;
        padding: 40px 32px;
        box-shadow: 0 30px 80px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(239, 68, 68, 0.2);
      }
      .ls-block-stop-icon {
        font-size: 72px; line-height: 1; margin-bottom: 16px;
        animation: ls-pulse 1.5s ease-in-out infinite;
      }
      @keyframes ls-pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.08); } }
      .ls-block-title {
        font-size: 56px; font-weight: 900; color: #fff;
        letter-spacing: 0.15em; margin: 0 0 8px; line-height: 1;
        text-shadow: 0 2px 20px rgba(239, 68, 68, 0.5);
      }
      .ls-block-subtitle {
        font-size: 22px; font-weight: 700; color: #fca5a5; margin: 0 0 20px;
      }
      .ls-block-domain {
        display: inline-block;
        background: rgba(239, 68, 68, 0.2);
        border: 1px solid rgba(239, 68, 68, 0.5);
        color: #fecaca;
        padding: 6px 14px; border-radius: 8px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 15px; font-weight: 600; margin-bottom: 20px;
        word-break: break-all;
      }
      .ls-block-explanation {
        font-size: 16px; color: #fee2e2; line-height: 1.5; margin: 0 0 8px;
      }
      .ls-block-brand {
        font-size: 14px; color: #fca5a5; font-style: italic; margin: 0 0 24px;
      }
      .ls-block-evidence {
        background: rgba(0, 0, 0, 0.32);
        border-radius: 14px; padding: 20px;
        margin-bottom: 20px; text-align: start;
        border: 1px solid rgba(239, 68, 68, 0.18);
      }
      .ls-block-evidence-heading {
        font-size: 13px; font-weight: 700; color: #fecaca; margin: 0 0 14px;
        text-transform: uppercase; letter-spacing: 0.05em;
      }
      .ls-block-evidence-grid {
        display: grid; grid-template-columns: 1fr; gap: 10px;
      }
      @media (min-width: 480px) {
        .ls-block-evidence-grid { grid-template-columns: 1fr 1fr; }
      }
      .ls-block-evidence-card {
        display: flex; gap: 12px; align-items: flex-start;
        background: rgba(127, 29, 29, 0.25);
        border: 1px solid rgba(239, 68, 68, 0.25);
        border-radius: 10px; padding: 10px 12px;
      }
      .ls-block-evidence-icon {
        flex-shrink: 0; font-size: 22px; line-height: 1.1;
      }
      .ls-block-evidence-title {
        font-size: 14px; font-weight: 700; color: #fff;
        margin-bottom: 3px; line-height: 1.25;
      }
      .ls-block-evidence-body {
        font-size: 12.5px; color: #fee2e2; line-height: 1.4;
      }
      .ls-block-scheme {
        background: rgba(0, 0, 0, 0.3);
        border-radius: 14px; padding: 20px;
        margin-bottom: 28px; text-align: start;
      }
      .ls-block-scheme-heading {
        font-size: 13px; font-weight: 700; color: #fecaca; margin: 0 0 12px;
        text-transform: uppercase; letter-spacing: 0.05em;
      }
      .ls-block-scheme-step {
        display: flex; gap: 12px; align-items: flex-start;
        margin: 10px 0; color: #fee2e2; font-size: 14px; line-height: 1.5;
      }
      .ls-block-scheme-step .ls-step-num {
        flex-shrink: 0; width: 26px; height: 26px; border-radius: 50%;
        background: rgba(239, 68, 68, 0.3); color: #fff;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: 13px; font-weight: 800;
        border: 1px solid rgba(239, 68, 68, 0.6);
      }
      .ls-block-actions {
        display: flex; flex-direction: column; gap: 12px; margin-top: 8px;
      }
      .ls-block-btn {
        display: block; width: 100%; padding: 16px 24px;
        border-radius: 12px; font-family: inherit; font-weight: 700; font-size: 17px;
        border: none; cursor: pointer; text-align: center;
        transition: transform 0.1s, background 0.15s, opacity 0.15s;
      }
      .ls-block-btn-back {
        background: #22c55e; color: #052e16;
        box-shadow: 0 6px 18px rgba(34, 197, 94, 0.3);
      }
      .ls-block-btn-back:hover { background: #16a34a; transform: translateY(-2px); }
      .ls-block-btn-proceed {
        background: transparent; color: #cbd5e1;
        border: 1px solid rgba(148, 163, 184, 0.3);
        font-size: 13px; font-weight: 500; padding: 10px 20px;
      }
      .ls-block-btn-proceed:not(:disabled):hover {
        background: rgba(148, 163, 184, 0.1); color: #e2e8f0;
      }
      .ls-block-btn-proceed:disabled { opacity: 0.5; cursor: wait; }
      .ls-block-footer {
        margin-top: 28px; font-size: 11px;
        color: rgba(254, 226, 226, 0.5);
        display: flex; align-items: center; justify-content: center; gap: 6px;
      }
      @media (max-width: 480px) {
        .ls-block-card { padding: 28px 20px; }
        .ls-block-title { font-size: 44px; }
        .ls-block-subtitle { font-size: 18px; }
        .ls-block-stop-icon { font-size: 60px; }
      }
    </style>

    <div class="ls-block-card" role="document">
      <div class="ls-block-stop-icon" aria-hidden="true">&#x26D4;</div>
      <h1 id="ls-block-title" class="ls-block-title">${e(bt("block_title"))}</h1>
      <p class="ls-block-subtitle">${e(bt("block_subtitle_scam"))}</p>
      <div class="ls-block-domain" dir="ltr">${e(domain)}</div>
      <p class="ls-block-explanation">${e(bt("block_explanation", [domain]))}</p>
      ${brandLine}

      ${evidenceHTML}

      <div class="ls-block-scheme">
        <h2 class="ls-block-scheme-heading">${e(bt("block_scheme_heading"))}</h2>
        <div class="ls-block-scheme-step">
          <span class="ls-step-num">1</span>
          <span>${e(bt("block_scheme_step1"))}</span>
        </div>
        <div class="ls-block-scheme-step">
          <span class="ls-step-num">2</span>
          <span>${e(bt("block_scheme_step2"))}</span>
        </div>
        <div class="ls-block-scheme-step">
          <span class="ls-step-num">3</span>
          <span>${e(bt("block_scheme_step3"))}</span>
        </div>
      </div>

      <div class="ls-block-actions">
        <button id="ls-block-back" class="ls-block-btn ls-block-btn-back" type="button">
          &#x2190; ${e(bt("block_back_button"))}
        </button>
        <button id="ls-block-proceed" class="ls-block-btn ls-block-btn-proceed" type="button" disabled>
          ${e(bt("block_proceed_countdown", ["5"]))}
        </button>
      </div>

      <p class="ls-block-footer">
        <span aria-hidden="true">&#x1F512;</span>
        <span>${e(bt("block_trust_footer"))}</span>
      </p>
    </div>
  `;

  document.body.appendChild(overlay);
  const prevOverflow = document.body.style.overflow;
  document.body.style.overflow = "hidden";

  // Strategy #3 — Grandma Mode behaviour.
  //
  // Apply once the overlay is in the DOM so the CSS variable cascade
  // takes effect on the painted node. We:
  //   - set an attribute on the overlay so the stylesheet can up-size
  //     fonts via attribute selectors,
  //   - inject inline overrides (CSS variables) to guarantee the
  //     overrides land regardless of the platform's default font
  //     size, and
  //   - kick off a voice alert in the user's UI locale.
  _readSkillLevel(function (lvl) {
    if (lvl === "granny") {
      overlay.setAttribute("data-skill", "granny");
      // Inline overrides — these out-scale the base values defined in
      // the embedded <style> above. We intentionally bump fonts by
      // ~45% (16→24, 22→32, 56→80) and increase line-height for
      // readability. Buttons go from 17 → 22 to make taps easier with
      // tremor / poor vision.
      var card = overlay.querySelector(".ls-block-card");
      if (card) card.style.padding = "56px 36px";
      var title = overlay.querySelector(".ls-block-title");
      if (title) {
        title.style.fontSize = "80px";
        title.style.letterSpacing = "0.18em";
      }
      var subtitle = overlay.querySelector(".ls-block-subtitle");
      if (subtitle) subtitle.style.fontSize = "32px";
      var explanation = overlay.querySelector(".ls-block-explanation");
      if (explanation) {
        explanation.style.fontSize = "24px";
        explanation.style.lineHeight = "1.6";
      }
      var domEl = overlay.querySelector(".ls-block-domain");
      if (domEl) domEl.style.fontSize = "20px";
      var stepsBtns = overlay.querySelectorAll(".ls-block-scheme-step, .ls-block-btn-back");
      stepsBtns.forEach(function (el) {
        if (el.classList.contains("ls-block-btn-back")) {
          el.style.fontSize = "22px";
          el.style.padding = "22px 28px";
        } else {
          el.style.fontSize = "20px";
        }
      });
      // Evidence card text up-sizing — keeps cards readable for users
      // with vision impairments without overflowing the column.
      var evTitles = overlay.querySelectorAll(".ls-block-evidence-title");
      evTitles.forEach(function (el) { el.style.fontSize = "18px"; });
      var evBodies = overlay.querySelectorAll(".ls-block-evidence-body");
      evBodies.forEach(function (el) { el.style.fontSize = "16px"; el.style.lineHeight = "1.5"; });
      var evIcons = overlay.querySelectorAll(".ls-block-evidence-icon");
      evIcons.forEach(function (el) { el.style.fontSize = "28px"; });

      // Voice alert.
      try {
        var voiceMsg = bt("block_voice_alert", [domain]);
        if (!voiceMsg || voiceMsg.indexOf("Cleanway blocked") !== -1
            || /^block_voice_alert/.test(voiceMsg)) {
          // Fallback to a hardcoded short phrase if the locale key
          // isn't there yet — we'll add it in i18n-strings shortly.
          voiceMsg = "Stop. This site is dangerous. Do not type your password.";
        }
        _speakAlert(voiceMsg);
      } catch (_) {
        /* speech failure non-fatal — visual block stays. */
      }
    }
  });

  // "Go back" — navigate to previous page (safest) or close tab
  const backBtn = overlay.querySelector("#ls-block-back");
  if (backBtn) {
    backBtn.addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        try {
          if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ type: "CLOSE_TAB" });
          } else {
            window.close();
          }
        } catch (_) { window.close(); }
      }
    });
    backBtn.focus();
  }

  // "I understand the risk" — enabled after 5-second countdown
  const proceedBtn = overlay.querySelector("#ls-block-proceed");
  if (proceedBtn) {
    let countdown = 5;
    proceedBtn.textContent = bt("block_proceed_countdown", [String(countdown)]);
    const interval = setInterval(() => {
      countdown--;
      if (countdown > 0) {
        proceedBtn.textContent = bt("block_proceed_countdown", [String(countdown)]);
      } else {
        clearInterval(interval);
        proceedBtn.disabled = false;
        proceedBtn.textContent = bt("block_proceed_button");
        proceedBtn.addEventListener("click", () => {
          overlay.remove();
          document.body.style.overflow = prevOverflow;
        }, { once: true });
      }
    }, 1000);
  }

  // Escape key → same as "Go back"
  overlay.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      ev.preventDefault();
      if (backBtn) backBtn.click();
    }
  });
}

// Preview hook — call from standalone preview HTML without chrome.* APIs
if (typeof window !== "undefined") {
  window.__LS_BLOCK_PREVIEW__ = function (opts) {
    showBlockPage({
      domain: (opts && opts.domain) || "sberbank-secure-login.ru",
      score: 95,
      reasons: (opts && opts.reasons) || [
        { detail: "Typosquat of sberbank.ru" },
        { detail: "Domain registered 2 days ago" },
      ],
    });
  };
}
