/**
 * Block Page — full-screen warning overlay for scam sites.
 *
 * The most critical UX moment in LinkShield: user is about to lose money
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
  block_trust_footer: "Protected by LinkShield. Your data stays on your device.",
};

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
