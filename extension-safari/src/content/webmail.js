/**
 * Cleanway Webmail Guardian — Gmail + Outlook Web + Yahoo Mail.
 *
 * Runs as a content script on mail.google.com, outlook.office.com /
 * outlook.live.com, and mail.yahoo.com. For the currently-open
 * conversation, it:
 *
 *   1. Extracts the subject, sender, reply-to, and body text.
 *   2. POSTs them to `/api/v1/email/analyze`.
 *   3. Renders a non-intrusive banner above the message:
 *        ✅ green   "Looks safe"
 *        ⚠️ amber   "Suspicious — check who sent it"
 *        🛑 red     "Likely a scam — don't click any links"
 *      Plus the risk score and, for amber and red, the most serious
 *      finding in one line (describeResult below).
 *
 * The banner is idempotent: we tag the injected node with a stable ID +
 * a MutationObserver watches for navigation (Gmail/Outlook are SPAs and
 * swap message bodies without reloading). On every swap we rescan.
 *
 * Privacy: only the subset of headers and body the analyzer needs are
 * sent. Recipients, thread IDs, attachment content — nothing else.
 */
(function () {
  "use strict";

  // ── Host adapters ────────────────────────────────────────────────────────
  // Each adapter knows the DOM of one webmail provider. Returns null if a
  // message isn't currently open (e.g., the user is on the inbox list).
  const ADAPTERS = {
    "mail.google.com": {
      container: () => document.querySelector('[role="main"] .ii.gt'),
      sender: () =>
        document.querySelector('.gD')?.getAttribute('email') || "",
      senderName: () =>
        document.querySelector('.gD')?.getAttribute('name') || "",
      replyTo: () => {
        const el = document.querySelector('[data-hovercard-id][email]');
        return el ? el.getAttribute('email') : "";
      },
      subject: () => document.querySelector('h2.hP')?.textContent || "",
      body: () => {
        const el = document.querySelector('[role="main"] .ii.gt .a3s');
        return { html: el?.innerHTML || "", text: el?.innerText || "" };
      },
      insertBanner: (banner, container) => {
        container.parentNode.insertBefore(banner, container);
      },
    },
    "outlook.office.com": outlookAdapter(),
    "outlook.live.com": outlookAdapter(),
    "mail.yahoo.com": {
      container: () =>
        document.querySelector('[data-test-id="message-view-body-content"]'),
      sender: () =>
        document.querySelector('[data-test-id="message-from"] [data-test-id="email-pill"]')?.getAttribute('data-email') || "",
      senderName: () =>
        document.querySelector('[data-test-id="message-from"] [data-test-id="email-pill"] span')?.textContent || "",
      replyTo: () => "",
      subject: () =>
        document.querySelector('[data-test-id="message-subject"]')?.textContent || "",
      body: () => {
        const el = document.querySelector('[data-test-id="message-view-body-content"]');
        return { html: el?.innerHTML || "", text: el?.innerText || "" };
      },
      insertBanner: (banner, container) => {
        container.parentNode.insertBefore(banner, container);
      },
    },
  };

  function outlookAdapter() {
    return {
      container: () =>
        document.querySelector('[role="document"] [aria-label*="Message body"]') ||
        document.querySelector('.ReadingPaneContainer .allowTextSelection'),
      sender: () => {
        const el = document.querySelector('[data-testid="message-header-from"] [data-testid="message-header-persona-primary"]');
        return el?.getAttribute('data-email') || "";
      },
      senderName: () => {
        const el = document.querySelector('[data-testid="message-header-from"] [data-testid="message-header-persona-primary"] span');
        return el?.textContent || "";
      },
      replyTo: () => "",
      subject: () => {
        const el = document.querySelector('[data-testid="message-subject-heading"]');
        return el?.textContent || "";
      },
      body: () => {
        const el = document.querySelector('[role="document"] [aria-label*="Message body"]') ||
                   document.querySelector('.ReadingPaneContainer .allowTextSelection');
        return { html: el?.innerHTML || "", text: el?.innerText || "" };
      },
      insertBanner: (banner, container) => {
        container.parentNode.insertBefore(banner, container);
      },
    };
  }

  // ── Config ───────────────────────────────────────────────────────────────
  const BANNER_ID = "cleanway-webmail-banner";
  const DEBOUNCE_MS = 600;
  const DEFAULT_API_BASE = "https://api.cleanway.ai";

  // ── Verdict → banner text ────────────────────────────────────────────────
  // Text in the browser's language (packages/i18n-strings extension.webmail).
  function t(key, subs) {
    try {
      return chrome.i18n.getMessage(key, subs || []) || key;
    } catch (e) {
      return key;
    }
  }

  // The analyzer (api/services/email_analyzer.py) explains each finding in
  // English (`message`), files it under a `category`, and names the kind of
  // sign with a stable `code`. The reader gets one line, in their language,
  // chosen by code: a category mixes strong and weak signs (a brand name
  // sent from a free mailbox, and a Reply-To on another domain, which shop
  // newsletters use every day, are both sender_spoofing), so a line per
  // category either accused the newsletter or undersold the fake bank.
  const FINDING_CODE_KEYS = Object.freeze({
    known_dangerous_link: "webmail_finding_url_reputation",
    brand_from_freemail: "webmail_finding_brand_from_freemail",
    brand_domain_mismatch: "webmail_finding_brand_domain_mismatch",
    sender_non_ascii: "webmail_finding_sender_non_ascii",
    reply_to_mismatch: "webmail_finding_reply_to_mismatch",
    spf_fail: "webmail_finding_auth_fail",
    dkim_fail: "webmail_finding_auth_fail",
    dmarc_fail: "webmail_finding_auth_fail",
    spf_softfail: "webmail_finding_spf_softfail",
    urgency: "webmail_finding_urgency",
    credential_request: "webmail_finding_credential_request",
    money_request: "webmail_finding_money_request",
    account_threat: "webmail_finding_account_threat",
    link_text_mismatch: "webmail_finding_link_text_mismatch",
  });

  // A finding with no code this build knows (an older API, or a code added
  // later) gets its category's line, worded to be true of every sign filed
  // there. A category nobody has mapped keeps the English message rather
  // than showing nothing.
  const FINDING_CATEGORY_KEYS = Object.freeze({
    url_reputation: "webmail_finding_url_reputation",
    sender_spoofing: "webmail_finding_sender_check",
    auth_fail: "webmail_finding_auth_unconfirmed",
    body_pattern: "webmail_finding_body_pattern",
    link_text_mismatch: "webmail_finding_link_text_mismatch",
  });

  function lookup(table, name) {
    return typeof name === "string" && Object.prototype.hasOwnProperty.call(table, name)
      ? table[name]
      : null;
  }

  function findingText(finding) {
    if (!finding) return "";
    const key = lookup(FINDING_CODE_KEYS, finding.code) || lookup(FINDING_CATEGORY_KEYS, finding.category);
    const localized = key ? t(key) : "";
    return localized && localized !== key ? localized : String(finding.message || "");
  }

  // The finding that weighs most. The analyzer lists them in a fixed order
  // (sender, auth, body, links), so the first one was often a weak sender
  // sign sitting above a link to a known dangerous site. Ties keep that order.
  function topFinding(findings) {
    let top = null;
    for (const f of Array.isArray(findings) ? findings : []) {
      if (f && (!top || (Number(f.severity) || 0) > (Number(top.severity) || 0))) top = f;
    }
    return top;
  }

  // What the banner says about one analysis result. A safe verdict names no
  // finding: a friend's "call me, it's urgent" is safe with one urgency
  // finding, and "Looks safe — no scam signs found" above "the text uses
  // scam tricks" said both at once. Its headline says "no serious signs"
  // when the analyzer did note something small.
  function describeResult(result) {
    const { level, score, findings } = result || {};
    const list = Array.isArray(findings) ? findings : [];
    const scoreText = t("badge_score", [String(Math.round(Number(score) || 0))]);
    if (level === "dangerous" || level === "suspicious") {
      const line = findingText(topFinding(list));
      return {
        level,
        headline: t(level === "dangerous" ? "webmail_dangerous" : "webmail_suspicious"),
        detail: line ? `${scoreText} • ${line}` : scoreText,
      };
    }
    return {
      level: "safe",
      headline: t(list.length ? "webmail_safe_minor" : "webmail_safe"),
      detail: scoreText,
    };
  }

  // The only thing this script puts on the shared isolated-world global:
  // the pure text helpers above, for scripts/test-extension-core.mjs. Set
  // before the host check, so the test can load this file off a mail page.
  window.__cleanwayWebmail = Object.freeze({ describeResult, findingText, topFinding });

  // ── Resolve adapter ──────────────────────────────────────────────────────
  const host = location.hostname;
  const adapter = ADAPTERS[host];
  if (!adapter) return;

  // ── Observation + debounced scan ─────────────────────────────────────────
  let scanTimer = null;
  let lastSignature = null;

  const observer = new MutationObserver(() => {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scheduleScan, DEBOUNCE_MS);
  });
  observer.observe(document.body, { childList: true, subtree: true });

  // Run once on initial load
  setTimeout(scheduleScan, DEBOUNCE_MS);

  function scheduleScan() {
    const container = adapter.container();
    if (!container) {
      // No open message — clean up any stale banner from a previous thread
      removeBanner();
      lastSignature = null;
      return;
    }

    const sig = container.dataset.cleanwaySignature ||
      `${adapter.subject()}|${adapter.sender()}|${container.textContent.length}`;
    if (sig === lastSignature) return; // already scanned this message
    lastSignature = sig;
    container.dataset.cleanwaySignature = sig;

    runScan(container).catch((err) => {
      console.warn("[Cleanway] webmail scan failed:", err && err.message);
    });
  }

  // ── Scan ─────────────────────────────────────────────────────────────────
  async function runScan(container) {
    const body = adapter.body();
    const payload = {
      from_address: adapter.sender(),
      from_display: adapter.senderName(),
      reply_to: adapter.replyTo(),
      subject: adapter.subject(),
      return_path: "",
      spf: null,
      dkim: null,
      dmarc: null,
      body_text: body.text || "",
      body_html: body.html || "",
    };

    renderBanner(container, { state: "scanning" });

    const apiBase = await getApiBase();
    const token = await getAuthToken();

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15_000);
    try {
      const resp = await fetch(`${apiBase}/api/v1/email/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
      if (!resp.ok) {
        // 429 means the public IP bucket is full — surface a quiet "slow
        // down" state rather than a red error.
        if (resp.status === 429) {
          renderBanner(container, { state: "rate_limited" });
          return;
        }
        throw new Error(`HTTP ${resp.status}`);
      }
      const result = await resp.json();
      renderBanner(container, { state: "ready", result });
    } catch (err) {
      console.warn("[Cleanway] webmail analyze failed:", err && err.message);
      renderBanner(container, { state: "error" });
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Banner UI ────────────────────────────────────────────────────────────
  function removeBanner() {
    document.getElementById(BANNER_ID)?.remove();
  }

  function renderBanner(container, opts) {
    removeBanner();
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    Object.assign(banner.style, {
      font: '13px/1.4 -apple-system, "Segoe UI", Roboto, sans-serif',
      borderRadius: "8px",
      padding: "10px 14px",
      margin: "8px 0",
      display: "flex",
      alignItems: "center",
      gap: "10px",
      boxShadow: "0 1px 2px rgba(0,0,0,0.1)",
    });

    let icon = "🛡️";
    let headline = "";
    let detail = "";
    let bg = "#f1f5f9", fg = "#334155", border = "#cbd5e1";

    if (opts.state === "scanning") {
      icon = "🛡️"; headline = t("webmail_scanning");
    } else if (opts.state === "rate_limited") {
      icon = "⏳"; headline = t("webmail_rate_limited");
      detail = t("webmail_rate_limited_detail");
      bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
    } else if (opts.state === "error") {
      // The technical reason (HTTP status, timeout) goes to the console in
      // runScan; the reader gets what to do about it.
      icon = "⚠️"; headline = t("webmail_error");
      detail = t("webmail_error_detail");
      bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
    } else if (opts.state === "ready") {
      const { findings, links } = opts.result || {};
      const verdict = describeResult(opts.result);
      headline = verdict.headline;
      detail = verdict.detail;
      if (verdict.level === "dangerous") {
        icon = "🛑";
        bg = "#fee2e2"; fg = "#7f1d1d"; border = "#fca5a5";
      } else if (verdict.level === "suspicious") {
        icon = "⚠️";
        bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
      } else {
        icon = "✅";
        bg = "#dcfce7"; fg = "#14532d"; border = "#86efac";
      }
      banner.dataset.findings = String((findings || []).length);
      banner.dataset.links = String((links || []).length);
    }

    banner.style.backgroundColor = bg;
    banner.style.color = fg;
    banner.style.border = `1px solid ${border}`;

    banner.innerHTML = `
      <span style="font-size:18px" aria-hidden="true"></span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600"></div>
        <div style="font-size:12px;opacity:0.9"></div>
      </div>
      <button type="button"
              style="background:transparent;border:0;cursor:pointer;font-size:18px;line-height:1;color:inherit;padding:0 4px">×</button>
    `;
    const [iconEl, textWrap, closeBtn] = banner.children;
    closeBtn.setAttribute("aria-label", t("webmail_dismiss"));
    iconEl.textContent = icon;
    textWrap.children[0].textContent = headline;
    textWrap.children[1].textContent = detail;
    closeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      banner.remove();
    });

    adapter.insertBanner(banner, container);
  }

  // ── Chrome storage helpers ──────────────────────────────────────────────
  function getApiBase() {
    return new Promise((resolve) => {
      if (typeof chrome === "undefined" || !chrome.storage) {
        resolve(DEFAULT_API_BASE);
        return;
      }
      chrome.storage.local.get("api_url", (data) => {
        resolve((data && data.api_url) || DEFAULT_API_BASE);
      });
    });
  }

  function getAuthToken() {
    return new Promise((resolve) => {
      if (typeof chrome === "undefined" || !chrome.storage) {
        resolve(null);
        return;
      }
      chrome.storage.local.get("auth_token", (data) => {
        resolve((data && data.auth_token) || null);
      });
    });
  }
})();
