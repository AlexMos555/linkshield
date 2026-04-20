/**
 * LinkShield Webmail Guardian — Gmail + Outlook Web + Yahoo Mail.
 *
 * Runs as a content script on mail.google.com, outlook.office.com /
 * outlook.live.com, and mail.yahoo.com. For the currently-open
 * conversation, it:
 *
 *   1. Extracts the subject, sender, reply-to, and body text.
 *   2. POSTs them to `/api/v1/email/analyze`.
 *   3. Renders a non-intrusive banner above the message:
 *        ✅ green   "Looks safe"
 *        ⚠️ amber   "Suspicious — treat with caution"
 *        🛑 red     "Likely phishing — don't click"
 *      Plus a collapsed list of findings the user can expand.
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
  const BANNER_ID = "linkshield-webmail-banner";
  const DEBOUNCE_MS = 600;
  const DEFAULT_API_BASE = "https://web-production-fe08.up.railway.app";

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

    const sig = container.dataset.linkshieldSignature ||
      `${adapter.subject()}|${adapter.sender()}|${container.textContent.length}`;
    if (sig === lastSignature) return; // already scanned this message
    lastSignature = sig;
    container.dataset.linkshieldSignature = sig;

    runScan(container).catch((err) => {
      console.warn("[LinkShield] webmail scan failed:", err && err.message);
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
      renderBanner(container, { state: "error", error: err && err.message });
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
      icon = "🛡️"; headline = "LinkShield is scanning this email…";
    } else if (opts.state === "rate_limited") {
      icon = "⏳"; headline = "LinkShield is rate-limited — please wait";
      detail = "Too many scans from this network right now. Try again in a minute.";
      bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
    } else if (opts.state === "error") {
      icon = "⚠️"; headline = "LinkShield couldn't reach the server";
      detail = opts.error || "";
      bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
    } else if (opts.state === "ready") {
      const { level, score, findings, links } = opts.result || {};
      if (level === "dangerous") {
        icon = "🛑"; headline = "Likely phishing — don't click any links";
        bg = "#fee2e2"; fg = "#7f1d1d"; border = "#fca5a5";
      } else if (level === "suspicious") {
        icon = "⚠️"; headline = "Suspicious — verify before interacting";
        bg = "#fef3c7"; fg = "#713f12"; border = "#fcd34d";
      } else {
        icon = "✅"; headline = "Looks safe — no phishing markers found";
        bg = "#dcfce7"; fg = "#14532d"; border = "#86efac";
      }
      const topFinding = (findings && findings[0] && findings[0].message) || "";
      detail = topFinding
        ? `Risk score ${score}/100 • ${topFinding}`
        : `Risk score ${score}/100`;
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
              aria-label="Dismiss"
              style="background:transparent;border:0;cursor:pointer;font-size:18px;line-height:1;color:inherit;padding:0 4px">×</button>
    `;
    const [iconEl, textWrap, closeBtn] = banner.children;
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
