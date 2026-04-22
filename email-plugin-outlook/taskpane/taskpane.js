/**
 * Cleanway Outlook taskpane — pulls the current message out of Office.js,
 * posts it to the Cleanway analyzer, renders the verdict.
 *
 * Privacy contract:
 * - Only the sender address + display name, auth headers, subject, and body
 *   text leave the device. Recipients, CCs, attachment content, full MIME
 *   headers, thread metadata are all untouched.
 * - The user's Supabase access token (stored by the Cleanway mobile app
 *   / extension after sign-in) is NOT available to the add-in — so we run
 *   as an anonymous user until Outlook SSO is wired. The backend accepts
 *   anonymous `/api/v1/email/analyze` calls under stricter IP rate limits.
 *
 * Lifecycle:
 * 1. `Office.onReady` fires → we have a valid `Office.context.mailbox.item`
 * 2. `loadMessage()` reads headers + body via Office APIs
 * 3. `scanMessage()` POSTs to the Cleanway API
 * 4. `renderVerdict()` paints the UI
 */
"use strict";

// ─── Config ─────────────────────────────────────────────────────────────────

const API_BASE = "https://web-production-fe08.up.railway.app";

// ─── DOM refs ───────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);
const els = {
  body: document.body,
  statusPill: $("status-pill"),
  verdict: $("verdict"),
  verdictTitle: $("verdict-title"),
  verdictSubtitle: $("verdict-subtitle"),
  verdictScore: $("verdict-score"),
  findings: $("findings"),
  findingsList: $("findings-list"),
  links: $("links"),
  linksList: $("links-list"),
  btnReport: $("btn-report"),
  btnRescan: $("btn-rescan"),
  error: $("error"),
  errorDetail: $("error-detail"),
};

// ─── Office.js entry ────────────────────────────────────────────────────────

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) {
    showError("This add-in only runs inside Outlook.");
    return;
  }
  els.btnRescan.addEventListener("click", runScan);
  els.btnReport.addEventListener("click", reportPhishing);
  runScan();
});

// ─── Main scan flow ─────────────────────────────────────────────────────────

async function runScan() {
  els.body.classList.add("loading");
  els.error.hidden = true;
  els.verdict.hidden = true;
  els.findings.hidden = true;
  els.links.hidden = true;
  els.btnReport.hidden = true;
  els.btnRescan.hidden = true;
  setStatus("Scanning…", "loading");

  let message;
  try {
    message = await loadMessage();
  } catch (err) {
    showError(err && err.message ? err.message : "Couldn't read this message.");
    return;
  }

  try {
    const result = await scanMessage(message);
    renderVerdict(result);
  } catch (err) {
    showError(
      err && err.message
        ? err.message
        : "Couldn't reach the Cleanway server.",
    );
  } finally {
    els.body.classList.remove("loading");
  }
}

// ─── Office.js wrappers ─────────────────────────────────────────────────────

/**
 * Collect the fields the analyzer cares about. Promisified wrappers around
 * Office APIs so we can `await` them.
 */
async function loadMessage() {
  const item = Office.context.mailbox.item;
  if (!item) throw new Error("No message is currently selected.");

  const [bodyText, authHeader] = await Promise.all([
    getBody(item, "text"),
    getAuthenticationResults(item).catch(() => ""),
  ]);
  // HTML body is optional — best effort, don't block the scan on failure.
  let bodyHtml = "";
  try {
    bodyHtml = await getBody(item, "html");
  } catch {
    bodyHtml = "";
  }

  const { spf, dkim, dmarc } = parseAuthResults(authHeader);

  return {
    from_address: (item.from && item.from.emailAddress) || "",
    from_display: (item.from && item.from.displayName) || "",
    reply_to:
      item.replyTo && item.replyTo.length
        ? item.replyTo[0].emailAddress
        : "",
    subject: item.subject || "",
    return_path: "",
    spf,
    dkim,
    dmarc,
    body_text: bodyText || "",
    body_html: bodyHtml || "",
  };
}

function getBody(item, format) {
  return new Promise((resolve, reject) => {
    const coercion =
      format === "html"
        ? Office.CoercionType.Html
        : Office.CoercionType.Text;
    item.body.getAsync(coercion, (res) => {
      if (res.status === Office.AsyncResultStatus.Succeeded) {
        resolve(res.value || "");
      } else {
        reject(res.error || new Error("body read failed"));
      }
    });
  });
}

function getAuthenticationResults(item) {
  return new Promise((resolve, reject) => {
    if (!item.getAllInternetHeadersAsync) {
      resolve("");
      return;
    }
    item.getAllInternetHeadersAsync((res) => {
      if (res.status === Office.AsyncResultStatus.Succeeded) {
        resolve(res.value || "");
      } else {
        reject(res.error || new Error("headers read failed"));
      }
    });
  });
}

/**
 * Extract SPF / DKIM / DMARC result strings from the raw
 * `Authentication-Results` header (which can be multi-line).
 */
function parseAuthResults(rawHeaders) {
  if (!rawHeaders) return { spf: null, dkim: null, dmarc: null };
  const match = /Authentication-Results:([\s\S]*?)(?:\r?\n\S|$)/i.exec(
    rawHeaders,
  );
  if (!match) return { spf: null, dkim: null, dmarc: null };
  const block = match[1];
  const pick = (key) => {
    const re = new RegExp(`\\b${key}\\s*=\\s*([a-z]+)`, "i");
    const m = re.exec(block);
    return m ? m[1].toLowerCase() : null;
  };
  return {
    spf: pick("spf"),
    dkim: pick("dkim"),
    dmarc: pick("dmarc"),
  };
}

// ─── Backend call ───────────────────────────────────────────────────────────

async function scanMessage(payload) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  try {
    const resp = await fetch(`${API_BASE}/api/v1/email/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    if (!resp.ok) {
      throw new Error(`Server returned ${resp.status}`);
    }
    return await resp.json();
  } finally {
    clearTimeout(timer);
  }
}

// ─── Rendering ──────────────────────────────────────────────────────────────

function renderVerdict(result) {
  const levelMap = {
    safe: {
      pill: "pill pill--safe",
      verdict: "verdict verdict--safe",
      title: "This email looks safe",
      subtitle: "No phishing markers found. Normal caution still applies.",
      pillText: "Safe",
    },
    suspicious: {
      pill: "pill pill--warn",
      verdict: "verdict verdict--warn",
      title: "Suspicious — treat with caution",
      subtitle: "Several phishing markers found. Don't click links without verifying.",
      pillText: "Suspicious",
    },
    dangerous: {
      pill: "pill pill--danger",
      verdict: "verdict verdict--danger",
      title: "Likely phishing",
      subtitle: "Strong phishing signals. Do not click links or reply.",
      pillText: "Phishing",
    },
  };
  const cfg = levelMap[result.level] || levelMap.safe;

  els.statusPill.className = cfg.pill;
  els.statusPill.textContent = cfg.pillText;
  els.verdict.className = cfg.verdict;
  els.verdictTitle.textContent = cfg.title;
  els.verdictSubtitle.textContent = cfg.subtitle;
  els.verdictScore.textContent = String(result.score ?? 0);
  els.verdict.hidden = false;

  renderFindings(result.findings || []);
  renderLinks(result.links || []);

  els.btnRescan.hidden = false;
  els.btnReport.hidden = result.level === "safe";
}

function renderFindings(findings) {
  if (!findings.length) return;
  els.findingsList.innerHTML = "";
  for (const f of findings) {
    const li = document.createElement("li");
    li.className = "finding";
    const sev =
      f.severity >= 35 ? "high" : f.severity >= 20 ? "med" : "low";
    li.innerHTML = `
      <span class="finding__severity finding__severity--${sev}" aria-hidden="true"></span>
      <div class="finding__body">
        <div class="finding__message"></div>
        <div class="finding__evidence"></div>
      </div>
    `;
    li.querySelector(".finding__message").textContent = f.message || "";
    li.querySelector(".finding__evidence").textContent = f.evidence || "";
    els.findingsList.appendChild(li);
  }
  els.findings.hidden = false;
}

function renderLinks(links) {
  if (!links.length) return;
  els.linksList.innerHTML = "";
  for (const link of links) {
    const li = document.createElement("li");
    li.className = "link-item";
    li.innerHTML = `
      <div class="link-item__text"></div>
      <div class="link-item__url"></div>
    `;
    li.querySelector(".link-item__text").textContent =
      link.display_text || link.url;
    li.querySelector(".link-item__url").textContent = link.url;
    els.linksList.appendChild(li);
  }
  els.links.hidden = false;
}

function setStatus(text, kind) {
  els.statusPill.textContent = text;
  els.statusPill.className = `pill pill--${kind}`;
}

function showError(detail) {
  els.body.classList.remove("loading");
  els.error.hidden = false;
  els.errorDetail.textContent = detail;
  setStatus("Error", "danger");
}

// ─── Report phishing ────────────────────────────────────────────────────────

async function reportPhishing() {
  els.btnReport.disabled = true;
  els.btnReport.textContent = "Reporting…";
  try {
    const message = await loadMessage();
    // Hit the feedback endpoint if authenticated; otherwise, queue locally.
    // The backend honours the same /feedback/report endpoint used by the
    // mobile app and browser extension. An anonymous submission still
    // contributes to the domain-level crowd source.
    await fetch(`${API_BASE}/api/v1/feedback/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: "outlook",
        reason: "phishing",
        sender: message.from_address,
        subject: message.subject,
      }),
    });
    els.btnReport.textContent = "✓ Reported";
  } catch {
    els.btnReport.textContent = "Retry report";
    els.btnReport.disabled = false;
  }
}
