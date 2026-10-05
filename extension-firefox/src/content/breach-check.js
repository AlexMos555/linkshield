/**
 * Breach Check — email leak lookup (NOT AVAILABLE YET).
 *
 * The popup's "Check email leak" button opens this overlay. It used to ask
 * for an email, "check" it, and answer "No breaches found — this email was
 * not found in any known data breaches". Nothing was checked:
 *
 *   /api/v1/breach/check/{prefix} proxies HIBP's Pwned PASSWORDS
 *   k-anonymity API. An email-SHA1 prefix only returns the password-hash
 *   suffixes that happen to share those 5 hex chars — not an answer about
 *   the email (Strategy #13 adversarial review, 2026-06-17). The honest
 *   lookup is HIBP's /breachedaccount endpoint, which is paid-tier only.
 *   The 2026-06 fix returned a "coming soon" message, but this overlay
 *   ignored it and still showed the green "no breaches" result.
 *
 * Until that endpoint is wired, the overlay says plainly that the email
 * check is not available and what already works (password-pwned.js warns
 * when a password typed into any form is in a known leak). No email is
 * asked for and nothing leaves the device. Text: packages/i18n-strings
 * extension.breach.
 */

// Named per file: content scripts share one global scope.
function _breachT(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

function showBreachCheckOverlay() {
  var existing = document.getElementById("ls-breach-overlay");
  if (existing) existing.remove();

  var div = document.createElement("div");
  div.id = "ls-breach-overlay";
  div.innerHTML = '<div style="position:fixed;inset:0;z-index:999999;background:#0f172aee;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;">' +
    '<div role="dialog" aria-modal="true" aria-labelledby="ls-breach-title" style="background:#1e293b;border-radius:16px;padding:32px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.5);">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">' +
    '<h2 id="ls-breach-title" style="font-size:20px;font-weight:700;margin:0;"></h2>' +
    '<span id="ls-breach-close" role="button" tabindex="0" style="cursor:pointer;color:#6b7280;font-size:20px;">×</span></div>' +
    '<p id="ls-breach-status" style="font-size:15px;color:#e2e8f0;margin:0 0 12px;line-height:1.5;"></p>' +
    '<p id="ls-breach-works-now" style="font-size:13px;color:#94a3b8;margin:0 0 20px;line-height:1.5;"></p>' +
    '<button id="ls-breach-ok" type="button" style="width:100%;background:#3b82f6;color:white;border:none;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer;"></button>' +
    '</div></div>';

  // Text goes in through textContent: nothing here is HTML.
  div.querySelector("#ls-breach-title").textContent = "🔓 " + _breachT("breach_title");
  div.querySelector("#ls-breach-status").textContent = _breachT("breach_not_available");
  div.querySelector("#ls-breach-works-now").textContent = _breachT("breach_works_now");
  var closeLabel = _breachT("breach_close");
  div.querySelector("#ls-breach-close").setAttribute("aria-label", closeLabel);
  div.querySelector("#ls-breach-ok").textContent = closeLabel;

  document.body.appendChild(div);
  function close() { div.remove(); }
  var closeBtn = document.getElementById("ls-breach-close");
  closeBtn.onclick = close;
  closeBtn.addEventListener("keydown", function(e) {
    if (e.key === "Enter" || e.key === " ") close();
  });
  var okBtn = document.getElementById("ls-breach-ok");
  okBtn.onclick = close;
  okBtn.focus();
}
