/**
 * Block Page — Warning overlay for dangerous sites.
 *
 * Shows a full-page warning before the user can interact with
 * a site scored as "dangerous" (score > 50).
 * User can choose to go back (recommended) or proceed anyway.
 */

/**
 * Show block page overlay for a dangerous domain
 * @param {object} result - Domain check result from API
 */
export function showBlockPage(result) {
  // Don't show if already shown on this page
  if (document.getElementById("ls-block-overlay")) return;

  const { domain, score, reasons } = result;

  const topReasons = (reasons || [])
    .slice(0, 4)
    .map(
      (r) =>
        `<div style="display:flex;align-items:flex-start;gap:8px;margin:8px 0;">
          <span style="color:#ef4444;flex-shrink:0;">&#x26A0;</span>
          <span>${r.detail}</span>
        </div>`
    )
    .join("");

  const overlay = document.createElement("div");
  overlay.id = "ls-block-overlay";
  overlay.innerHTML = `
    <div style="
      position:fixed;inset:0;z-index:2147483647;
      background:#0f172aee;backdrop-filter:blur(8px);
      display:flex;align-items:center;justify-content:center;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      color:#e2e8f0;
    ">
      <div style="max-width:480px;text-align:center;padding:40px 24px;">
        <!-- Warning icon -->
        <div style="
          width:80px;height:80px;border-radius:50%;
          background:#ef444420;margin:0 auto 24px;
          display:flex;align-items:center;justify-content:center;
          font-size:40px;
        ">&#x1F6E1;</div>

        <h1 style="font-size:28px;font-weight:800;color:#f8fafc;margin:0 0 8px;">
          Dangerous Site Detected
        </h1>

        <p style="font-size:16px;color:#94a3b8;margin:0 0 24px;">
          LinkShield has identified <strong style="color:#ef4444;">${domain}</strong>
          as a potential threat (score: ${score}/100)
        </p>

        <!-- Reasons -->
        <div style="
          background:#1e293b;border-radius:12px;padding:16px;
          text-align:left;margin-bottom:24px;font-size:14px;
          border:1px solid #ef444440;
        ">
          ${topReasons || '<div style="color:#94a3b8;">Multiple risk signals detected</div>'}
        </div>

        <!-- Actions -->
        <div style="display:flex;flex-direction:column;gap:12px;">
          <button onclick="history.back()" style="
            background:#22c55e;color:#052e16;border:none;
            border-radius:10px;padding:14px 32px;font-size:16px;
            font-weight:700;cursor:pointer;
          ">
            &#x2190; Go Back (Recommended)
          </button>

          <button id="ls-proceed-btn" style="
            background:transparent;color:#64748b;border:1px solid #334155;
            border-radius:10px;padding:12px 32px;font-size:14px;
            cursor:pointer;
          ">
            I understand the risk — proceed anyway
          </button>
        </div>

        <p style="font-size:11px;color:#475569;margin-top:20px;">
          &#x1F512; This warning is shown by LinkShield browser extension
        </p>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  // Prevent interaction with the page behind the overlay
  document.body.style.overflow = "hidden";

  // "Proceed anyway" button — remove overlay after 3 second delay
  const proceedBtn = document.getElementById("ls-proceed-btn");
  if (proceedBtn) {
    let countdown = 3;
    proceedBtn.textContent = `I understand the risk — proceed anyway (${countdown}s)`;
    proceedBtn.disabled = true;
    proceedBtn.style.opacity = "0.5";

    const interval = setInterval(() => {
      countdown--;
      if (countdown <= 0) {
        clearInterval(interval);
        proceedBtn.textContent = "I understand the risk — proceed anyway";
        proceedBtn.disabled = false;
        proceedBtn.style.opacity = "1";
        proceedBtn.onclick = () => {
          overlay.remove();
          document.body.style.overflow = "";
        };
      } else {
        proceedBtn.textContent = `I understand the risk — proceed anyway (${countdown}s)`;
      }
    }, 1000);
  }
}
