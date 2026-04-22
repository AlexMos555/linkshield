/**
 * Breach Check — k-Anonymity Email Leak Detection
 *
 * Privacy flow:
 *   1. User enters email in overlay
 *   2. Extension hashes email with SHA-1 LOCALLY
 *   3. Only first 5 chars of hash sent to API
 *   4. API returns ~500 matching suffixes from HIBP
 *   5. Extension checks LOCALLY if full hash matches
 *   → Server and HIBP never see the full email or hash
 */

async function sha1(message) {
  var msgBuffer = new TextEncoder().encode(message);
  var hashBuffer = await crypto.subtle.digest("SHA-1", msgBuffer);
  var hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(function(b) { return b.toString(16).padStart(2, "0"); }).join("").toUpperCase();
}

async function checkEmailBreach(email) {
  var hash = await sha1(email.toLowerCase().trim());
  var prefix = hash.substring(0, 5);
  var suffix = hash.substring(5);

  try {
    var resp = await fetch((typeof window !== "undefined" && window.CLEANWAY_API_BASE ? window.CLEANWAY_API_BASE : "https://api.cleanway.ai") + "/api/v1/breach/check/" + prefix);
    if (!resp.ok) return { error: "Service unavailable" };

    var data = await resp.json();
    var match = null;

    for (var i = 0; i < data.suffixes.length; i++) {
      if (data.suffixes[i].suffix === suffix) {
        match = data.suffixes[i];
        break;
      }
    }

    if (match) {
      return {
        breached: true,
        count: match.count,
        message: "This email appeared in " + match.count + " data breach(es). Change passwords on affected services.",
      };
    } else {
      return {
        breached: false,
        count: 0,
        message: "No breaches found for this email.",
      };
    }
  } catch (e) {
    return { error: "Could not check. Try again later." };
  }
}

function showBreachCheckOverlay() {
  var existing = document.getElementById("ls-breach-overlay");
  if (existing) existing.remove();

  var div = document.createElement("div");
  div.id = "ls-breach-overlay";
  div.innerHTML = '<div style="position:fixed;inset:0;z-index:999999;background:#0f172aee;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;">' +
    '<div style="background:#1e293b;border-radius:16px;padding:32px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.5);">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">' +
    '<h2 style="font-size:20px;font-weight:700;margin:0;">\uD83D\uDD13 Breach Check</h2>' +
    '<span id="ls-breach-close" style="cursor:pointer;color:#6b7280;font-size:20px;">\u00D7</span></div>' +
    '<p style="font-size:13px;color:#94a3b8;margin-bottom:16px;">Check if your email appeared in data breaches. Your email is hashed locally — we never see it.</p>' +
    '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
    '<input id="ls-breach-email" type="email" placeholder="your@email.com" style="flex:1;padding:10px 14px;border-radius:8px;border:1px solid #334155;background:#0f172a;color:#e2e8f0;font-size:14px;outline:none;">' +
    '<button id="ls-breach-btn" style="background:#3b82f6;color:white;border:none;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer;">Check</button></div>' +
    '<div id="ls-breach-result" style="display:none;padding:16px;border-radius:10px;font-size:14px;"></div>' +
    '<div style="font-size:10px;color:#475569;text-align:center;margin-top:12px;">\uD83D\uDD12 Email hashed with SHA-1 on your device. Only first 5 chars of hash sent to server.</div>' +
    '</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-breach-close").onclick = function() { div.remove(); };

  document.getElementById("ls-breach-btn").onclick = async function() {
    var email = document.getElementById("ls-breach-email").value.trim();
    if (!email || !email.includes("@")) {
      alert("Please enter a valid email address.");
      return;
    }

    var btn = document.getElementById("ls-breach-btn");
    btn.textContent = "Checking...";
    btn.disabled = true;

    var result = await checkEmailBreach(email);
    var resultDiv = document.getElementById("ls-breach-result");
    resultDiv.style.display = "block";

    if (result.error) {
      resultDiv.style.background = "#1e293b";
      resultDiv.style.border = "1px solid #334155";
      resultDiv.innerHTML = '<div style="color:#f59e0b;">\u26A0 ' + result.error + '</div>';
    } else if (result.breached) {
      resultDiv.style.background = "#450a0a";
      resultDiv.style.border = "1px solid #ef4444";
      resultDiv.innerHTML = '<div style="color:#ef4444;font-weight:600;margin-bottom:4px;">\u274C Breached!</div>' +
        '<div style="color:#fca5a5;">Found in ' + result.count + ' data breach(es).</div>' +
        '<div style="color:#94a3b8;font-size:12px;margin-top:8px;">Recommendation: Change your password on all services where you use this email.</div>';
    } else {
      resultDiv.style.background = "#052e16";
      resultDiv.style.border = "1px solid #22c55e";
      resultDiv.innerHTML = '<div style="color:#22c55e;font-weight:600;">\u2705 No breaches found</div>' +
        '<div style="color:#86efac;font-size:13px;">This email was not found in any known data breaches.</div>';
    }

    btn.textContent = "Check";
    btn.disabled = false;
  };

  // Enter key support
  document.getElementById("ls-breach-email").addEventListener("keydown", function(e) {
    if (e.key === "Enter") document.getElementById("ls-breach-btn").click();
  });
}
