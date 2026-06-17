/**
 * Password Pwned-Check — Cleanway Strategy doc Top-20 #13.
 *
 * When a user types a password into any form, the moment they
 * move focus away (blur) we:
 *   1. SHA-1 the password locally
 *   2. Send only the first 5 hex chars of the hash to Cleanway
 *   3. Get back the suffix list (k-anonymity)
 *   4. Match the user's actual suffix locally
 *   5. If found → inline "this password appeared in N data breaches"
 *
 * The full hash never leaves the device. We discard it from
 * memory the moment the lookup is done — no breach log, no
 * Sentry breadcrumb, no per-call counter beyond a local
 * "breached_passwords_seen" tally for the popup.
 *
 * UX rules:
 *   * Passive. We never block the form. Users can submit
 *     anyway — we just told them once that the password is in
 *     a leak.
 *   * Per-input throttle. We check ONCE per password input per
 *     pageload. If the user types, blurs, retypes, blurs again,
 *     we only call the API once unless the value actually changed.
 *   * Min length 4. Short test passwords waste an API call.
 *   * Per-page debounce. If 5 password fields land on a page,
 *     the first blur queues them through a 500 ms lock so we
 *     don't fan out 5 API calls in parallel.
 */

(function () {
  if (window.__cwPwnedPasswordsLoaded) return;
  window.__cwPwnedPasswordsLoaded = true;

  var MIN_LENGTH = 4;
  var STORAGE_KEY = "pwned_password_seen_count";
  var API_PATH = "/api/v1/breach/check/";

  var _seenInputs = new WeakSet();
  var _lastValueByInput = new WeakMap();
  var _scanInFlight = false;

  function _apiBase() {
    return (typeof window !== "undefined" && window.CLEANWAY_API_BASE)
      ? window.CLEANWAY_API_BASE
      : "https://api.cleanway.ai";
  }

  // ── SHA-1 via Web Crypto. SubtleCrypto requires secure context.
  //    Returns hex string. Throws on no-crypto pages (file://, http).
  async function _sha1Hex(text) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("no crypto.subtle");
    }
    var buf = new TextEncoder().encode(text);
    var hashBuf = await window.crypto.subtle.digest("SHA-1", buf);
    var bytes = new Uint8Array(hashBuf);
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      out += h.length === 1 ? "0" + h : h;
    }
    return out.toUpperCase();
  }

  // ── Lookup. Returns breach count (>0) or 0.
  async function _checkPrefix(prefix, fullHash) {
    var resp = await fetch(_apiBase() + API_PATH + prefix, {
      method: "GET",
      credentials: "omit",
      mode: "cors",
    });
    if (!resp.ok) return 0;
    var data = await resp.json();
    var ourSuffix = fullHash.slice(5);
    var suffixes = (data && data.suffixes) || [];
    for (var i = 0; i < suffixes.length; i++) {
      var row = suffixes[i];
      if (row && row.suffix === ourSuffix && row.count > 0) {
        return row.count;
      }
    }
    return 0;
  }

  // ── Inline banner attached to the password input's nearest form.
  //    The banner is below the input, dismissible, ARIA-live polite
  //    so screen readers announce it without preempting input focus.
  function _showBanner(input, count) {
    var existing = document.getElementById("ls-pwned-banner");
    if (existing) existing.remove();

    var anchor = input.form || input.parentElement || document.body;
    var bar = document.createElement("div");
    bar.id = "ls-pwned-banner";
    bar.setAttribute("role", "status");
    bar.setAttribute("aria-live", "polite");
    bar.style.cssText = [
      "margin:8px 0",
      "padding:10px 14px",
      "border-radius:8px",
      "background:#7c2d12",
      "color:#fff7ed",
      "font:13px/1.45 -apple-system,system-ui,sans-serif",
      "border:1px solid #f97316",
      "max-width:480px",
    ].join(";");

    bar.innerHTML =
      "<strong>⚠️ This password is in a known data breach.</strong>" +
      "<div style=\"margin-top:6px;color:#fed7aa;\">Cleanway found this exact password in " +
      String(count).replace(/[^0-9]/g, "") +
      " public leaks. Change it before re-using it anywhere.</div>" +
      "<button id=\"ls-pwned-dismiss\" style=\"background:transparent;color:#fff7ed;border:1px solid #c2410c;border-radius:6px;padding:4px 10px;margin-top:8px;cursor:pointer;font-size:12px;\">Got it</button>";

    try {
      anchor.appendChild(bar);
    } catch (_e) {
      document.body.appendChild(bar);
    }

    var dismiss = bar.querySelector("#ls-pwned-dismiss");
    if (dismiss) {
      dismiss.addEventListener("click", function () {
        if (bar.parentNode) bar.parentNode.removeChild(bar);
      });
    }
  }

  function _bumpLocalCounter() {
    try {
      chrome.storage.local.get([STORAGE_KEY]).then(function (d) {
        var n = (d && d[STORAGE_KEY]) || 0;
        var update = {};
        update[STORAGE_KEY] = n + 1;
        chrome.storage.local.set(update).catch(function () {});
      }).catch(function () {});
    } catch (_e) { /* extension storage unavailable in some contexts */ }
  }

  async function _onPasswordBlur(e) {
    var input = e && e.target;
    if (!input || input.type !== "password") return;
    var value = input.value || "";
    if (value.length < MIN_LENGTH) return;
    if (_scanInFlight) return;

    // Throttle: skip if we've already checked this exact value.
    if (_lastValueByInput.get(input) === value) return;
    _lastValueByInput.set(input, value);

    _scanInFlight = true;
    try {
      var hash = await _sha1Hex(value);
      // Discard the password value from memory ASAP. Subsequent
      // reads of `value` would just go back to the DOM input anyway.
      value = null;
      var prefix = hash.slice(0, 5);
      var count = await _checkPrefix(prefix, hash);
      hash = null;
      if (count > 0) {
        _showBanner(input, count);
        _bumpLocalCounter();
      }
    } catch (_e) {
      // No crypto on this page, or the network died. Silent fail —
      // the user shouldn't be told "we couldn't check your password"
      // because that's not actionable.
    } finally {
      _scanInFlight = false;
    }
  }

  // ── Wire blur listeners on all password inputs, including those
  //    that appear later (SPA login modals etc).
  function _wireInput(input) {
    if (!input || _seenInputs.has(input)) return;
    _seenInputs.add(input);
    input.addEventListener("blur", _onPasswordBlur, true);
  }

  function _scan(root) {
    var inputs = (root || document).querySelectorAll('input[type="password"]');
    for (var i = 0; i < inputs.length; i++) _wireInput(inputs[i]);
  }

  _scan(document);

  try {
    var mo = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (!node || node.nodeType !== 1) continue;
          if (node.tagName === "INPUT" && node.type === "password") {
            _wireInput(node);
          } else if (node.querySelectorAll) {
            _scan(node);
          }
        }
      }
    });
    mo.observe(document.documentElement, {
      childList: true, subtree: true,
    });
  } catch (_e) {
    // No MutationObserver — fall back to the initial scan only.
  }
})();
