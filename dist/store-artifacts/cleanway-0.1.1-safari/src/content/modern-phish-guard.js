/**
 * Cleanway Modern-Phish Guard — Strategy Top-20 #11.
 *
 * Three modern phishing patterns that classic URL-only checks miss:
 *
 *   1. Browser-in-the-Browser (BitB) — page renders a fake browser
 *      chrome (title bar + URL bar + traffic-light buttons) inside
 *      a <div>, then opens a login form below. The address bar in
 *      the picture is HTML, not the real one.
 *   2. Tab-napping — `target="_blank"` link without
 *      `rel="noopener"` lets the opened page rewrite the original
 *      tab via `window.opener.location = "..."`. We patch every
 *      such link on the page.
 *   3. Overlay credential prompt — a <div> styled to look like a
 *      login dialog (NOT a real <form>), with password-shaped
 *      inputs, captures creds without the browser ever seeing a
 *      form submission. We flag the page.
 *
 * Runs at document_idle so the DOM is stable; re-runs on a
 * MutationObserver because phishing pages often inject the overlay
 * after a fake "loading" animation.
 */

(function () {
  if (window.__cwModernPhishGuardLoaded) return;
  window.__cwModernPhishGuardLoaded = true;

  // ── 2. Tab-napping: patch target=_blank without rel=noopener ──
  // We don't show UI for this — it's pure hardening. Just keep
  // every external link from being able to repaint the tab the
  // user came from.
  function _patchTabNapping(root) {
    var links = (root || document).querySelectorAll(
      'a[target="_blank"]:not([data-cw-rel-patched])'
    );
    var patched = 0;
    for (var i = 0; i < links.length; i++) {
      var a = links[i];
      var rel = (a.getAttribute("rel") || "").toLowerCase();
      var needs = [];
      if (rel.indexOf("noopener") === -1) needs.push("noopener");
      if (rel.indexOf("noreferrer") === -1) needs.push("noreferrer");
      if (needs.length) {
        a.setAttribute(
          "rel",
          (rel ? rel + " " : "") + needs.join(" ")
        );
        patched++;
      }
      a.setAttribute("data-cw-rel-patched", "1");
    }
    return patched;
  }

  // ── 1. BitB detection ──
  // Look for absolutely-positioned divs that contain:
  //   • a traffic-light row (3 small round elements) OR a
  //     macOS-window-controls-shaped pseudo-bar at the top
  //   • a URL-looking text node ("https://" prefix or domain.tld)
  //   • a child element that is, or contains, a password input
  // If all three are present and the URL-bar TEXT does not match
  // window.location.host → very likely BitB.
  function _findBitB() {
    var hits = [];
    var bars = document.querySelectorAll(
      'div, header, nav'
    );
    // Cap to first 2000 to bound work on giant pages.
    var limit = Math.min(bars.length, 2000);
    for (var i = 0; i < limit; i++) {
      var el = bars[i];
      var text = (el.textContent || "").trim();
      if (text.length < 8 || text.length > 400) continue;
      // Heuristic: contains an https-prefixed URL OR a "domain.tld"
      // and is followed (in DOM order) by a password input within
      // 12 siblings or descendants.
      var urlMatch = text.match(
        /(https?:\/\/[A-Za-z0-9.\-]+|[a-z0-9\-]+\.[a-z]{2,12}\/[A-Za-z0-9\/_\-]*)/
      );
      if (!urlMatch) continue;
      var asUrl = urlMatch[0];
      // Strip protocol if present.
      var host = asUrl
        .replace(/^https?:\/\//i, "")
        .split("/")[0]
        .toLowerCase();
      if (!host || host === window.location.host) continue;
      // Check this element's subtree for a password input.
      var pw = el.querySelector('input[type="password"]');
      if (!pw) continue;
      // Bonus: it tries to look like a window chrome. We look for
      // 2–4 small round siblings near the URL bar (traffic-light
      // buttons). We don't REQUIRE this because some BitB kits
      // skip the dots — but if present it's near-conclusive.
      var dots = el.querySelectorAll(
        'div, span, button'
      );
      var roundish = 0;
      var dotLimit = Math.min(dots.length, 30);
      for (var j = 0; j < dotLimit; j++) {
        var d = dots[j];
        try {
          var cs = getComputedStyle(d);
          var w = parseFloat(cs.width);
          var h = parseFloat(cs.height);
          var br = parseFloat(cs.borderRadius);
          if (
            w >= 8 && w <= 20 &&
            h >= 8 && h <= 20 &&
            br >= w / 2 - 1
          ) {
            roundish++;
            if (roundish >= 2) break;
          }
        } catch (_e) {
          // getComputedStyle can throw if el detached; ignore.
        }
      }
      hits.push({
        fakeHost: host,
        realHost: window.location.host,
        hasTrafficLights: roundish >= 2,
      });
      if (hits.length >= 3) break; // bound work
    }
    return hits;
  }

  // ── 3. Overlay credential prompt: password input not in a real form ──
  function _findOrphanPasswordInputs() {
    var pwds = document.querySelectorAll('input[type="password"]');
    var orphans = [];
    for (var i = 0; i < pwds.length; i++) {
      var p = pwds[i];
      // Walk up looking for a real <form>. We don't trust
      // role="form" — phishers use it specifically to mimic forms.
      var node = p.parentElement;
      var inForm = false;
      var hops = 0;
      while (node && hops < 20) {
        if (node.tagName === "FORM") { inForm = true; break; }
        node = node.parentElement;
        hops++;
      }
      if (inForm) continue;
      // Find the nearest containing block that also holds a
      // username/email/text input — that's the credential trap.
      var ancestor = p.parentElement;
      var hopsUp = 0;
      var trap = null;
      while (ancestor && hopsUp < 8) {
        var sibling = ancestor.querySelector(
          'input[type="text"], input[type="email"]'
        );
        if (sibling && sibling !== p) {
          trap = ancestor;
          break;
        }
        ancestor = ancestor.parentElement;
        hopsUp++;
      }
      if (trap) {
        orphans.push({
          tagName: trap.tagName.toLowerCase(),
          // Don't leak input values — only attribute names that
          // help us label the warning, never .value.
          hasEmailField: !!trap.querySelector('input[type="email"]'),
        });
        if (orphans.length >= 2) break;
      }
    }
    return orphans;
  }

  // ── Warning banner ──
  function _showBanner(threats) {
    if (document.getElementById("cw-modern-phish-banner")) return;
    var msg = "";
    if (threats.bitb && threats.bitb.length) {
      msg = "This page is drawing a fake browser address bar (\"" +
        threats.bitb[0].fakeHost +
        "\"). You are actually on " + window.location.host + ".";
    } else if (threats.orphans && threats.orphans.length) {
      msg = "This page asks for a password without a real login form — " +
        "credentials may be stolen.";
    } else {
      return;
    }
    var bar = document.createElement("div");
    bar.id = "cw-modern-phish-banner";
    bar.setAttribute("role", "alert");
    bar.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483646",
      "background:#7c1d1d",
      "color:#fff",
      "font:600 14px/1.4 -apple-system,system-ui,sans-serif",
      "padding:12px 16px",
      "box-shadow:0 2px 8px rgba(0,0,0,.35)",
      "text-align:center",
    ].join(";");
    bar.textContent = "⚠️ Cleanway: " + msg;
    document.documentElement.appendChild(bar);
  }

  function _run() {
    _patchTabNapping(document);
    // Skip BitB/overlay scans on extension-internal pages and
    // login pages we explicitly trust (origin matches well-known
    // login hosts isn't a check we make here — domain reputation
    // is the analyzer's job).
    var threats = {
      bitb: _findBitB(),
      orphans: _findOrphanPasswordInputs(),
    };
    if (
      (threats.bitb && threats.bitb.length) ||
      (threats.orphans && threats.orphans.length)
    ) {
      try {
        chrome.runtime.sendMessage({
          type: "MODERN_PHISH_SIGNAL",
          host: window.location.host,
          signals: threats,
        });
      } catch (_e) {
        // chrome.runtime not present in some test harnesses; ignore.
      }
      _showBanner(threats);
    }
  }

  // Initial pass at document_idle (manifest controls timing).
  _run();

  // Re-scan when the DOM changes (overlays often appear after
  // a fake loading spinner). Coalesce with a 400 ms debounce.
  var _rescanTimer = null;
  try {
    var mo = new MutationObserver(function () {
      if (_rescanTimer) clearTimeout(_rescanTimer);
      _rescanTimer = setTimeout(function () {
        _patchTabNapping(document);
        // Don't re-run BitB on every mutation — only once per page
        // unless the banner was dismissed, which we don't support.
        if (!document.getElementById("cw-modern-phish-banner")) {
          _run();
        }
      }, 400);
    });
    mo.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  } catch (_e) {
    // MutationObserver not available; the initial pass is still useful.
  }
})();
