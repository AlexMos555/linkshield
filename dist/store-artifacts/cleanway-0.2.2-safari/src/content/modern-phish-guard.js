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
 * Runs at document_idle so the DOM is stable; re-runs, at idle time,
 * when a MutationObserver sees an <input> added, because phishing pages
 * often inject the overlay after a fake "loading" animation.
 */

(function () {
  if (window.__cwModernPhishGuardLoaded) return;
  window.__cwModernPhishGuardLoaded = true;

  // Warning text in the browser's language (extension.modern_phish in
  // packages/i18n-strings). The banner is set via textContent, so the
  // page-supplied hostnames inside it need no escaping.
  function _t(key, subs) {
    try {
      return chrome.i18n.getMessage(key, subs || []) || key;
    } catch (e) {
      return key;
    }
  }

  // ── 2. Tab-napping: patch target=_blank without rel=noopener ──
  // We don't show UI for this — it's pure hardening. Just keep
  // every external link from being able to repaint the tab the
  // user came from.
  var TARGET_BLANK = 'a[target="_blank"]:not([data-cw-rel-patched])';

  // `root`: the document, or an element just added to the page (itself
  // included).
  function _patchTabNapping(root) {
    root = root || document;
    var links = Array.prototype.slice.call(root.querySelectorAll(TARGET_BLANK));
    if (root.nodeType === 1 && root.matches && root.matches(TARGET_BLANK)) links.push(root);
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
  // A fake window is a small block (a div, header or nav) that holds:
  //   • a URL-looking text ("https://" prefix or domain.tld/path)
  //   • a password input
  //   • often a traffic-light row (2–4 small round elements)
  // If the URL-bar TEXT does not match window.location.host → very likely
  // BitB.
  //
  // Every such block is an ancestor of a password input, so the search
  // starts there and walks up, instead of reading the text of up to 2000
  // divs on every DOM change (32–46 ms a rescan on a 1500-post feed). An
  // ancestor's text holds its child's, so the walk stops at the first one
  // longer than a fake window's (MAX_WINDOW_TEXT), and the text is read
  // with a bound (_textUpTo), never a whole page's textContent.
  var MAX_PASSWORD_INPUTS = 10;
  var MAX_HOPS = 12;
  var MAX_WINDOW_TEXT = 400;
  // Raw characters read at most per block: markup whitespace counts too.
  var MAX_RAW_TEXT = 4 * MAX_WINDOW_TEXT;

  // The element's text, or null once it passes `max` characters (or a
  // generous number of text nodes) — the rest is never read.
  function _textUpTo(el, max) {
    var walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    var out = "";
    var nodes = 0;
    var n;
    while ((n = walker.nextNode())) {
      out += n.nodeValue;
      nodes++;
      if (out.length > max || nodes > 200) return null;
    }
    return out;
  }

  function _fakeWindowHost(el) {
    var raw = _textUpTo(el, MAX_RAW_TEXT);
    if (raw === null) return { stop: true };
    var text = raw.trim();
    if (text.length > MAX_WINDOW_TEXT) return { stop: true };
    if (text.length < 8 || !/^(DIV|HEADER|NAV)$/.test(el.tagName)) return {};
    var urlMatch = text.match(
      /(https?:\/\/[A-Za-z0-9.\-]+|[a-z0-9\-]+\.[a-z]{2,12}\/[A-Za-z0-9\/_\-]*)/
    );
    if (!urlMatch) return {};
    // Strip protocol if present.
    var host = urlMatch[0]
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .toLowerCase();
    if (!host || host === window.location.host) return {};
    return { host: host };
  }

  function _findBitB() {
    var hits = [];
    var seen = new Set();
    var pwds = document.querySelectorAll('input[type="password"]');
    var limit = Math.min(pwds.length, MAX_PASSWORD_INPUTS);
    for (var i = 0; i < limit && hits.length < 3; i++) {
      var el = pwds[i].parentElement;
      for (var hops = 0; el && hops < MAX_HOPS; hops++, el = el.parentElement) {
        if (el === document.body || el === document.documentElement) break;
        if (seen.has(el)) break; // walked from here for another input already
        seen.add(el);
        var found = _fakeWindowHost(el);
        if (found.stop) break;
        if (found.host) {
          hits.push(_describeHit(el, found.host));
          break;
        }
      }
    }
    return hits;
  }

  function _describeHit(el, host) {
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
    return {
      fakeHost: host,
      realHost: window.location.host,
      hasTrafficLights: roundish >= 2,
    };
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
      msg = _t("mpg_bitb", ["\"" + threats.bitb[0].fakeHost + "\"", window.location.host]);
    } else if (threats.orphans && threats.orphans.length) {
      msg = _t("mpg_orphan");
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

  // Re-scan when the DOM changes (overlays often appear after a fake
  // loading spinner) — but only for what was added: new links get the
  // tab-napping fix, and the BitB / overlay scans re-run only when an
  // <input> arrived. A feed growing by posts used to re-run both on every
  // change, 400 ms later. Work waits for idle time (requestIdleCallback;
  // Safari has none, so a timer there).
  var MAX_PENDING_ROOTS = 500;
  var _pending = { roots: [], overflow: false, scan: false, scheduled: false };

  function _idle(fn) {
    if (typeof window.requestIdleCallback === "function") {
      window.requestIdleCallback(fn, { timeout: 1000 });
    } else {
      setTimeout(fn, 400);
    }
  }

  function _addsInput(node) {
    if (node.tagName === "INPUT") return true;
    return typeof node.querySelector === "function" && node.querySelector("input") !== null;
  }

  function _flush() {
    var p = _pending;
    _pending = { roots: [], overflow: false, scan: false, scheduled: false };
    if (p.overflow) {
      _patchTabNapping(document);
    } else {
      for (var i = 0; i < p.roots.length; i++) {
        if (p.roots[i].isConnected) _patchTabNapping(p.roots[i]);
      }
    }
    // Once the banner is up the page has been warned; it has no dismiss.
    if (p.scan && !document.getElementById("cw-modern-phish-banner")) _run();
  }

  try {
    var mo = new MutationObserver(function (mutations) {
      for (var i = 0; i < mutations.length; i++) {
        var added = mutations[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (!node || node.nodeType !== 1) continue;
          if (_pending.roots.length < MAX_PENDING_ROOTS) _pending.roots.push(node);
          else _pending.overflow = true;
          if (!_pending.scan && _addsInput(node)) _pending.scan = true;
        }
      }
      if (!_pending.scheduled && (_pending.roots.length || _pending.overflow)) {
        _pending.scheduled = true;
        _idle(_flush);
      }
    });
    mo.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  } catch (_e) {
    // MutationObserver not available; the initial pass is still useful.
  }
})();
