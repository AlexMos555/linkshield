/**
 * The block page (blocked.html): what was blocked, read back from this
 * page's own address (utils/blocked-url.js validates every field), drawn by
 * content/block-page.js with textContent.
 *
 *   "Go back to safety"  the page before the scam one: two steps back (the
 *                        scam page is the entry right behind this one), or,
 *                        with nothing to go back to, the tab closes.
 *   "Open anyway"        BLOCK_PROCEED: the background allows that site in
 *                        this tab for a while and loads the blocked address
 *                        again (background/block-redirect.js). Kids mode
 *                        hides the button (block-page.js).
 *
 * A verdict resting on Google's lists is drawn only inside Google's window
 * (the address's `x`): Web Risk allows a warning only while Google's answer
 * is valid, "under no other circumstances". The address outlives it — Chrome
 * and Safari restore tabs, Forward comes back after "Go back to safety", the
 * browser history opens it again — and no content script runs on this page
 * to check the site. So past the window, or with none, nothing is drawn from
 * the address: the background checks the site again (page: true, as the
 * page check does) and the page shows that answer — a block, with its own
 * window written back into the address, or "checked again, not flagged
 * now" with a button to open the site. A page left open takes the warning
 * down when the window ends, and when it is shown again (visibilitychange,
 * pageshow from the back/forward cache: hidden tabs' timers are throttled).
 */
(function () {
  "use strict";

  var B = self.cleanwayBlockedUrl;
  var shown = B.parse(location.search);
  // A stale cached copy can come back with milliseconds left: not re-asked
  // in a tight loop.
  var MIN_WAIT_MS = 1000;
  // The site check waits up to 3 s for the API (background/public-check.js).
  var ANSWER_TIMEOUT_MS = 10000;
  var RECHECK_EN = {
    block_rechecking: "Checking $DOMAIN$ again…",
    block_recheck_title: "Checked again",
    block_recheck_clear: "$DOMAIN$ is not flagged as dangerous now. The earlier warning has expired.",
    block_recheck_failed: "Cleanway could not check $DOMAIN$ again right now. The earlier warning has expired.",
    block_recheck_open: "Open the site",
    block_recheck_back: "Go back",
  };

  var expiryTimer = null;
  var asking = false;
  var warningDrawn = false;

  function send(message) {
    try {
      var sent = chrome.runtime.sendMessage(message);
      if (sent && typeof sent.catch === "function") sent.catch(function () {});
    } catch (e) { /* the extension was reloaded under this page */ }
  }

  /** The background's reply, or null: no background, an error, no reply in time. */
  function ask(message) {
    return new Promise(function (resolve) {
      var done = false;
      var giveUp = null;
      var finish = function (value) {
        if (done) return;
        done = true;
        if (giveUp) clearTimeout(giveUp);
        resolve(value || null);
      };
      giveUp = setTimeout(function () { finish(null); }, ANSWER_TIMEOUT_MS);
      try {
        var sent = chrome.runtime.sendMessage(message);
        if (sent && typeof sent.then === "function") sent.then(finish, function () { finish(null); });
        else finish(null);
      } catch (e) {
        finish(null);
      }
    });
  }

  function _t(key, subs) {
    try {
      var text = chrome.i18n.getMessage(key, subs || []);
      if (text) return text;
    } catch (e) { /* the English below */ }
    var en = RECHECK_EN[key] || key;
    return subs && subs.length ? en.replace("$DOMAIN$", String(subs[0])) : en;
  }

  try {
    document.title = chrome.i18n.getMessage("block_title") + " — Cleanway";
    var lang = chrome.i18n.getUILanguage();
    if (lang) document.documentElement.lang = lang;
  } catch (e) { /* keep the defaults */ }

  function goBack() {
    if (window.history.length > 2) window.history.go(-2);
    else send({ type: "CLOSE_TAB" });
  }

  /** Whatever is on screen: the warning, or the "checked again" note. */
  function clearScreen() {
    ["ls-block-overlay", "cw-recheck"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.remove();
    });
    document.body.style.overflow = "";
    warningDrawn = false;
  }

  function drawWarning() {
    document.documentElement.style.background = "";
    document.body.style.background = "";
    window.__cleanwayShowBlockPage(
      {
        domain: shown.domain,
        level: "dangerous",
        confidence_pct: shown.confidence_pct === null ? undefined : shown.confidence_pct,
        reasons: shown.reasons,
      },
      {
        onBack: goBack,
        // No address to go back to (malformed, or not http/https): no button
        // action — the countdown still runs, the click does nothing.
        onProceed: function () {
          if (shown.url) send({ type: "BLOCK_PROCEED" });
        },
      }
    );
    warningDrawn = true;
    if (!shown.url) {
      var proceed = document.getElementById("ls-block-proceed");
      if (proceed) proceed.style.display = "none";
    }
    watchWindow();
  }

  /** Google's window ends: the warning goes and the site is asked about again. */
  function watchWindow() {
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
    if (typeof shown.advisory_until !== "number") return;
    expiryTimer = setTimeout(recheck, Math.max(shown.advisory_until - Date.now(), MIN_WAIT_MS));
  }

  function button(text, primary, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = text;
    b.style.cssText = "font:inherit;font-size:16px;font-weight:600;padding:12px 20px;margin:6px;border-radius:10px;cursor:pointer;min-height:44px;"
      + (primary ? "background:#f8fafc;color:#0f172a;border:1px solid #f8fafc;" : "background:transparent;color:#f8fafc;border:1px solid #94a3b8;");
    b.addEventListener("click", onClick);
    return b;
  }

  /** Neutral: no warning, no Google credit. `title` only once the answer is in. */
  function drawNote(title, line, withOpen) {
    var dark = "#0f172a";
    document.documentElement.style.background = dark;
    document.body.style.background = dark;
    var box = document.createElement("div");
    box.id = "cw-recheck";
    box.setAttribute("role", "status");
    try { box.dir = chrome.i18n.getMessage("@@bidi_dir") || "ltr"; } catch (e) { box.dir = "ltr"; }
    box.style.cssText = "max-width:560px;margin:15vh auto 0;padding:0 16px;color:#f8fafc;"
      + "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;text-align:center;";
    if (title) {
      var h = document.createElement("h1");
      h.style.cssText = "font-size:28px;margin:0 0 12px;";
      h.textContent = title;
      box.appendChild(h);
    }
    var p = document.createElement("p");
    p.style.cssText = "font-size:17px;line-height:1.5;margin:0 0 20px;overflow-wrap:anywhere;";
    p.textContent = line;
    box.appendChild(p);
    var actions = document.createElement("div");
    actions.appendChild(button(_t("block_recheck_back"), !withOpen, goBack));
    if (withOpen && shown.url) {
      // Straight to the site, no "open anyway" allowance: if it is flagged
      // again, the page check blocks it again.
      actions.appendChild(button(_t("block_recheck_open"), true, function () { location.replace(shown.url); }));
    }
    box.appendChild(actions);
    document.body.appendChild(box);
  }

  function recheck() {
    if (asking) return;
    asking = true;
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
    clearScreen();
    drawNote("", _t("block_rechecking", [shown.domain]), false);
    ask({ type: "CHECK_DOMAINS", domains: [shown.domain], page: true }).then(function (reply) {
      asking = false;
      var r = reply && Array.isArray(reply.results) ? reply.results[0] : null;
      clearScreen();
      if (r && r.level === "dangerous") {
        var base = "";
        try { base = chrome.runtime.getURL(""); } catch (e) { /* the old address stays */ }
        var next = base ? B.build(base, {
          domain: shown.domain,
          confidence_pct: r.confidence_pct,
          reasons: r.reasons,
          advisory_until: r.advisory_until,
        }, shown.url) : null;
        if (next) {
          // The fresh verdict and its window in the address: a reload, the
          // popup and "open anyway" read this one.
          try { window.history.replaceState(null, "", next); } catch (e) { /* the page still draws it */ }
          shown = B.parse(next);
        }
        drawWarning();
        return;
      }
      drawNote(_t("block_recheck_title"), r ? _t("block_recheck_clear", [shown.domain]) : _t("block_recheck_failed", [shown.domain]), true);
    });
  }

  function recheckIfOver() {
    if (warningDrawn && !asking && B.needsRecheck(shown, Date.now())) recheck();
  }

  if (shown.domain && B.needsRecheck(shown, Date.now())) recheck();
  else drawWarning();

  document.addEventListener("visibilitychange", function () {
    if (!document.hidden) recheckIfOver();
  });
  window.addEventListener("pageshow", function (ev) {
    if (ev && ev.persisted) recheckIfOver();
  });
})();
