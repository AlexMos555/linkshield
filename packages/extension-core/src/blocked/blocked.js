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
 *
 * Only the server's answer is "checked again" (source "api", or "platform"
 * for a user-content host). Without one — the lookup's 3 s ran out, a 5xx,
 * a 429, offline — the background hands back the offline scorer's guess
 * (source "local"), and that is no fresh check: right at the window's end
 * the server has dropped its own copy too and analyses the site anew, often
 * for longer than 3 s. So the page asks once more a few seconds later, then
 * says it could not check, with "Try again" as the main button. Kids mode
 * never gets "Open the site", on any screen: a child should not get past a
 * block from this page (block-page.js).
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
  // No answer from the server: asked once more after this. The server keeps
  // analysing after the extension stops waiting, and caches what it found.
  var RETRY_AFTER_MS = 5000;
  // A Google block with no window of its own (advisory_ttl 0) comes back
  // with the background's 30 s: neither side keeps it, so every round is a
  // fresh analysis on the server, counted against this install's limit.
  // After this many such rounds in a row the page stops asking by itself.
  var SHORT_WINDOW_MS = 60000;
  var MAX_SHORT_ROUNDS = 3;
  // Settings never answering: "Open the site" stays hidden (skillLevel).
  var SKILL_TIMEOUT_MS = 1000;
  var RECHECK_EN = {
    block_rechecking: "Checking $DOMAIN$ again…",
    block_recheck_title: "Checked again",
    block_recheck_clear: "$DOMAIN$ is not flagged as dangerous now. The earlier warning has expired.",
    block_recheck_caution: "It still shows some signs of a scam. Don't enter passwords or card details there unless you trust it.",
    block_recheck_failed_title: "Could not check again",
    block_recheck_failed: "Cleanway could not check $DOMAIN$ again right now. The earlier warning has expired.",
    block_recheck_paused: "The earlier warning about $DOMAIN$ has expired. Press “Try again” to check the site once more.",
    block_recheck_retry: "Try again",
    block_recheck_open: "Open the site",
    block_recheck_back: "Go back",
  };

  var expiryTimer = null;
  var asking = false;
  var warningDrawn = false;
  var shortRounds = 0;

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

  /**
   * The persona from Settings (chrome.storage.local, as block-page.js reads
   * it). Settings that never answer count as Kids: no way into the site.
   */
  var skillLevel = new Promise(function (resolve) {
    var done = false;
    var finish = function (data) {
      if (done) return;
      done = true;
      resolve((data && data.skill_level) || "regular");
    };
    setTimeout(function () { finish({ skill_level: "kids" }); }, SKILL_TIMEOUT_MS);
    try {
      var got = chrome.storage.local.get(["skill_level"], finish);
      if (got && typeof got.then === "function") got.then(finish, function () { finish(null); });
    } catch (e) {
      finish(null);
    }
  });

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
    expiryTimer = setTimeout(windowOver, Math.max(shown.advisory_until - Date.now(), MIN_WAIT_MS));
  }

  function windowOver() {
    if (shortRounds >= MAX_SHORT_ROUNDS) pause();
    else recheck();
  }

  function button(text, main, onClick) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = text;
    if (main) b.setAttribute("data-main", "true");
    b.style.cssText = "font:inherit;font-size:16px;font-weight:600;padding:12px 20px;margin:6px;border-radius:10px;cursor:pointer;min-height:44px;"
      + (main ? "background:#f8fafc;color:#0f172a;border:1px solid #f8fafc;" : "background:transparent;color:#f8fafc;border:1px solid #94a3b8;");
    b.addEventListener("click", onClick);
    return b;
  }

  var BACK = { key: "block_recheck_back", onClick: goBack };
  var RETRY = { key: "block_recheck_retry", onClick: function () { shortRounds = 0; recheck(); } };
  // Straight to the site, no "open anyway" allowance: if it is flagged
  // again, the page check blocks it again.
  var OPEN = { key: "block_recheck_open", onClick: function () { location.replace(shown.url); } };

  /**
   * Neutral: no warning, no Google credit. `title` only once the answer is
   * in. `actions`: the main one first.
   */
  function drawNote(title, lines, actions) {
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
    lines.forEach(function (line) {
      var p = document.createElement("p");
      p.style.cssText = "font-size:17px;line-height:1.5;margin:0 0 20px;overflow-wrap:anywhere;";
      p.textContent = line;
      box.appendChild(p);
    });
    var row = document.createElement("div");
    actions.forEach(function (a, i) {
      row.appendChild(button(_t(a.key), i === 0, a.onClick));
    });
    box.appendChild(row);
    document.body.appendChild(box);
  }

  /** The server's answer (or the platform rule), not the offline guess. */
  function checked(r) {
    return Boolean(r) && (r.source === "api" || r.source === "platform");
  }

  function askSite() {
    return ask({ type: "CHECK_DOMAINS", domains: [shown.domain], page: true }).then(function (reply) {
      return reply && Array.isArray(reply.results) && reply.results[0] ? reply.results[0] : null;
    });
  }

  /** Once more after a few seconds, unless the first answer settles it. */
  function askSiteTwice() {
    return askSite().then(function (r) {
      if (r && (r.level === "dangerous" || checked(r))) return r;
      return new Promise(function (resolve) {
        setTimeout(function () { resolve(askSite()); }, RETRY_AFTER_MS);
      });
    });
  }

  function drawBlock(r) {
    var left = typeof r.advisory_until === "number" ? r.advisory_until - Date.now() : null;
    shortRounds = left !== null && left <= SHORT_WINDOW_MS ? shortRounds + 1 : 0;
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
  }

  function drawAnswer(r, skill) {
    var open = skill !== "kids" && shown.url ? [OPEN] : [];
    var d = [shown.domain];
    if (checked(r)) {
      var lines = [_t("block_recheck_clear", d)];
      if (r.level === "caution") lines.push(_t("block_recheck_caution"));
      drawNote(_t("block_recheck_title"), lines, open.concat([BACK]));
    } else {
      drawNote(_t("block_recheck_failed_title"), [_t("block_recheck_failed", d)], [RETRY, BACK].concat(open));
    }
  }

  function recheck() {
    if (asking) return;
    asking = true;
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
    clearScreen();
    drawNote("", [_t("block_rechecking", [shown.domain])], [BACK]);
    Promise.all([askSiteTwice(), skillLevel]).then(function (got) {
      asking = false;
      var r = got[0];
      clearScreen();
      if (r && r.level === "dangerous") drawBlock(r);
      else drawAnswer(r, got[1]);
    });
  }

  /**
   * A Google block with no window, asked about MAX_SHORT_ROUNDS times in a
   * row: its warning goes as before, and the page waits for the person.
   */
  function pause() {
    if (expiryTimer) clearTimeout(expiryTimer);
    expiryTimer = null;
    clearScreen();
    drawNote("", [_t("block_recheck_paused", [shown.domain])], [RETRY, BACK]);
  }

  function recheckIfOver() {
    if (warningDrawn && !asking && B.needsRecheck(shown, Date.now())) windowOver();
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
