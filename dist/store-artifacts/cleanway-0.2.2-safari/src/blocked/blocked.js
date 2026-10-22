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
 */
(function () {
  "use strict";

  var shown = self.cleanwayBlockedUrl.parse(location.search);

  function send(message) {
    try {
      var sent = chrome.runtime.sendMessage(message);
      if (sent && typeof sent.catch === "function") sent.catch(function () {});
    } catch (e) { /* the extension was reloaded under this page */ }
  }

  try {
    document.title = chrome.i18n.getMessage("block_title") + " — Cleanway";
    var lang = chrome.i18n.getUILanguage();
    if (lang) document.documentElement.lang = lang;
  } catch (e) { /* keep the defaults */ }

  window.__cleanwayShowBlockPage(
    {
      domain: shown.domain,
      level: "dangerous",
      confidence_pct: shown.confidence_pct === null ? undefined : shown.confidence_pct,
      reasons: shown.reasons,
    },
    {
      onBack: function () {
        if (window.history.length > 2) window.history.go(-2);
        else send({ type: "CLOSE_TAB" });
      },
      // No address to go back to (malformed, or not http/https): no button
      // action — the countdown still runs, the click does nothing.
      onProceed: function () {
        if (shown.url) send({ type: "BLOCK_PROCEED" });
      },
    }
  );

  if (!shown.url) {
    var proceed = document.getElementById("ls-block-proceed");
    if (proceed) proceed.style.display = "none";
  }
})();
