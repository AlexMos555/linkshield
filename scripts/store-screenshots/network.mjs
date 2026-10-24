/**
 * Everything the browser asks the network for, answered by this script.
 *
 * Chromium runs with every host name mapped to nowhere, and browser-wide
 * DevTools Fetch interception (cdp.mjs) pauses each http(s) request:
 *   - api.cleanway.ai: the stub below, the e2e test's approach
 *     (scripts/test-extension-sw.mjs) without its invented verdicts: a site
 *     check gets the verdict the extension's OWN offline rules give that host
 *     (src/utils/local-scorer.js of the loaded build), /health gets 200, and
 *     anything else a 404.
 *   - the demo hosts: their pages from fixtures.mjs.
 *   - anything else: refused as if the name did not resolve, and logged.
 * Playwright's own routes would miss the toolbar popup, which Playwright
 * never sees as a page.
 */
import { pageFor } from "./fixtures.mjs";

export const API_HOST = "api.cleanway.ai";

export function stubAnswer(method, url, score) {
  const path = new URL(url).pathname;
  if (method === "GET" && path === "/health") return [200, { status: "ok" }];
  const check = path.match(/^\/api\/v1\/public\/check\/([^/]+)$/);
  if (method === "GET" && check) {
    const host = decodeURIComponent(check[1]);
    const v = score(host);
    // The public check's shape: English signals with their reason codes
    // (background/index.js apiReasons maps the codes to the user's language).
    return [200, {
      domain: host,
      score: v.score,
      level: v.level,
      signals: v.reasons.map((r) => r.detail),
      reason_codes: v.reasons.map((r) => r.signal),
    }];
  }
  return [404, { detail: "Not answered by the screenshot stub" }];
}

/** Start answering. `log.api` and `log.refused` (Sets) collect what was asked. */
export function interceptAll(browser, lang, score, log) {
  const fulfill = (requestId, status, type, body, extra = []) => browser.send("Fetch.fulfillRequest", {
    requestId,
    responseCode: status,
    responseHeaders: [{ name: "Content-Type", value: type }, { name: "Cache-Control", value: "no-store" }, ...extra],
    body: Buffer.from(body).toString("base64"),
  });
  browser.on("Fetch.requestPaused", async ({ requestId, request }) => {
    const url = request.url;
    // The patterns below are http(s) only; anything else is not network.
    if (!/^https?:/.test(url)) return browser.send("Fetch.continueRequest", { requestId });
    const u = new URL(url);
    if (u.hostname === API_HOST) {
      const [status, body] = stubAnswer(request.method, url, score);
      log.api.add(`${request.method} ${u.pathname}${u.search} → ${status}${body.level ? ` ${body.level}` : ""}`);
      // Like the real API: no CORS headers for a web page's own origin.
      const origin = request.headers.Origin || request.headers.origin || "";
      const cors = /^https?:/.test(origin) ? [] : [{ name: "Access-Control-Allow-Origin", value: "*" }];
      return fulfill(requestId, status, "application/json", JSON.stringify(body), cors);
    }
    const html = pageFor(url, lang);
    if (html) return fulfill(requestId, 200, "text/html; charset=utf-8", html);
    log.refused.add(`${u.origin}${u.pathname}`);
    return browser.send("Fetch.failRequest", { requestId, errorReason: "NameNotResolved" });
  });
  return browser.send("Fetch.enable", { patterns: [{ urlPattern: "http://*" }, { urlPattern: "https://*" }] });
}
