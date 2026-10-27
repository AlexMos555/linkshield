/**
 * A second, browser-level DevTools connection next to Playwright's own.
 *
 * Playwright drives the tabs, but three things the store shots need live on
 * the browser target, which a persistent context does not expose:
 *   - Extensions.triggerAction: the toolbar click. It opens the extension's
 *     real popup over a tab and grants activeTab for that tab, exactly as a
 *     person clicking the icon does (a popup opened any other way cannot read
 *     the tab's address and says "Couldn't check this page").
 *   - The popup itself: Chromium hosts it outside the tab strip, so
 *     Playwright never sees it as a page. It is attached and captured here.
 *   - Fetch interception for the whole browser, service worker and popup
 *     included, so no request reaches a real server (see extension.mjs).
 *
 * Chromium is started with --remote-debugging-port=0 and writes the port to
 * <profile>/DevToolsActivePort. Node 22's built-in WebSocket does the rest.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function debuggingPort(profileDir, timeoutMs = 30000) {
  const file = join(profileDir, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      const port = readFileSync(file, "utf8").split("\n")[0].trim();
      if (/^\d+$/.test(port)) return Number(port);
    }
    await sleep(100);
  }
  throw new Error(`no DevToolsActivePort in ${profileDir}`);
}

export async function connectBrowser(profileDir) {
  const port = await debuggingPort(profileDir);
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const ws = new WebSocket(version.webSocketDebuggerUrl);
  await new Promise((ok, fail) => {
    ws.addEventListener("open", ok, { once: true });
    ws.addEventListener("error", () => fail(new Error("DevTools websocket failed")), { once: true });
  });

  let nextId = 0;
  const pending = new Map();
  const listeners = new Map();
  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { ok, fail, method } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) fail(new Error(`${method}: ${msg.error.message}`));
      else ok(msg.result);
      return;
    }
    for (const fn of listeners.get(msg.method) || []) {
      Promise.resolve(fn(msg.params, msg.sessionId)).catch((err) => console.error(`  ! ${msg.method}: ${err.message}`));
    }
  });

  function send(method, params = {}, sessionId) {
    const id = ++nextId;
    return new Promise((ok, fail) => {
      pending.set(id, { ok, fail, method });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  function on(method, fn) {
    if (!listeners.has(method)) listeners.set(method, []);
    listeners.get(method).push(fn);
  }

  /** Evaluate in an attached session; returns the value (JSON-serialisable). */
  async function evaluate(sessionId, expression) {
    const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (r.exceptionDetails) throw new Error(`evaluate: ${r.exceptionDetails.text} ${expression.slice(0, 80)}`);
    return r.result.value;
  }

  return {
    version: version.Browser,
    send,
    on,
    evaluate,
    close: () => ws.close(),
  };
}
