/**
 * Just enough W3C WebDriver to drive a real Firefox through geckodriver,
 * with Node's own fetch: no Selenium, nothing added to the repository.
 *
 * geckodriver runs with --allow-system-access, so scripts can also run in
 * Firefox's privileged "chrome" context. Three things need it:
 *   - the toolbar click: browserAction.triggerAction(window), the same call
 *     Firefox makes for the add-on's keyboard shortcut. It opens the real
 *     popup over the tab and grants activeTab for it, as a click does
 *     (action.openPopup() would not grant it, and the popup could not read
 *     the tab's address);
 *   - a picture of that popup, which lives in a panel outside every tab
 *     (drawSnapshot of the popup's own document);
 *   - the error console of the whole browser (nsIConsoleService): uncaught
 *     errors and CSP refusals of the background page, the popup, every
 *     extension page and content script, with their file and line.
 * (console.error/warn calls are not in that console; Firefox prints them on
 * stdout with devtools.console.stdout.content, and geckodriver passes it on.)
 */
import { spawn } from "node:child_process";
import { createServer } from "node:net";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.on("error", reject);
  s.listen(0, "127.0.0.1", () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});

/**
 * Start geckodriver, with Firefox's profile under `profileRoot`; `output`
 * collects its stdout/stderr lines, which carry Firefox's own.
 */
export async function startGeckodriver(bin, profileRoot) {
  const port = await freePort();
  const proc = spawn(bin, ["--port", String(port), "--allow-system-access", "--log", "info", "--profile-root", profileRoot],
    { stdio: ["ignore", "pipe", "pipe"] });
  let spawnError = null;
  proc.on("error", (e) => { spawnError = e; });
  const output = [];
  const keep = (d) => output.push(...d.toString().split("\n").filter(Boolean));
  proc.stdout.on("data", keep);
  proc.stderr.on("data", keep);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 100; i++) {
    if (spawnError) throw new Error(`cannot run geckodriver (${bin}): ${spawnError.message} — pass --geckodriver <path>`);
    if (proc.exitCode !== null) throw new Error(`geckodriver exited: ${output.join("\n")}`);
    const ok = await fetch(`${base}/status`).then((r) => r.ok, () => false);
    if (ok) return { base, output, stop: () => proc.kill() };
    await sleep(100);
  }
  proc.kill();
  throw new Error("geckodriver did not start");
}

/** One WebDriver session. */
export class Session {
  static async create(base, capabilities) {
    const s = new Session(base, null);
    const v = await s.call("POST", "/session", { capabilities: { alwaysMatch: capabilities } }, false);
    s.id = v.sessionId;
    s.capabilities = v.capabilities;
    return s;
  }

  constructor(base, id) {
    this.base = base;
    this.id = id;
    this.context = "content";
  }

  async call(method, path, body, inSession = true) {
    const url = `${this.base}${inSession ? `/session/${this.id}` : ""}${path}`;
    const r = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const j = await r.json();
    if (j.value && j.value.error) throw new Error(`${method} ${path}: ${j.value.error}: ${j.value.message}`);
    return j.value;
  }

  async setContext(context) {
    if (this.context === context) return;
    await this.call("POST", "/moz/context", { context });
    this.context = context;
  }

  /** Firefox's process id, to make sure it is gone at the end. */
  get firefoxPid() { return this.capabilities && this.capabilities["moz:processID"]; }

  /** Run `script` (a function body) in the current tab's page. */
  async content(script, ...args) {
    await this.setContext("content");
    return this.call("POST", "/execute/sync", { script, args });
  }

  /** Run `script` (an async function body: `await` works) in the browser's privileged context. */
  async chrome(script, ...args) {
    await this.setContext("chrome");
    const wrapped = `const done = arguments[arguments.length - 1];
      (async (...args) => { ${script} })(...Array.from(arguments).slice(0, -1))
        .then((v) => done({ ok: v }), (e) => done({ err: String(e && e.stack || e) }));`;
    const r = await this.call("POST", "/execute/async", { script: wrapped, args });
    if (r && r.err) throw new Error(`chrome script: ${r.err}`);
    return r && r.ok;
  }

  async installTemporaryAddon(path) {
    return this.call("POST", "/moz/addon/install", { path, temporary: true });
  }

  // Tabs, addresses and screenshots: in the chrome context the same
  // commands would name browser windows and chrome:// documents instead.
  async tabCall(method, path, body) {
    await this.setContext("content");
    return this.call(method, path, body);
  }

  handles() { return this.tabCall("GET", "/window/handles"); }
  currentHandle() { return this.tabCall("GET", "/window"); }
  switchTo(handle) { return this.tabCall("POST", "/window", { handle }); }
  closeTab() { return this.tabCall("DELETE", "/window"); }
  newWindow() { return this.tabCall("POST", "/window/new", { type: "window" }).then((v) => v.handle); }
  setRect(width, height) { return this.tabCall("POST", "/window/rect", { width, height }); }
  url() { return this.tabCall("GET", "/url"); }
  go(url) { return this.tabCall("POST", "/url", { url }); }

  async screenshot() {
    return Buffer.from(await this.tabCall("GET", "/screenshot"), "base64");
  }

  /** End the session (Firefox quits); if that fails, stop Firefox's process. */
  async quit() {
    const ok = await this.call("DELETE", "").then(() => true, () => false);
    if (!ok && this.firefoxPid) {
      try { process.kill(this.firefoxPid); } catch (e) { /* already gone */ }
    }
  }
}

const CONSOLE_TOPIC = "cleanway-smoke-console";

/**
 * Keep every error and warning Firefox's error console receives, from the
 * start of the browser on (the messages logged before this call are taken
 * too). Chrome-context scripts run in a fresh scope per window, so the list
 * is handed out through an observer topic, not a global.
 */
export async function watchErrorConsole(session) {
  await session.chrome(`
    const kept = [];
    const take = (m) => {
      if (!(m instanceof Ci.nsIScriptError)) return;
      if ((m.flags & Ci.nsIScriptError.infoFlag) !== 0) return;
      const isWarning = (m.flags & Ci.nsIScriptError.warningFlag) !== 0;
      kept.push({ level: isWarning ? "warning" : "error", category: m.category, message: m.errorMessage,
        source: m.sourceName, line: m.lineNumber, column: m.columnNumber });
    };
    for (const m of Services.console.getMessageArray() || []) take(m);
    Services.console.registerListener({ observe: take });
    Services.obs.addObserver({ observe: (subject) => { subject.wrappedJSObject.json = JSON.stringify(kept); } },
      "${CONSOLE_TOPIC}");
  `);
}

/** What watchErrorConsole has kept so far: [{level, category, message, source, line, column}]. */
export async function errorConsole(session) {
  const json = await session.chrome(`
    const holder = { json: "[]" };
    holder.wrappedJSObject = holder;
    Services.obs.notifyObservers(holder, "${CONSOLE_TOPIC}");
    return holder.json;
  `);
  return JSON.parse(json || "[]");
}

/** The privileged-scope helpers the popup functions below share. */
const FIND = `
  const { ExtensionParent } = ChromeUtils.importESModule("resource://gre/modules/ExtensionParent.sys.mjs");
  const extension = ExtensionParent.GlobalManager.getExtension(addonId);
  if (!extension) throw new Error("the add-on " + addonId + " is not running");
  const windows = [...Services.wm.getEnumerator("navigator:browser")];
  const win = windows.find((w) => w.gBrowser && w.gBrowser.selectedBrowser.currentURI.spec.startsWith(tabUrlPrefix));
  if (!win) throw new Error("no window shows " + tabUrlPrefix + ": " + windows.map((w) => w.gBrowser.selectedBrowser.currentURI.spec).join(", "));
  const popupBrowser = () => win.document.querySelector("browser.webextension-popup-browser[webextension-view-type=popup]");
`;

/**
 * Click the add-on's toolbar button in the window whose current tab's
 * address starts with `tabUrlPrefix`: focus it, then triggerAction.
 */
export async function clickToolbarButton(session, addonId, tabUrlPrefix) {
  await session.chrome(`
    const [addonId, tabUrlPrefix] = args;
    ${FIND}
    win.focus();
    for (let i = 0; i < 50 && Services.focus.activeWindow !== win; i++) await new Promise((r) => win.setTimeout(r, 100));
    if (Services.focus.activeWindow !== win) throw new Error("the window did not take focus");
    const action = ExtensionParent.apiManager.global.browserActionFor(extension);
    if (!action) throw new Error("the add-on has no toolbar button");
    action.triggerAction(win);
    for (let i = 0; i < 100 && !popupBrowser(); i++) await new Promise((r) => win.setTimeout(r, 100));
    if (!popupBrowser()) throw new Error("the popup did not open");
    return true;
  `, addonId, tabUrlPrefix);
}

/** The open popup as a PNG (its own document, at its size in the panel). */
export async function popupPng(session, addonId, tabUrlPrefix) {
  const dataUrl = await session.chrome(`
    const [addonId, tabUrlPrefix] = args;
    ${FIND}
    const b = popupBrowser();
    if (!b) throw new Error("no popup is open");
    const bitmap = await b.browsingContext.currentWindowGlobal.drawSnapshot(null, 1, "white");
    const canvas = win.document.createElementNS("http://www.w3.org/1999/xhtml", "canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    canvas.getContext("2d").drawImage(bitmap, 0, 0);
    bitmap.close();
    return canvas.toDataURL("image/png");
  `, addonId, tabUrlPrefix);
  return Buffer.from(dataUrl.replace(/^data:image\/png;base64,/, ""), "base64");
}

/** Close the popup, as clicking the button again does. */
export async function closePopup(session, addonId, tabUrlPrefix) {
  await session.chrome(`
    const [addonId, tabUrlPrefix] = args;
    ${FIND}
    const b = popupBrowser();
    if (!b) return false;
    const panel = b.closest("panel");
    if (panel && typeof panel.hidePopup === "function") panel.hidePopup();
    for (let i = 0; i < 50 && popupBrowser(); i++) await new Promise((r) => win.setTimeout(r, 100));
    return !popupBrowser();
  `, addonId, tabUrlPrefix);
}
