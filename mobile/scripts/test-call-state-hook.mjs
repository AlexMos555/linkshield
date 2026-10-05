#!/usr/bin/env node
/**
 * Regression test for src/hooks/useCallState.ts — run with
 * `node scripts/test-call-state-hook.mjs`.
 *
 * The hook behind the stop screen runs under real React 18 here, against a
 * stand-in for the native module (CallState.kt: the audio mode, no
 * permission). What is pinned:
 *
 *  1. Where calls cannot be seen (iOS, an older native build, a native call
 *     that throws) the snapshot is null and no reason is ever given — the
 *     screen must never claim to know about a call it cannot see.
 *  2. A call already going on when the screen opens is seen at once; a call
 *     that ends while the screen is open turns into the 30-minute window
 *     through the module's event, and the window closes by itself without a
 *     foreground or a re-render from anywhere else.
 *  3. Coming back to the foreground re-reads the phone; `refresh()` — what
 *     the guard calls the moment an action is asked for — answers from the
 *     phone, not from the last event.
 *  4. The module's listener is registered while the screen lives and removed
 *     with it.
 *
 * No test runner in mobile/: the hook is transpiled with the tree's
 * TypeScript and loaded with a small require that hands it its stubs; react /
 * react-dom come from mobile/node_modules.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

const MINUTE = 60_000;
const WINDOW = 30 * MINUTE; // call-guard.ts AFTER_CALL_WINDOW_MS

// ── the world the hook talks to: the phone, the module, the OS ─────

let world;

const IDLE = { inCall: false, ringing: false, callStartedAt: 0, callEndedAt: 0, windowEndsAt: 0, guardActive: false };

function resetWorld() {
  world = {
    platform: "android",
    phone: { ...IDLE },
    nativeThrows: false,
    appState: "active",
    listeners: { call: [], app: [] },
  };
}

function subscribe(kind, cb) {
  world.listeners[kind] = [...world.listeners[kind], cb];
  return { remove: () => { world.listeners[kind] = world.listeners[kind].filter((l) => l !== cb); } };
}

function emit(kind, payload) {
  for (const cb of world.listeners[kind]) cb(payload);
}

/** CallState.kt as the module reports it. */
const VPN = {
  callState: () => {
    if (world.nativeThrows) throw new Error("module gone");
    return { ...world.phone };
  },
  addCallStateChangedListener: (cb) => subscribe("call", cb),
};

const STUBS = {
  "react-native": {
    Platform: {
      get OS() {
        return world.platform;
      },
    },
    AppState: {
      get currentState() {
        return world.appState;
      },
      addEventListener: (_type, cb) => subscribe("app", cb),
    },
  },
  "../../modules/cleanway-vpn": VPN,
};

/** CommonJS-load a .ts file of the app, the stubs above in place of its imports. */
function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (spec in STUBS) return STUBS[spec];
    if (spec.startsWith(".")) return loadTs(resolve(dirname(file), `${spec}.ts`));
    return appRequire(spec);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

// ── React 18 in node: a root whose component renders nothing ────────

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
globalThis.window = { HTMLIFrameElement: class {}, document: { activeElement: null } };
globalThis.document = globalThis.window.document;
const React = appRequire("react");
const { createRoot } = appRequire("react-dom/client");
const { act } = React;
const noop = () => {};
const container = () => ({
  nodeType: 1, nodeName: "DIV", tagName: "DIV", namespaceURI: "http://www.w3.org/1999/xhtml",
  addEventListener: noop, removeEventListener: noop,
  ownerDocument: { nodeType: 9, addEventListener: noop, removeEventListener: noop },
});

const { useCallState } = loadTs(join(root, "src/hooks/useCallState.ts"));

/** Let promises, effects and timers up to [ms] run. */
const settle = (ms = 5) => act(async () => {
  await new Promise((r) => setTimeout(r, ms));
});

/** A screen that asks the hook: what it says now, and its refresh. */
async function openScreen() {
  let view = null;
  function Screen() {
    view = useCallState();
    return null;
  }
  const rootNode = createRoot(container());
  await act(async () => rootNode.render(React.createElement(Screen)));
  await settle();
  return {
    now: () => ({ seen: view.snapshot !== null, reason: view.reason }),
    refresh: () => {
      let answer;
      act(() => { answer = view.refresh(); });
      return answer;
    },
    close: async () => act(async () => rootNode.unmount()),
  };
}

const inCall = () => ({ ...IDLE, inCall: true, callStartedAt: Date.now() - 2 * MINUTE, guardActive: true });
const endedAgo = (ms) => ({
  ...IDLE, callStartedAt: Date.now() - ms - 3 * MINUTE, callEndedAt: Date.now() - ms,
  windowEndsAt: Date.now() - ms + WINDOW, guardActive: ms < WINDOW,
});

const CASES = [
  [
    "iOS: no snapshot, no reason, no listener",
    async () => {
      world.platform = "ios";
      const screen = await openScreen();
      const now = screen.now();
      const listeners = world.listeners.call.length;
      await screen.close();
      return { ...now, listeners };
    },
    { seen: false, reason: null, listeners: 0 },
  ],
  [
    "the native call throws: nothing is claimed",
    async () => {
      world.nativeThrows = true;
      const screen = await openScreen();
      const now = screen.now();
      await screen.close();
      return now;
    },
    { seen: false, reason: null },
  ],
  [
    "an idle phone: seen, no reason",
    async () => {
      const screen = await openScreen();
      const now = screen.now();
      await screen.close();
      return now;
    },
    { seen: true, reason: null },
  ],
  [
    "a call already going on when the screen opens",
    async () => {
      world.phone = inCall();
      const screen = await openScreen();
      const now = screen.now();
      await screen.close();
      return now;
    },
    { seen: true, reason: "in_call" },
  ],
  [
    "the call ends while the screen is open: the module's event turns it into the window",
    async () => {
      world.phone = inCall();
      const screen = await openScreen();
      const during = screen.now().reason;
      world.phone = endedAgo(0);
      await act(async () => emit("call", { ...world.phone }));
      await settle();
      const after = screen.now().reason;
      await screen.close();
      return { during, after };
    },
    { during: "in_call", after: "after_call" },
  ],
  [
    "the window closes by itself, with nothing else touching the screen",
    async () => {
      // The call ended 30 minutes minus 700 ms ago: the window closes in 700 ms.
      world.phone = endedAgo(WINDOW - 700);
      const screen = await openScreen();
      const open = screen.now().reason;
      await settle(1_500);
      const closed = screen.now().reason;
      await screen.close();
      return { open, closed };
    },
    { open: "after_call", closed: null },
  ],
  [
    "a call 31 minutes ago is over, whatever the stale native flag says",
    async () => {
      world.phone = { ...endedAgo(31 * MINUTE), guardActive: true };
      const screen = await openScreen();
      const now = screen.now();
      await screen.close();
      return now;
    },
    { seen: true, reason: null },
  ],
  [
    "back in the foreground the phone is read again",
    async () => {
      const screen = await openScreen();
      const before = screen.now().reason;
      await act(async () => {
        world.appState = "background";
        emit("app", "background");
      });
      world.phone = inCall();
      await act(async () => {
        world.appState = "active";
        emit("app", "active");
      });
      await settle();
      const after = screen.now().reason;
      await screen.close();
      return { before, after };
    },
    { before: null, after: "in_call" },
  ],
  [
    "refresh() answers from the phone, now — what the guard needs the moment an action is asked for",
    async () => {
      const screen = await openScreen();
      world.phone = inCall();
      const answer = screen.refresh();
      const shown = screen.now().reason;
      await screen.close();
      return { answer, shown };
    },
    { answer: "in_call", shown: "in_call" },
  ],
  [
    "the module's listener lives with the screen",
    async () => {
      const screen = await openScreen();
      const open = world.listeners.call.length;
      await screen.close();
      return { open, closed: world.listeners.call.length };
    },
    { open: 1, closed: 0 },
  ],
];

let failed = 0;
for (const [name, run, expected] of CASES) {
  resetWorld();
  try {
    deepStrictEqual(await run(), expected);
    console.log(`  ok    ${name}`);
  } catch (e) {
    failed += 1;
    console.log(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
  }
}
console.log(failed === 0 ? `all ${CASES.length} cases pass` : `${failed} of ${CASES.length} cases FAILED`);
process.exit(failed === 0 ? 0 : 1);
