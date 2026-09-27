#!/usr/bin/env node
/**
 * Regression test for src/hooks/useNetworkShield.ts — run with
 * `node scripts/test-network-shield-hook.mjs`.
 *
 * The hook behind the home screen's shield card runs under real React 18
 * here, against a stand-in for the native module that keeps the service's
 * side of things — the stored pause, the intents the service has not handled
 * yet, its events. Three findings of the 1.0.2 emulator run are pinned:
 *
 *  1. «Включить сейчас» during a pause read the stored pause before the
 *     service had handled the resume, so the screen stayed «на паузе» over a
 *     shield that was blocking again. The module now clears the stored pause
 *     before it returns, and the screen follows the service's pause events —
 *     also for the notification's "turn back on", which the screen never saw.
 *  2. The home screen checked the connection only on opening and on a
 *     foreground: it kept «Нет сети / Активных щитов: 0» for five minutes and
 *     more after the network was back. It now re-checks on the module's
 *     connection events — once per burst, and not in the background.
 *  3. A stopped shield said "usually after a reboot, one tap" whatever had
 *     stopped it. The hook now passes on the cause the service recorded.
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
const NETWORK_SETTLE_MS = 1000; // useNetworkShield's

// ── the world the hook talks to: the service, the phone, the OS ─────

let world;

function resetWorld() {
  world = {
    running: true,
    userEnabled: true,
    stopReason: null,
    storedPause: 0,
    serviceInbox: [],
    probeOk: true,
    internet: true,
    probes: 0,
    appState: "active",
    listeners: { stopped: [], pause: [], network: [], app: [] },
  };
}

function subscribe(kind, cb) {
  world.listeners[kind] = [...world.listeners[kind], cb];
  return { remove: () => { world.listeners[kind] = world.listeners[kind].filter((l) => l !== cb); } };
}

function emit(kind, payload) {
  for (const cb of world.listeners[kind]) cb(payload);
}

/** The service handles the intents it was sent, in order (onStartCommand on its main thread). */
function serviceRuns() {
  const inbox = world.serviceInbox;
  world.serviceInbox = [];
  for (const handle of inbox) handle();
}

/** CleanwayVpnService.pauseUntil: store the pause, then announce it. */
function servicePausesUntil(until) {
  world.storedPause = until;
  emit("pause", { until });
}

const VPN = {
  startVpn: async () => true,
  stopVpn: async () => {},
  isVpnRunning: () => world.running,
  wasUserEnabled: () => world.userEnabled,
  lastStopReason: () => world.stopReason,
  privateDnsStrictHost: () => null,
  blocklistStatus: () => ({
    version: 7, count: 460_481, revoked: false, ageMs: MINUTE, stale: false, hasCanary: true, lastError: null, lastFetchAt: 1,
  }),
  verifyFiltering: async () => {
    world.probes += 1;
    return world.probeOk;
  },
  verifyListFiltering: async () => world.probeOk,
  addVpnStoppedListener: (cb) => subscribe("stopped", cb),
  addPauseChangedListener: (cb) => subscribe("pause", cb),
  addNetworkChangedListener: (cb) => subscribe("network", cb),
  pauseProtection: (until) => {
    world.serviceInbox = [...world.serviceInbox, () => servicePausesUntil(until)];
  },
  // The 1.0.3 module: the stored pause is cleared before this returns; the
  // service hears of it later.
  resumeProtection: () => {
    world.storedPause = 0;
    world.serviceInbox = [...world.serviceInbox, () => servicePausesUntil(0)];
  },
  pausedUntil: () => (world.storedPause > Date.now() ? world.storedPause : 0),
};

const STUBS = {
  "react-native": {
    Platform: { OS: "android" },
    AppState: {
      get currentState() {
        return world.appState;
      },
      addEventListener: (_type, cb) => subscribe("app", cb),
    },
  },
  "../../modules/cleanway-vpn": VPN,
};

// hasInternet(): a HEAD to api.cleanway.ai/health.
globalThis.fetch = async () => {
  if (!world.internet) throw new Error("Network request failed");
  return { ok: true };
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

const { useNetworkShield } = loadTs(join(root, "src/hooks/useNetworkShield.ts"));

/** Let promises, effects and timers up to [ms] run. */
const settle = (ms = 5) => act(async () => {
  await new Promise((r) => setTimeout(r, ms));
});

/** The open home screen: what its shield card shows now, and its actions. */
async function openHome() {
  let shield = null;
  function Home() {
    shield = useNetworkShield();
    return null;
  }
  const rootNode = createRoot(container());
  await act(async () => rootNode.render(React.createElement(Home)));
  await settle();
  return {
    now: () => ({
      state: shield.state,
      paused: shield.pausedUntil > 0,
      interrupted: shield.interrupted,
      stopReason: shield.stopReason,
    }),
    resume: async () => {
      await act(async () => shield.resume());
      await settle();
    },
    close: async () => act(async () => rootNode.unmount()),
  };
}

const CASES = [
  [
    "«Включить сейчас»: the screen leaves «на паузе» at once, before the service has handled it",
    async () => {
      world.storedPause = Date.now() + 15 * MINUTE;
      const home = await openHome();
      const before = home.now().state;
      await home.resume();
      const beforeService = home.now().state;
      await act(async () => serviceRuns());
      await settle();
      const after = home.now().state;
      await home.close();
      return { before, beforeService, after };
    },
    { before: "paused", beforeService: "on", after: "on" },
  ],
  [
    "the notification's «Включить сейчас» with the app open (no foreground): the screen follows the service",
    async () => {
      world.storedPause = Date.now() + 15 * MINUTE;
      const home = await openHome();
      const before = home.now().state;
      await act(async () => servicePausesUntil(0));
      await settle();
      const after = home.now().state;
      await home.close();
      return { before, after };
    },
    { before: "paused", after: "on" },
  ],
  [
    "a pause started elsewhere shows on the open screen",
    async () => {
      const home = await openHome();
      await act(async () => servicePausesUntil(Date.now() + 15 * MINUTE));
      await settle();
      const now = home.now();
      await home.close();
      return now;
    },
    { state: "paused", paused: true, interrupted: false, stopReason: null },
  ],
  [
    "the network comes back while the screen is open: «Нет сети» turns into «on» without leaving it",
    async () => {
      world.probeOk = false;
      world.internet = false;
      const home = await openHome();
      const offline = home.now().state;
      world.probeOk = true;
      world.internet = true;
      await act(async () => emit("network", { online: true }));
      await settle(NETWORK_SETTLE_MS + 100);
      const back = home.now().state;
      await home.close();
      return { offline, back };
    },
    { offline: "offline", back: "on" },
  ],
  [
    "the network goes away while the screen is open: «on» turns into «Нет сети»",
    async () => {
      const home = await openHome();
      const on = home.now().state;
      world.probeOk = false;
      world.internet = false;
      await act(async () => emit("network", { online: false }));
      await settle(NETWORK_SETTLE_MS + 100);
      const gone = home.now().state;
      await home.close();
      return { on, gone };
    },
    { on: "on", gone: "offline" },
  ],
  [
    "a burst of connection events is one re-check",
    async () => {
      const home = await openHome();
      const probesBefore = world.probes;
      await act(async () => {
        emit("network", { online: false });
        emit("network", { online: true });
        emit("network", { online: true });
      });
      await settle(NETWORK_SETTLE_MS + 100);
      const probes = world.probes - probesBefore;
      await home.close();
      return { probes };
    },
    { probes: 1 },
  ],
  [
    "in the background a connection event checks nothing (the foreground will)",
    async () => {
      const home = await openHome();
      const probesBefore = world.probes;
      world.appState = "background";
      await act(async () => emit("network", { online: true }));
      await settle(NETWORK_SETTLE_MS + 100);
      const probes = world.probes - probesBefore;
      await home.close();
      return { probes };
    },
    { probes: 0 },
  ],
  [
    "a stopped shield passes on why it stopped",
    async () => {
      world.running = false;
      const seen = [];
      for (const reason of ["revoked", "private_dns", null]) {
        world.stopReason = reason;
        const home = await openHome();
        seen.push(home.now());
        await home.close();
      }
      return seen;
    },
    [
      { state: "setup", paused: false, interrupted: true, stopReason: "revoked" },
      { state: "setup", paused: false, interrupted: true, stopReason: "private_dns" },
      { state: "setup", paused: false, interrupted: true, stopReason: null },
    ],
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
if (failed > 0) {
  console.error(`\n${failed} of ${CASES.length} cases failed`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${CASES.length} cases pass`);
}
