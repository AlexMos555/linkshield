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
 *     connection events — once per burst, and listening only in the
 *     foreground — and re-reads the list when the service swaps one in.
 *  3. A stopped shield said "usually after a reboot, one tap" whatever had
 *     stopped it. The hook now passes on the cause the service recorded, and
 *     the module passes on only the causes the screen has words for.
 *  4. A shield the person left on, killed by a battery manager while the app
 *     was closed, waited for a tap on «Включить снова». Opening the app now
 *     asks the native side to bring it back (rearmShield, the watchdog's
 *     rules); a refusal there leaves the "stopped" screen as before.
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
const REARM_SETTLE_MS = 1500; // useNetworkShield's

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
    listCount: 460_481,
    appState: "active",
    // rearmShield(): undefined = an older native build without the call.
    rearm: undefined,
    rearmCalls: 0,
    listeners: { stopped: [], pause: [], list: [], network: [], app: [] },
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
  rearmShield: () => {
    if (world.rearm === undefined) return undefined;
    world.rearmCalls += 1;
    return world.rearm();
  },
  lastStopReason: () => world.stopReason,
  privateDnsStrictHost: () => null,
  blocklistStatus: () => (world.listCount > 0
    ? { version: 7, count: world.listCount, revoked: false, ageMs: MINUTE, stale: false, hasCanary: true, lastError: null, lastFetchAt: 1 }
    : { version: 0, count: 0, revoked: false, ageMs: null, stale: true, hasCanary: false, lastError: null, lastFetchAt: 0 }),
  verifyFiltering: async () => {
    world.probes += 1;
    return world.probeOk;
  },
  verifyListFiltering: async () => world.probeOk,
  addVpnStoppedListener: (cb) => subscribe("stopped", cb),
  addPauseChangedListener: (cb) => subscribe("pause", cb),
  addBlocklistChangedListener: (cb) => subscribe("list", cb),
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
    listCount: () => shield.blocklist.count,
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
    "the list lands seconds after the network is back: the open screen shows it",
    async () => {
      world.listCount = 0;
      const home = await openHome();
      const before = home.listCount();
      world.listCount = 460_481;
      await act(async () => emit("list", {}));
      await settle();
      const after = home.listCount();
      await home.close();
      return { before, after };
    },
    { before: 0, after: 460_481 },
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
    "in the background the screen does not listen for the connection; back in front it does, and re-checks",
    async () => {
      // The service keeps the process alive all day: a subscription left in
      // place kept the module's network callback registered and woke JS for
      // every change, only for the hook to drop it.
      const home = await openHome();
      const foreground = world.listeners.network.length;
      const probesBefore = world.probes;
      await act(async () => {
        world.appState = "background";
        emit("app", "background");
      });
      const background = world.listeners.network.length;
      await act(async () => {
        world.appState = "active";
        emit("app", "active");
      });
      await settle();
      const back = world.listeners.network.length;
      const probes = world.probes - probesBefore;
      await home.close();
      return { foreground, background, back, probes, afterClose: world.listeners.network.length };
    },
    { foreground: 1, background: 0, back: 1, probes: 1, afterClose: 0 },
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
  [
    "a shield a battery manager killed comes back when the app opens, no tap",
    async () => {
      world.running = false;
      world.rearm = () => {
        world.running = true; // the service came up
        return "start";
      };
      const home = await openHome();
      await settle(REARM_SETTLE_MS + 100);
      const now = home.now();
      await home.close();
      return { ...now, rearmCalls: world.rearmCalls };
    },
    { state: "on", paused: false, interrupted: false, stopReason: null, rearmCalls: 1 },
  ],
  [
    "the native side refuses (Android took the tunnel away): the screen says stopped, and why",
    async () => {
      world.running = false;
      world.stopReason = "revoked";
      world.rearm = () => "taken_away";
      const home = await openHome();
      await settle(REARM_SETTLE_MS + 100);
      const now = home.now();
      await home.close();
      return { ...now, rearmCalls: world.rearmCalls };
    },
    { state: "setup", paused: false, interrupted: true, stopReason: "revoked", rearmCalls: 1 },
  ],
  [
    "asked to start, but the tunnel did not come up: stopped, not a green guess",
    async () => {
      world.running = false;
      world.rearm = () => "start";
      const home = await openHome();
      await settle(REARM_SETTLE_MS + 100);
      const now = home.now();
      await home.close();
      return now;
    },
    { state: "setup", paused: false, interrupted: true, stopReason: null },
  ],
  [
    "turned off by the person: the app never asks to bring it back",
    async () => {
      world.running = false;
      world.userEnabled = false;
      world.rearm = () => "start";
      const home = await openHome();
      await settle();
      const now = home.now();
      await home.close();
      return { ...now, rearmCalls: world.rearmCalls };
    },
    { state: "setup", paused: false, interrupted: false, stopReason: null, rearmCalls: 0 },
  ],
];

// ── the module's side: what reaches the hook from the native call ───

/**
 * modules/cleanway-vpn/index.ts itself, over a native module that answers
 * lastStopReason() with [answer]. The JS bundle and the native build ship
 * separately, so anything the native side might say must come out as a
 * cause the screen has words for, or as none.
 */
function moduleStopReason(answer) {
  STUBS["./src/CleanwayVpnModule"] = {
    lastStopReason: typeof answer === "function" ? answer : () => answer,
  };
  return loadTs(join(root, "modules/cleanway-vpn/index.ts")).lastStopReason();
}

const MODULE_CASES = [
  ["«revoked» passes", "revoked", "revoked"],
  ["«private_dns» passes", "private_dns", "private_dns"],
  ["a cause a newer native build knows reads as none", "battery_saver", null],
  ["nothing recorded", null, null],
  ["not a string", 42, null],
  ["the native call throws", () => { throw new Error("module gone"); }, null],
  ["an older native build without the call", undefined, null],
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
for (const [name, answer, expected] of MODULE_CASES) {
  try {
    const native = answer === undefined ? {} : null;
    if (native) STUBS["./src/CleanwayVpnModule"] = native;
    const got = native ? loadTs(join(root, "modules/cleanway-vpn/index.ts")).lastStopReason() : moduleStopReason(answer);
    deepStrictEqual(got, expected);
    console.log(`  ok    module: ${name}`);
  } catch (e) {
    failed += 1;
    console.log(`  FAIL  module: ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
  }
}
const total = CASES.length + MODULE_CASES.length;
if (failed > 0) {
  console.error(`\n${failed} of ${total} cases failed`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${total} cases pass`);
}
