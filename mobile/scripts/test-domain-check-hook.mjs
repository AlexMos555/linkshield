#!/usr/bin/env node
/**
 * Regression test for src/hooks/useDomainCheck.ts — run with
 * `node scripts/test-domain-check-hook.mjs`.
 *
 * The hook behind the link-check screens (app/shared.tsx, app/result.tsx)
 * runs under real React 18 here, with the list, the server, History and the
 * haptics stubbed. Two bugs found in review are pinned:
 *
 *  1. A second link shared to the OPEN /shared screen. Expo Router reuses the
 *     screen and changes only its params (pinned below with the real
 *     @react-navigation StackRouter, as in test-message-handoff.mjs), so the
 *     hook sees a new domain while it stays mounted. The old version saved
 *     the previous site's verdict under the new name — sberbank.ru went into
 *     History as «Опасно — сайт из списка мошеннических» after a listed scam,
 *     a scam after sberbank.ru was never recorded and buzzed "success", and
 *     the first frame showed the old site's card under the new name.
 *  2. A listed site shows «Опасно» at once, so people close the screen before
 *     the server answers (up to ~24 s). The old version saved History only
 *     after the server answered, while the screen was open — the scam never
 *     reached History, where family members look.
 *
 * No test runner in mobile/: the hook and check-verdict.ts are transpiled
 * with the tree's TypeScript and loaded with a small require that hands the
 * hook its stubs; react / react-dom come from mobile/node_modules.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

// ── the world the hook talks to ─────────────────────────────────────

const LIST = new Map([["scam-pochta.ru", "scam-pochta.ru"], ["gosuslugee.ru", "gosuslugee.ru"]]);
let rows = [];
let haptics = [];
let pendingChecks = [];

function resetWorld() {
  rows = [];
  haptics = [];
  pendingChecks = [];
}

const STUBS = {
  "../services/api": {
    checkDomain: (domain) => new Promise((settle) => pendingChecks.push({ domain, settle })),
  },
  "../services/database": {
    saveCheck: async (row) => {
      rows = [...rows, { id: rows.length + 1, ...row }];
      return rows.length;
    },
    updateCheck: async (id, row) => {
      rows = rows.map((r) => (r.id === id ? { id, ...row } : r));
    },
  },
  "../../modules/cleanway-vpn": {
    matchBlocklist: async (domain) => LIST.get(domain) ?? null,
  },
  "expo-haptics": {
    notificationAsync: async (kind) => {
      haptics = [...haptics, kind];
    },
    NotificationFeedbackType: { Error: "error", Warning: "warning", Success: "success" },
  },
};

/** CommonJS-load a .ts file of the app, its relative imports from source, the stubs above in their place. */
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

const { useDomainCheck } = loadTs(join(root, "src/hooks/useDomainCheck.ts"));

/** Let promises and effects run. */
const settle = () => act(async () => {
  await new Promise((r) => setTimeout(r, 5));
});

/** The server answers the oldest open check of [domain]. */
async function server(domain, answer) {
  const i = pendingChecks.findIndex((c) => c.domain === domain);
  if (i < 0) throw new Error(`no open check for ${domain}`);
  const [check] = pendingChecks.splice(i, 1);
  await act(async () => {
    check.settle(typeof answer === "string" ? { data: null, error: { kind: answer } } : { data: answer, error: null });
  });
  await settle();
}

const verdict = (domain, level, score, codes = []) => ({
  domain, level, score, confidence: "high",
  reasons: codes.map((code) => ({ code, detail: code })),
});

/** A mounted link-check screen; share() hands the SAME screen a new site, as the router does. */
async function openScreen(domain, record = true) {
  const frames = [];
  let retry = noop;
  function Screen(props) {
    const c = useDomainCheck(props.domain, props.record);
    retry = c.retry;
    frames.push({ domain: props.domain, listed: c.listed, pending: c.pending, result: c.result?.domain ?? null });
    return null;
  }
  const rootNode = createRoot(container());
  await act(async () => rootNode.render(React.createElement(Screen, { domain, record })));
  await settle();
  return {
    frames,
    retry: async () => {
      await act(async () => retry());
      await settle();
    },
    share: async (next) => {
      const firstFrame = frames.length;
      await act(async () => rootNode.render(React.createElement(Screen, { domain: next, record })));
      await settle();
      return frames[firstFrame];
    },
    close: async () => act(async () => rootNode.unmount()),
  };
}

/** History as [domain, level, score, source]. */
const history = () => rows.map((r) => [r.domain, r.level, r.score, r.source ?? "server"]);

/**
 * Two pushes of /shared while it is on top, dispatched the way expo-router 4
 * dispatches router.push (a NAVIGATE with a fresh __EXPO_ROUTER_key), to a
 * <Stack.Screen name="shared" options={…}/> whose props leave getId undefined.
 */
function secondShareReusesTheScreen(StackRouter) {
  const router = StackRouter({});
  const options = { routeNames: ["(tabs)", "shared"], routeParamList: {}, routeGetIdList: { shared: undefined } };
  let state = router.getInitialState(options);
  const push = (url) => ({
    type: "NAVIGATE",
    target: state.key,
    payload: { name: "shared", params: { url, __EXPO_ROUTER_key: `k-${Math.random()}` } },
  });
  state = router.getStateForAction(state, push("https://scam-pochta.ru/track"), options);
  const first = state.routes.at(-1).key;
  state = router.getStateForAction(state, push("https://sberbank.ru/"), options);
  const top = state.routes.at(-1);
  return { sameScreen: top.key === first, url: top.params.url, depth: state.routes.length };
}

const { StackRouter } = await import(pathToFileURL(appRequire.resolve("@react-navigation/routers")).href);

const CASES = [
  [
    "the router gives the OPEN /shared screen the second link — no new screen",
    async () => secondShareReusesTheScreen(StackRouter),
    { sameScreen: true, url: "https://sberbank.ru/", depth: 2 },
  ],
  [
    "listed scam, then sberbank.ru to the same screen: each saved under its own name, with its own buzz",
    async () => {
      const s = await openScreen("scam-pochta.ru");
      await server("scam-pochta.ru", verdict("scam-pochta.ru", "dangerous", 95, ["phishtank"]));
      const firstFrame = await s.share("sberbank.ru");
      await server("sberbank.ru", verdict("sberbank.ru", "safe", 0, ["known_legitimate"]));
      return { firstFrame, history: history(), haptics };
    },
    {
      // The new site starts as "checking" — never the old verdict under its name.
      firstFrame: { domain: "sberbank.ru", listed: undefined, pending: true, result: null },
      history: [["scam-pochta.ru", "dangerous", 95, "list"], ["sberbank.ru", "safe", 0, "server"]],
      haptics: ["error", "success"],
    },
  ],
  [
    "sberbank.ru, then a listed scam to the same screen: the scam is recorded and buzzes as danger",
    async () => {
      const s = await openScreen("sberbank.ru");
      await server("sberbank.ru", verdict("sberbank.ru", "safe", 0));
      const firstFrame = await s.share("scam-pochta.ru");
      const beforeServer = history();
      await server("scam-pochta.ru", verdict("scam-pochta.ru", "dangerous", 95, ["phishtank"]));
      return { firstFrame, beforeServer, history: history(), haptics };
    },
    {
      firstFrame: { domain: "scam-pochta.ru", listed: undefined, pending: true, result: null },
      beforeServer: [["sberbank.ru", "safe", 0, "server"], ["scam-pochta.ru", "dangerous", 0, "list"]],
      history: [["sberbank.ru", "safe", 0, "server"], ["scam-pochta.ru", "dangerous", 95, "list"]],
      haptics: ["success", "error"],
    },
  ],
  [
    "a listed site is in History as soon as the list answers — closing before the server keeps it",
    async () => {
      const s = await openScreen("gosuslugee.ru");
      const onScreen = s.frames.at(-1);
      await s.close();
      const afterClose = history();
      // The server answers after the screen is gone: the row gets its details.
      await server("gosuslugee.ru", verdict("gosuslugee.ru", "caution", 25, ["unnatural_ngram"]));
      return { onScreen, afterClose, history: history(), reasons: rows[0].reasons.map((r) => r.code) };
    },
    {
      onScreen: { domain: "gosuslugee.ru", listed: "gosuslugee.ru", pending: true, result: null },
      afterClose: [["gosuslugee.ru", "dangerous", 0, "list"]],
      // A calmer server answer never downgrades the list's row.
      history: [["gosuslugee.ru", "dangerous", 0, "list"]],
      reasons: ["on_device_list", "unnatural_ngram"],
    },
  ],
  [
    "a late answer for the previous site is filed under that site, never shown on the new one",
    async () => {
      const s = await openScreen("a-shop.ru");
      await s.share("b-shop.ru");
      await server("a-shop.ru", verdict("a-shop.ru", "caution", 40, ["no_mx_record"]));
      const onScreen = s.frames.at(-1);
      const afterA = history();
      await server("b-shop.ru", verdict("b-shop.ru", "safe", 5));
      return { onScreen, afterA, history: history() };
    },
    {
      onScreen: { domain: "b-shop.ru", listed: null, pending: true, result: null },
      afterA: [["a-shop.ru", "caution", 40, "server"]],
      history: [["a-shop.ru", "caution", 40, "server"], ["b-shop.ru", "safe", 5, "server"]],
    },
  ],
  [
    "a failed server check of a listed site keeps the list's row; a retry fills it in, still one row",
    async () => {
      const s = await openScreen("scam-pochta.ru");
      await server("scam-pochta.ru", "timeout");
      const afterFailure = history();
      await s.retry();
      await server("scam-pochta.ru", verdict("scam-pochta.ru", "dangerous", 90, ["surbl"]));
      return { afterFailure, history: history() };
    },
    {
      afterFailure: [["scam-pochta.ru", "dangerous", 0, "list"]],
      history: [["scam-pochta.ru", "dangerous", 90, "list"]],
    },
  ],
  [
    "not recording (a link-guard hand-off): nothing is saved, the verdict still shows",
    async () => {
      const s = await openScreen("scam-pochta.ru", false);
      await server("scam-pochta.ru", verdict("scam-pochta.ru", "dangerous", 95));
      return { history: history(), last: s.frames.at(-1) };
    },
    {
      history: [],
      last: { domain: "scam-pochta.ru", listed: "scam-pochta.ru", pending: false, result: "scam-pochta.ru" },
    },
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
