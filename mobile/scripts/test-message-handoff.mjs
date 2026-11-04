#!/usr/bin/env node
/**
 * Regression test for report #5 — run with `node scripts/test-message-handoff.mjs`.
 *
 * The bug, reproduced twice on 2026-09-25: check one SMS, leave the message
 * screen open, share a NEW scam message to Cleanway — and read "no signs of
 * fraud" about the OLD one; the new message never reached History.
 *
 * Why: the share router sends "/message" again, and Expo Router 4–6 (with
 * the Stack.Screen options this app sets) did not mount a second screen — it
 * gave the open one new params. The params were `{from: "share"}` both
 * times, the screen took its text once on mount, and never looked again.
 * Since Expo SDK 58 router.push always stacks a new screen; the share router
 * calls router.navigate, which still hands the open screen the new params.
 *
 * Pinned here, in two layers:
 *  1. the navigation fact itself, with expo-router's own stack router and
 *     the actions it dispatches for router.navigate and router.push — so if a
 *     future router does something else, this test says so;
 *  2. src/services/message-handoff.ts: each share gets its own id, and the
 *     open screen's takeForScreen() hands over the NEW text exactly once.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/services/message-handoff.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-handoff-"));

/**
 * Two shares while /message is on top, dispatched the way expo-router 58
 * dispatches them: router.navigate is a NAVIGATE and router.push a PUSH
 * (getNavigateAction in expo-router/build/global-state), to a
 * <Stack.Screen name="message"/> without dangerouslySingular, i.e. no getId.
 */
function secondShare(type, { StackRouter, createInitialState }) {
  const router = StackRouter({});
  const config = { routeNames: ["(tabs)", "message"], routeGetIdList: { message: undefined } };
  let state = createInitialState({ routeNames: config.routeNames, initialRouteName: "(tabs)", parentChain: "root" });
  const share = (params) => ({ type, target: state.key, payload: { singular: undefined, name: "message", params } });
  state = router.getStateForAction(state, share({ from: "share", handoff: "a" }), config).state;
  const first = state.routes.at(-1).key;
  state = router.getStateForAction(state, share({ from: "share", handoff: "b" }), config).state;
  const top = state.routes.at(-1);
  return { sameScreen: top.key === first, handoff: top.params.handoff, depth: state.routes.length };
}

/** The share router's calls to /message, from app/_layout.tsx (ShareIntentRouter). */
function shareRouterCalls() {
  const layout = readFileSync(join(root, "app/_layout.tsx"), "utf8");
  const body = layout.slice(layout.indexOf("function ShareIntentRouter()"));
  const calls = [...body.slice(0, body.indexOf("\n}\n")).matchAll(/router\.(\w+)\(\{ pathname: "\/message"/g)];
  return calls.map((m) => m[1]);
}

try {
  execFileSync(
    "npx",
    [
      "tsc", src, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const m = await import(pathToFileURL(join(out, "src/services/message-handoff.js")).href);
  const appRequire = createRequire(join(root, "package.json"));
  const nav = {
    StackRouter: appRequire("expo-router/build/react-navigation/routers/index.js").StackRouter,
    createInitialState: appRequire("expo-router/build/react-navigation/core/createInitialState.js").createInitialState,
  };

  // An open message screen: its ref, and what it checked, in order.
  const screen = () => {
    const handled = { current: null };
    const checked = [];
    return {
      render(params, now) {
        const text = m.takeForScreen(params, handled, now);
        if (text) checked.push(text);
      },
      checked,
    };
  };

  const CASES = [
    [
      "router.navigate (what the share router calls) gives the OPEN screen the second share's params — no new screen",
      () => secondShare("NAVIGATE", nav),
      { sameScreen: true, handoff: "b", depth: 2 },
    ],
    [
      "router.push would stack a second message screen since Expo SDK 58 — why the share router navigates",
      () => secondShare("PUSH", nav),
      { sameScreen: false, handoff: "b", depth: 3 },
    ],
    [
      "the share router reaches /message with router.navigate only",
      () => shareRouterCalls(),
      ["navigate"],
    ],
    [
      "a second share to the open screen is checked — the new text, once",
      () => {
        const s = screen();
        const first = m.handOffMessage("Ваш код 1234, никому не сообщайте", 1_000);
        s.render({ from: "share", handoff: first }, 1_010);
        s.render({ from: "share", handoff: first }, 1_020); // a re-render: nothing new
        const second = m.handOffMessage("Мама, у меня новый номер, срочно переведи 15000", 60_000);
        s.render({ from: "share", handoff: second }, 60_010);
        s.render({ from: "share", handoff: second }, 60_020);
        return s.checked;
      },
      ["Ваш код 1234, никому не сообщайте", "Мама, у меня новый номер, срочно переведи 15000"],
    ],
    [
      "every share gets its own id",
      () => {
        const a = m.handOffMessage("one", 5);
        const b = m.handOffMessage("two", 5);
        return a !== b;
      },
      true,
    ],
    [
      "a stale id never takes a newer message — it waits for its own screen",
      () => {
        const old = m.handOffMessage("old", 0);
        const fresh = m.handOffMessage("new", 10);
        return [m.takeHandedOffMessage(old, 20), m.takeHandedOffMessage(fresh, 20)];
      },
      [null, "new"],
    ],
    [
      "taken once, then gone",
      () => {
        const id = m.handOffMessage("once", 0);
        return [m.takeHandedOffMessage(id, 1), m.takeHandedOffMessage(id, 2)];
      },
      ["once", null],
    ],
    [
      "a handoff nobody took within 30 s is dropped, never checked later",
      () => {
        const id = m.handOffMessage("late", 0);
        return m.takeHandedOffMessage(id, 30_001);
      },
      null,
    ],
    [
      "a screen opened by hand (no share) takes nothing",
      () => {
        m.handOffMessage("someone else's", 0);
        const s = screen();
        s.render({}, 1);
        s.render({ from: "home" }, 2);
        return s.checked;
      },
      [],
    ],
  ];

  let failed = 0;
  for (const [name, run, expected] of CASES) {
    try {
      deepStrictEqual(run(), expected);
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
} finally {
  rmSync(out, { recursive: true, force: true });
}
