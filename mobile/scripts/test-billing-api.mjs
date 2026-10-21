#!/usr/bin/env node
/**
 * Table test for src/lib/billing-api.ts — run with `node scripts/test-billing-api.mjs`.
 *
 * The phone's calls to /billing/v1 against a scripted fetch: the device
 * secret as a bearer, the idempotency key on the POSTs that take one, the
 * envelope read the one way the server writes it, and the three failures a
 * screen must tell apart — no network, a timeout, the server saying no with
 * its machine word. A phone number appears in a checkout body and nowhere
 * else: not in the URL, not in an error.
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

const STUBS = { "expo-constants": { __esModule: true, default: { expoConfig: { version: "1.0.3" } } } };

function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (spec in STUBS) return STUBS[spec];
    return spec.startsWith(".") ? loadTs(resolve(dirname(file), `${spec}.ts`)) : appRequire(spec);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const { createBillingApi } = loadTs(join(root, "src/lib/billing-api.ts"));

const ok = (data, status = 200) => ({ status, body: { success: true, data, error: null } });
const fail = (status, code, message = "") => ({ status, body: { success: false, data: null, error: { code, message } } });

/** A fetch that answers from a script and records what it was asked. */
function fakeFetch(script) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body === undefined ? undefined : JSON.parse(init.body) });
    const answer = typeof script === "function" ? script(url, init) : script;
    if (answer instanceof Error) throw answer;
    if (answer === "hang") return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
    return { ok: answer.status >= 200 && answer.status < 300, status: answer.status, json: async () => answer.body };
  };
  return { impl, calls };
}

const api = (script, extra = {}) => {
  const f = fakeFetch(script);
  return { client: createBillingApi({ baseUrl: "https://billing.test/", fetchImpl: f.impl, timeoutMs: 50, ...extra }), calls: f.calls };
};

const CASES = [
  ["register: no auth, the body as given, the base URL without its trailing slash", async () => {
    const { client, calls } = api(ok({ device_id: "d1", device_secret: "s3cret", legacy_free: true }, 201));
    const r = await client.registerDevice({ platform: "android", app_version: "1.0.3", legacy_claim: true });
    return { r, url: calls[0].url, method: calls[0].method, auth: calls[0].headers.Authorization, body: calls[0].body, client: calls[0].headers["X-Client"], version: calls[0].headers["X-Client-Version"] };
  }, {
    r: { data: { device_id: "d1", device_secret: "s3cret", legacy_free: true }, error: null },
    url: "https://billing.test/billing/v1/devices", method: "POST", auth: undefined,
    body: { platform: "android", app_version: "1.0.3", legacy_claim: true }, client: "mobile", version: "1.0.3",
  }],
  ["entitlement: GET with the device secret as a bearer, no body", async () => {
    const { client, calls } = api(ok({ token: "t", claims: {}, status: { mode: "full" } }));
    const r = await client.getEntitlement("s3cret");
    return { data: r.data.token, auth: calls[0].headers.Authorization, body: calls[0].body, ct: calls[0].headers["Content-Type"] };
  }, { data: "t", auth: "Bearer s3cret", body: undefined, ct: undefined }],
  ["checkout: idempotency key, the number only in the body", async () => {
    const { client, calls } = api(ok({ checkout_id: "c1", kind: "await_sms", url: null, sdk_params: null, status: "pending", provider: "fake" }, 201));
    const r = await client.startCheckout("s3cret", { plan_code: "solo", provider: "fake", msisdn: "+79150000000", consent_doc_version: "ru/v1", consent_method: "app_button" }, "idem-1");
    return { kind: r.data.kind, idem: calls[0].headers["Idempotency-Key"], msisdnInBody: calls[0].body.msisdn, urlHasNumber: calls[0].url.includes("7915") };
  }, { kind: "await_sms", idem: "idem-1", msisdnInBody: "+79150000000", urlHasNumber: false }],
  ["the server says no: its code and status, nothing of the request in the error", async () => {
    const { client } = api(fail(409, "already_subscribed", "this phone already has a subscription"));
    const r = await client.startCheckout("s3cret", { plan_code: "solo", provider: "fake", msisdn: "+79150000000", consent_doc_version: "ru/v1", consent_method: "app_button" }, "idem-2");
    return { ...r, leak: JSON.stringify(r).includes("7915") };
  }, { data: null, error: { kind: "api", status: 409, code: "already_subscribed", message: "this phone already has a subscription" }, leak: false }],
  ["no network", async () => (await api(new Error("Network request failed")).client.getPlans()).error, { kind: "network", status: 0, code: "network", message: "could not reach the billing server" }],
  ["a timeout is its own failure", async () => (await api("hang").client.getPlans()).error.kind, "timeout"],
  ["a non-JSON 502 and a 200 without the envelope both read as the server failing", async () => {
    const a = api({ status: 502, body: undefined });
    a.calls.length = 0;
    const r1 = await a.client.getPlans();
    const r2 = await api({ status: 200, body: { plans: [] } }).client.getPlans();
    const r3 = await api({ status: 200, body: { success: true, data: null, error: null } }).client.getPlans();
    return [r1.error.code, r1.error.kind, r2.error.code, r3.error.code];
  }, ["http_502", "api", "http_200", "http_200"]],
  ["a missing device secret never goes on the wire", async () => {
    const { client, calls } = api(ok({}));
    const r = await client.getEntitlement("");
    return { code: r.error.code, calls: calls.length };
  }, { code: "device_secret_missing", calls: 0 }],
  ["claim, codes, devices, seat removal: paths and verbs", async () => {
    const { client, calls } = api((url) => (url.endsWith("/codes") ? ok({ code: "123456" }, 201) : ok({ removed: "dev-2" })));
    await client.claimSeat("s", "123456");
    await client.createClaimCode("s", "idem-3");
    await client.listDevices("s");
    await client.removeSeat("s", "dev-2");
    await client.cancelSubscription("s");
    await client.getCheckout("s", "c/1");
    return calls.map((c) => `${c.method} ${c.url.replace("https://billing.test", "")}${c.headers["Idempotency-Key"] ? " ⟲" : ""}`);
  }, [
    "POST /billing/v1/claim", "POST /billing/v1/subscription/codes ⟲", "GET /billing/v1/subscription/devices",
    "DELETE /billing/v1/subscription/seats/dev-2", "POST /billing/v1/subscription/cancel", "GET /billing/v1/checkout/c%2F1",
  ]],
];

let failed = 0;
for (const [name, run, expected] of CASES) {
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
