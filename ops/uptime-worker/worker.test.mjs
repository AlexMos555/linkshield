// Tests for the uptime Worker, run in Node with fetch, KV, the email binding
// and R2 stubbed: `node --test ops/uptime-worker/worker.test.mjs` (also run by
// tests/test_uptime_worker.py, so CI's pytest job covers it).
import assert from "node:assert/strict";
import { register } from "node:module";
import { test } from "node:test";

// The Workers runtime's built-in module, stubbed for Node; and worker.js read
// as an ES module (no package.json says so, and Node 20 does not guess).
register(
  "data:text/javascript," +
    encodeURIComponent(`
      export async function resolve(specifier, context, next) {
        if (specifier === "cloudflare:email") {
          return { shortCircuit: true, url: "data:text/javascript," + encodeURIComponent(
            "export class EmailMessage { constructor(from, to, raw) { Object.assign(this, { from, to, raw }); } }") };
        }
        return next(specifier, context);
      }
      export async function load(url, context, next) {
        if (url.endsWith("/ops/uptime-worker/worker.js")) {
          return { ...(await next(url, { ...context, format: "module" })), format: "module", shortCircuit: true };
        }
        return next(url, context);
      }`),
);
const worker = (await import("./worker.js")).default;

const MIN = 60_000;
const T0 = Date.parse("2026-10-22T12:00:00Z");

// ── DNS answers ──

function name(n) {
  return n.split(".").flatMap((l) => [l.length, ...Buffer.from(l)]).concat(0);
}
function question(qname) {
  return [...name(qname), 0, 1, 0, 1];
}
function answerA(qname) {
  return Uint8Array.from([0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, ...question(qname),
    0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 142, 250, 74, 46]);
}
function nxdomain(qname, mname) {
  const rdata = [...name(mname), ...name("hostmaster.cleanway.ai"), ...new Array(20).fill(0)];
  return Uint8Array.from([0, 0, 0x85, 0x83, 0, 1, 0, 0, 0, 1, 0, 0, ...question(qname),
    ...name("cleanway.ai"), 0, 6, 0, 1, 0, 0, 0, 60, rdata.length >> 8, rdata.length & 0xff, ...rdata]);
}
// The live gateway's answer for the list canary, captured 2026-10-22.
const LIVE_BLOCK = Buffer.from(
  "0000858300010000000100000b6c6973742d63616e61727908636c65616e776179026169000001000108636c65616e77617902616900000600010000003c004107626c6f636b656408636c65616e776179026169000a686f73746d617374657208636c65616e776179026169000000000100000e1000000258000151800000003c",
  "hex",
);

const GOOGLE_Q = "AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ";
const CANARY_Q = "AAABAAABAAAAAAAAC2xpc3QtY2FuYXJ5CGNsZWFud2F5AmFpAAABAAE";

// ── world ──

function healthyDeep() {
  return {
    status: "ok",
    warnings: [],
    components: { redis: { ok: true }, supabase: { ok: true }, supabase_server_key: { ok: true } },
  };
}

// The live /health/doh shape (api/routers/doh.py, api/services/doh_metrics.py),
// trimmed: stats are one worker process's, cumulative since it started, and
// `recent` the same histogram over its last 150-180 s.
function healthyDoh() {
  return {
    ok: true,
    filter: { loaded: true, error: null, count: 628734 },
    stats: {
      since: 1792786992,
      counts: { queries: 500000, cache_hit: 300000 },
      p50_ms_le: 5.0,
      p95_ms_le: 50.0,
      p99_ms_le: 100.0,
      over_ms: { 5000: 0 },
      recent: { window_s: 180, queries: 3000, p50_ms_le: 5.0, p95_ms_le: 50.0, p99_ms_le: 100.0, over_ms: { 5000: 0 } },
    },
  };
}

function world() {
  const w = {
    pages: { "https://cleanway.ai/": 200, "https://cleanway.ai/ru/android": 200 },
    deep: { status: 200, body: healthyDeep() },
    doh: { status: 200, body: healthyDoh() }, // a string body is sent as is
    dns: { [GOOGLE_Q]: answerA("google.com"), [CANARY_Q]: LIVE_BLOCK },
    down: new Set(), // URLs whose fetch throws
    fetched: [],
    kv: new Map(),
    puts: 0,
    sent: [],
    sendFails: 0,
    backups: null, // [{ uploaded }] → binds BACKUPS
  };
  globalThis.fetch = async (url) => {
    w.fetched.push(url);
    if ([...w.down].some((d) => url.startsWith(d))) throw new TypeError("fetch failed");
    if (url === "https://api.cleanway.ai/health/deep") {
      return new Response(JSON.stringify(w.deep.body), { status: w.deep.status });
    }
    if (url === "https://dns.cleanway.ai/health/doh") {
      const b = w.doh.body;
      return new Response(typeof b === "string" ? b : JSON.stringify(b), { status: w.doh.status });
    }
    if (url.startsWith("https://dns.cleanway.ai/dns-query?dns=")) {
      const q = url.split("dns=")[1];
      return new Response(w.dns[q], { status: w.dns[q] ? 200 : 400 });
    }
    return new Response("", { status: w.pages[url] ?? 404 });
  };
  w.env = () => ({
    ALERT_TO: "founder@example.com",
    STATE: {
      get: async (k) => w.kv.get(k) ?? null,
      put: async (k, v) => {
        w.puts++;
        w.kv.set(k, v);
      },
    },
    ALERT: {
      send: async (msg) => {
        if (w.sendFails > 0) {
          w.sendFails--;
          throw new Error("destination address not verified");
        }
        w.sent.push(msg);
      },
    },
    ...(w.backups && {
      BACKUPS: { list: async () => ({ objects: w.backups, truncated: false }) },
    }),
  });
  w.tick = async (at) => {
    const waits = [];
    await worker.scheduled({ scheduledTime: at }, w.env(), { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
  };
  w.state = () => JSON.parse(w.kv.get("state") || "{}");
  w.subjects = () => w.sent.map((m) => decodeSubject(m.raw));
  return w;
}

function decodeSubject(raw) {
  const b64 = raw.match(/^Subject: =\?UTF-8\?B\?(.+)\?=$/m)[1];
  return Buffer.from(b64, "base64").toString("utf8");
}

async function minutes(w, from, n) {
  for (let i = 0; i < n; i++) await w.tick(from + i * MIN);
}

// ── tests ──

test("healthy: no mail, every check at zero, a heartbeat on the first run", async () => {
  const w = world();
  await w.tick(T0);
  assert.equal(w.sent.length, 0);
  const s = w.state();
  assert.deepEqual(Object.keys(s.fails).sort(), [
    "api", "blocklist", "dns_filter", "dns_latency", "doh_block", "doh_resolve", "install_page", "landing",
    "server_key", "warnings_other",
  ]);
  assert.ok(Object.values(s.fails).every((n) => n === 0));
  assert.equal(s.heartbeat_at, new Date(T0).toISOString());
});

test("one /health/deep request serves the api check and every warning check", async () => {
  const w = world();
  await w.tick(T0);
  assert.equal(w.fetched.filter((u) => u.endsWith("/health/deep")).length, 1);
});

test("the DNS queries are RFC 8484 GETs for google.com and the list canary", async () => {
  const w = world();
  await w.tick(T0);
  const qs = w.fetched.filter((u) => u.includes("dns=")).map((u) => u.split("dns=")[1]).sort();
  assert.deepEqual(qs, [GOOGLE_Q, CANARY_Q].sort());
});

test("an API outage mails once after two failures, then once when it is back", async () => {
  const w = world();
  w.deep = { status: 503, body: { status: "degraded", warnings: [], components: { redis: { ok: true }, supabase: { ok: false } } } };
  await minutes(w, T0, 4);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает api"]);
  assert.match(w.sent[0].raw, /api: HTTP 503, status=degraded, failing: supabase/);
  w.deep = { status: 200, body: healthyDeep() };
  await w.tick(T0 + 5 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает api", "Cleanway: снова работает api"]);
});

test("a single failed minute is not an alert", async () => {
  const w = world();
  w.pages["https://cleanway.ai/ru/android"] = 502;
  await w.tick(T0);
  w.pages["https://cleanway.ai/ru/android"] = 200;
  await w.tick(T0 + MIN);
  assert.equal(w.sent.length, 0);
});

test("a warning that stays red does not hide the next one", async () => {
  const w = world();
  w.deep.body.warnings = ["blocklist"];
  w.deep.body.components.blocklist = { ok: false, error: "stale" };
  await minutes(w, T0, 2);
  w.deep.body.warnings = ["blocklist", "supabase_server_key"];
  w.deep.body.components.supabase_server_key = { ok: false, status: 401 };
  await minutes(w, T0 + 2 * MIN, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает blocklist", "Cleanway: не работает server_key"]);
  assert.match(w.sent[1].raw, /server_key: supabase_server_key: HTTP 401/);
});

test("a warning the monitor does not know still alerts", async () => {
  const w = world();
  w.deep.body.warnings = ["email"];
  await minutes(w, T0, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает warnings_other"]);
});

test("an unreachable API alerts once, not once per warning check", async () => {
  const w = world();
  w.down.add("https://api.cleanway.ai/");
  await minutes(w, T0, 3);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает api"]);
});

test("an upstream NXDOMAIN for the canary is not our block", async () => {
  const w = world();
  w.dns[CANARY_Q] = nxdomain("list-canary.cleanway.ai", "ns1.upstream.example");
  await minutes(w, T0, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает doh_block"]);
  assert.match(w.sent[0].raw, /soa ns1\.upstream\.example \(not our block\)/);
});

test("our synthesised NXDOMAIN (uncompressed or compressed) passes", async () => {
  const w = world();
  w.dns[CANARY_Q] = nxdomain("list-canary.cleanway.ai", "blocked.cleanway.ai");
  await minutes(w, T0, 2);
  assert.equal(w.sent.length, 0);
});

test("a DNS gateway that resolves nothing alerts", async () => {
  const w = world();
  w.dns[GOOGLE_Q] = Uint8Array.from([0, 0, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0, ...question("google.com")]);
  await minutes(w, T0, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает doh_resolve"]);
  assert.match(w.sent[0].raw, /rcode 2, 0 answers/);
});

// ── DNS latency (docs/runbooks/capacity.md: p95_ms_le in /health/doh ≥ 200) ──

const DOH_HEALTH = "https://dns.cleanway.ai/health/doh";

// The last minutes of the worker that answered (stats.recent).
const recent = (w) => w.doh.body.stats.recent;

function slow(w, p95 = 500) {
  recent(w).p95_ms_le = p95;
  recent(w).p99_ms_le = 1000;
}

test("one /health/doh request per run, on the DNS name", async () => {
  const w = world();
  await w.tick(T0);
  assert.equal(w.fetched.filter((u) => u === DOH_HEALTH).length, 1);
});

test("DNS slow for five minutes in a row mails once, and once more when it is fast again", async () => {
  const w = world();
  slow(w);
  await minutes(w, T0, 4);
  assert.equal(w.sent.length, 0);
  await w.tick(T0 + 4 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency"]);
  assert.match(
    w.sent[0].raw,
    /dns_latency: p95 ≤ 500 ms \(alert at ≥ 200\), p99 ≤ 1000 ms, 3000 queries in the last 180 s on the worker that answered/,
  );
  assert.match(w.sent[0].raw, /docs\/runbooks\/capacity\.md/);
  recent(w).p95_ms_le = 50;
  await w.tick(T0 + 5 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency", "Cleanway: снова работает dns_latency"]);
});

test("the line is the capacity runbook's: p95_ms_le 100 never alerts, 200 does", async () => {
  const w = world();
  slow(w, 100);
  await minutes(w, T0, 8);
  assert.equal(w.sent.length, 0);
  slow(w, 200);
  await minutes(w, T0 + 8 * MIN, 5);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency"]);
});

test("one fast minute starts the count again", async () => {
  const w = world();
  slow(w);
  await minutes(w, T0, 4);
  recent(w).p95_ms_le = 20;
  await w.tick(T0 + 4 * MIN);
  slow(w);
  await minutes(w, T0 + 5 * MIN, 4);
  assert.equal(w.sent.length, 0);
});

test("p95 past the last histogram bucket (null with queries) is slow, not missing", async () => {
  const w = world();
  recent(w).p95_ms_le = null;
  recent(w).p99_ms_le = null;
  recent(w).over_ms = { 5000: 400 };
  await minutes(w, T0, 5);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency"]);
  assert.match(w.sent[0].raw, /dns_latency: p95 over 5000 ms/);
});

test("a worker with too few recent queries to judge keeps the count instead of resetting it", async () => {
  // Today's ~2 queries a minute per worker, mostly this monitor's own probes,
  // or a worker that just started: a p95 of a handful of lookups says nothing.
  // The floor is on the window, not on the lifetime count (500,000 here).
  const w = world();
  slow(w);
  await minutes(w, T0, 3);
  recent(w).queries = 20;
  await minutes(w, T0 + 3 * MIN, 3);
  assert.equal(w.sent.length, 0);
  assert.equal(w.state().fails.dns_latency, 3);
  recent(w).queries = 3000;
  await minutes(w, T0 + 6 * MIN, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency"]);
});

test("a long-lived worker that turns slow alerts on its last minutes, not on its lifetime", async () => {
  // 2026-10-24 review: judged since start, a day-old worker needed over an
  // hour of slow answers before its p95 moved.
  const w = world();
  slow(w);
  assert.equal(w.doh.body.stats.p95_ms_le, 50); // the lifetime p95 has not moved
  await minutes(w, T0, 5);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency"]);
});

test("a worker that is fast again recovers although its lifetime p95 stays high", async () => {
  // Judged since start, a two-hour slowdown kept a day-old worker's p95 over
  // the line for ~14 h: the "снова работает" mail waited for a deploy.
  const w = world();
  slow(w);
  w.doh.body.stats.p95_ms_le = 500;
  await minutes(w, T0, 5);
  recent(w).p95_ms_le = 50;
  recent(w).p99_ms_le = 100;
  await w.tick(T0 + 5 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает dns_latency", "Cleanway: снова работает dns_latency"]);
  assert.equal(w.state().fails.dns_latency, 0);
});

test("an API without stats.recent (a deploy older than the monitor) is not judged", async () => {
  const w = world();
  delete w.doh.body.stats.recent;
  w.doh.body.stats.p95_ms_le = 500;
  await minutes(w, T0, 6);
  assert.equal(w.sent.length, 0);
  assert.ok(!("dns_latency" in w.state().fails));
});

test("an unreadable /health/doh is not a latency alert: doh_resolve speaks for DNS being down", async () => {
  for (const broken of [
    { status: 404, body: '{"detail":"Not Found"}' },
    { status: 502, body: "<html>Application not found</html>" },
    "unreachable",
  ]) {
    const w = world();
    if (broken === "unreachable") w.down.add(DOH_HEALTH);
    else w.doh = broken;
    await minutes(w, T0, 6);
    assert.equal(w.sent.length, 0, JSON.stringify(broken));
    assert.ok(!("dns_latency" in w.state().fails));
  }
});

test("a long slow spell does not write KV every minute", async () => {
  const w = world();
  slow(w);
  await minutes(w, T0, 5);
  const after = w.puts;
  await minutes(w, T0 + 5 * MIN, 4);
  assert.equal(w.puts, after);
  assert.equal(w.state().fails.dns_latency, 5);
});

test("a failed send is recorded and retried the next minute", async () => {
  const w = world();
  w.pages["https://cleanway.ai/"] = 500;
  w.sendFails = 1;
  await minutes(w, T0, 2);
  assert.equal(w.sent.length, 0);
  assert.equal(w.state().alert_error.error, "destination address not verified");
  assert.deepEqual(w.state().down, []);
  await w.tick(T0 + 2 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает landing"]);
  assert.deepEqual(w.state().down, ["landing"]);
  assert.equal(w.state().alert_error, null);
});

test("a failed send is forgotten once nothing is owed: the check recovered before the retry", async () => {
  // The founder was never told it was down, so no recovery mail is owed
  // either; a stale alert_error would keep the DNS canary red until the next
  // real outage (scripts/dns_canary.py fails on any alert_error).
  const w = world();
  w.pages["https://cleanway.ai/"] = 500;
  w.sendFails = 1;
  await minutes(w, T0, 2);
  assert.equal(w.state().alert_error.error, "destination address not verified");
  w.pages["https://cleanway.ai/"] = 200;
  await w.tick(T0 + 2 * MIN);
  assert.equal(w.sent.length, 0);
  assert.deepEqual(w.state().down, []);
  assert.equal(w.state().alert_error, null);
});

test("a failed recovery mail stays recorded until it goes out", async () => {
  const w = world();
  w.pages["https://cleanway.ai/"] = 500;
  await minutes(w, T0, 2);
  w.pages["https://cleanway.ai/"] = 200;
  w.sendFails = 1;
  await w.tick(T0 + 2 * MIN);
  assert.deepEqual(w.state().down, ["landing"]);
  assert.ok(w.state().alert_error);
  await w.tick(T0 + 3 * MIN);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает landing", "Cleanway: снова работает landing"]);
  assert.equal(w.state().alert_error, null);
});

test("a long outage does not write KV every minute", async () => {
  const w = world();
  w.pages["https://cleanway.ai/"] = 500;
  await minutes(w, T0, 3);
  const after = w.puts;
  await minutes(w, T0 + 3 * MIN, 5);
  assert.equal(w.puts, after);
  assert.equal(w.state().fails.landing, 2);
});

test("an unchanged state is still written as a heartbeat every 10 minutes", async () => {
  const w = world();
  await minutes(w, T0, 10);
  assert.equal(w.puts, 1);
  await w.tick(T0 + 10 * MIN);
  assert.equal(w.puts, 2);
  assert.equal(w.state().heartbeat_at, new Date(T0 + 10 * MIN).toISOString());
});

test("without an R2 binding there is no backup check", async () => {
  const w = world();
  await w.tick(T0);
  assert.ok(!("backup" in w.state().fails));
});

test("a backup older than 30 hours alerts; a fresh one does not", async () => {
  const w = world();
  w.backups = [{ uploaded: new Date(T0 - 31 * 3_600_000) }, { uploaded: new Date(T0 - 55 * 3_600_000) }];
  await minutes(w, T0, 2);
  assert.deepEqual(w.subjects(), ["Cleanway: не работает backup"]);
  assert.match(w.sent[0].raw, /newest backup is 31\.0 h old/);
  w.backups.push({ uploaded: new Date(T0 - 3_600_000) });
  await w.tick(T0 + 2 * MIN);
  assert.equal(w.subjects()[1], "Cleanway: снова работает backup");
});

test("an empty backup bucket alerts", async () => {
  const w = world();
  w.backups = [];
  await minutes(w, T0, 2);
  assert.match(w.sent[0].raw, /no object under db\/ in R2/);
});

test("GET / shows the state without caching", async () => {
  const w = world();
  await w.tick(T0);
  const r = await worker.fetch(new Request("https://cleanway-uptime.example/"), w.env());
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.equal((await r.json()).heartbeat_at, new Date(T0).toISOString());
});

test("an old state (before heartbeats) is read without errors", async () => {
  const w = world();
  w.kv.set("state", JSON.stringify({ fails: { landing: 0, api: 3, doh: 0 }, down: ["api"], at: "2026-10-18T18:32:22Z" }));
  await w.tick(T0);
  // The old 'doh' check is gone; 'api' is healthy now → its recovery mail.
  assert.deepEqual(w.subjects(), ["Cleanway: снова работает api"]);
  assert.ok(!("doh" in w.state().fails));
});
