// Tests for the mail-security Worker (MTA-STS policy + TLS-RPT intake), run
// in Node with KV, the email binding and the incoming message stubbed:
// `node --test ops/mail-security-worker/worker.test.mjs` (also run by
// tests/test_mail_security_worker.py, so CI's pytest job covers it).
import assert from "node:assert/strict";
import { register } from "node:module";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

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
        if (url.endsWith("/ops/mail-security-worker/worker.js")) {
          return { ...(await next(url, { ...context, format: "module" })), format: "module", shortCircuit: true };
        }
        return next(url, context);
      }`),
);
const worker = (await import("./worker.js")).default;

const DAY = 86_400_000;
const T0 = Date.parse("2026-10-23T09:00:00Z");
const POLICY_URL = "https://mta-sts.cleanway.ai/.well-known/mta-sts.txt";
const DASH_URL = "https://cleanway-mail-security.amoskotin.workers.dev/";

// ── a TLS report as Google mails it (RFC 8460 §5.3) ──

function report({ org = "Google Inc.", id = "2026-10-22T00:00:00Z_cleanway.ai", ok = 1200, failed = 0, details } = {}) {
  return {
    "organization-name": org,
    "date-range": { "start-datetime": "2026-10-22T00:00:00Z", "end-datetime": "2026-10-22T23:59:59Z" },
    "contact-info": "smtp-tls-reporting@google.com",
    "report-id": id,
    policies: [
      {
        policy: {
          "policy-type": "sts",
          "policy-string": ["version: STSv1", "mode: testing", "mx: route1.mx.cloudflare.net", "max_age: 86400"],
          "policy-domain": "cleanway.ai",
          "mx-host": ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net"],
        },
        summary: { "total-successful-session-count": ok, "total-failure-session-count": failed },
        ...(details && { "failure-details": details }),
      },
    ],
  };
}

const MISMATCH = {
  "result-type": "certificate-host-mismatch",
  "sending-mta-ip": "209.85.220.41",
  "receiving-mx-hostname": "route2.mx.cloudflare.net",
  "receiving-ip": "104.30.0.1",
  "failed-session-count": 3,
  "failure-reason-code": "X509_V_ERR_HOSTNAME_MISMATCH",
};

const BOUNDARY = "000000000000c7c1a40615c0e1f2";

function mail(attachment, { type = "application/tlsrpt+gzip", encoding = "base64", eol = "\r\n", boundary = BOUNDARY } = {}) {
  const body = encoding === "base64" ? Buffer.from(attachment).toString("base64").replace(/.{76}/g, "$&\n") : String(attachment);
  const file = "google.com!cleanway.ai!1792627200!1792713599!001.json.gz";
  return [
    "Received: from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69])",
    "From: noreply-smtp-tls-reporting@google.com",
    "To: tls-reports@cleanway.ai",
    "Subject: Report Domain: cleanway.ai Submitter: google.com",
    " Report-ID: <2026.10.22T00.00.00Z+cleanway.ai@google.com>",
    "TLS-Report-Domain: cleanway.ai",
    "TLS-Report-Submitter: google.com",
    "MIME-Version: 1.0",
    `Content-Type: multipart/report; boundary="${boundary}";`,
    "\treport-type=tlsrpt",
    "",
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes',
    "",
    "This is an aggregate TLS report from google.com",
    "",
    `--${boundary}`,
    `Content-Type: ${type}; name="${file}"`,
    `Content-Disposition: attachment; filename="${file}"`,
    ...(encoding ? [`Content-Transfer-Encoding: ${encoding}`] : []),
    "",
    ...body.split("\n"),
    `--${boundary}--`,
    "",
  ].join(eol);
}

const gz = (r) => gzipSync(Buffer.from(JSON.stringify(r)));

// ── world ──

function world() {
  const w = { kv: new Map(), puts: [], sent: [], sendFails: 0, now: T0, rejected: [], forwarded: [] };
  Date.now = () => w.now;
  w.env = (extra = {}) => ({
    ALERT_TO: "founder@example.com",
    STATE: {
      get: async (k) => w.kv.get(k) ?? null,
      put: async (k, v, opts) => {
        w.puts.push({ k, opts });
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
    ...extra,
  });
  w.receive = async (raw, env = w.env()) => {
    const bytes = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
    const message = {
      from: "noreply-smtp-tls-reporting@google.com",
      to: "tls-reports@cleanway.ai",
      headers: new Headers(),
      raw: new Response(bytes).body,
      rawSize: bytes.length,
      setReject: (r) => w.rejected.push(r),
      forward: async (to) => w.forwarded.push(to),
      reply: async () => w.forwarded.push("reply"),
    };
    w.message = message;
    await worker.email(message, env, { waitUntil() {} });
  };
  w.day = (d = "2026-10-23") => JSON.parse(w.kv.get(`day:${d}`) || "null");
  w.subjects = () => w.sent.map((m) => decodeSubject(m.raw));
  return w;
}

function decodeSubject(raw) {
  const b64 = raw.match(/^Subject: =\?UTF-8\?B\?(.+)\?=$/m)[1];
  return Buffer.from(b64, "base64").toString("utf8");
}

const get = (url, env, method = "GET") => worker.fetch(new Request(url, { method }), env);

// ── the MTA-STS policy ──

test("the policy is exactly RFC 8461 text, CRLF lines, mode testing by default", async () => {
  const w = world();
  const r = await get(POLICY_URL, w.env());
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.equal(
    await r.text(),
    "version: STSv1\r\nmode: testing\r\nmx: route1.mx.cloudflare.net\r\nmx: route2.mx.cloudflare.net\r\n" +
      "mx: route3.mx.cloudflare.net\r\nmax_age: 86400\r\n",
  );
});

test("the policy parses under RFC 8461's grammar: one field per line, version first", async () => {
  const w = world();
  const body = await (await get(POLICY_URL, w.env())).text();
  assert.ok(body.length < 64 * 1024);
  const lines = body.split("\r\n");
  assert.equal(lines.pop(), ""); // the last field ends in CRLF too
  assert.equal(lines[0], "version: STSv1");
  for (const l of lines) assert.match(l, /^(version|mode|mx|max_age): [\x21-\x7e]+$/);
  assert.ok(!/\n(?<!\r\n)/.test(body.replace(/\r\n/g, "")), "no bare LF");
  const fields = lines.map((l) => l.split(": ")[0]);
  for (const once of ["version", "mode", "max_age"]) assert.equal(fields.filter((f) => f === once).length, 1);
});

test("MTA_STS_MODE=enforce switches the mode and a week of max_age", async () => {
  const w = world();
  const body = await (await get(POLICY_URL, w.env({ MTA_STS_MODE: " Enforce " }))).text();
  assert.match(body, /^mode: enforce\r$/m);
  assert.match(body, /^max_age: 604800\r$/m);
});

test("an unknown MTA_STS_MODE falls back to testing; none is allowed for a rollback", async () => {
  const w = world();
  for (const bad of ["", "enforced", "constructor", "__proto__"]) {
    const body = await (await get(POLICY_URL, w.env({ MTA_STS_MODE: bad }))).text();
    assert.match(body, /^mode: testing\r$/m, bad);
  }
  const none = await (await get(POLICY_URL, w.env({ MTA_STS_MODE: "none" }))).text();
  assert.match(none, /^mode: none\r$/m);
  assert.match(none, /^max_age: 86400\r$/m);
});

test("HEAD on the policy answers 200 with no body", async () => {
  const w = world();
  const r = await get(POLICY_URL, w.env(), "HEAD");
  assert.equal(r.status, 200);
  assert.equal(await r.text(), "");
});

test("everything else is a 404", async () => {
  const w = world();
  const env = w.env();
  for (const [url, method] of [
    ["https://mta-sts.cleanway.ai/", "GET"],
    ["https://mta-sts.cleanway.ai/.well-known/mta-sts.txt/", "GET"],
    ["https://mta-sts.cleanway.ai/.well-known/security.txt", "GET"],
    ["https://mta-sts.cleanway.ai/.well-known/mta-sts.json", "GET"],
    [POLICY_URL, "POST"],
    [POLICY_URL, "PUT"],
    ["https://cleanway-mail-security.amoskotin.workers.dev/.well-known/mta-sts.txt", "GET"],
    ["https://cleanway-mail-security.amoskotin.workers.dev/favicon.ico", "GET"],
    [DASH_URL, "POST"],
    ["https://cleanway.ai/", "GET"],
    ["https://cleanway.ai/.well-known/mta-sts.txt", "GET"],
  ]) {
    const r = await get(url, env, method);
    assert.equal(r.status, 404, `${method} ${url}`);
    assert.equal(r.headers.get("cache-control"), "no-store");
  }
});

// ── TLS reports ──

test("a gzip report from Google is counted per policy, kept 90 days, and no mail when nothing failed", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1200, failed: 0 }))));
  const s = w.day();
  assert.equal(s.reports, 1);
  assert.equal(s.successful, 1200);
  assert.equal(s.failed, 0);
  assert.deepEqual(s.policies, { "sts cleanway.ai": { successful: 1200, failed: 0 } });
  assert.deepEqual(s.reporters, { "Google Inc.": 1 });
  assert.deepEqual(s.covers, ["2026-10-22"]);
  assert.equal(s.errors, 0);
  assert.equal(w.sent.length, 0);
  assert.deepEqual(w.puts.map((p) => [p.k, p.opts]), [["day:2026-10-23", { expirationTtl: 90 * 86_400 }]]);
  assert.deepEqual([w.rejected, w.forwarded], [[], []]);
});

test("reports of one day add up across reporters and policies", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1200 }))));
  const ms = report({ org: "Microsoft Corporation", id: "133797", ok: 40, failed: 0 });
  ms.policies.push({
    policy: { "policy-type": "no-policy-found", "policy-domain": "cleanway.ai" },
    summary: { "total-successful-session-count": 7, "total-failure-session-count": 0 },
  });
  await w.receive(mail(gz(ms)));
  const s = w.day();
  assert.equal(s.reports, 2);
  assert.equal(s.successful, 1247);
  assert.deepEqual(s.policies, {
    "sts cleanway.ai": { successful: 1240, failed: 0 },
    "no-policy-found cleanway.ai": { successful: 7, failed: 0 },
  });
  assert.deepEqual(s.reporters, { "Google Inc.": 1, "Microsoft Corporation": 1 });
});

test("a report with failed sessions mails the founder once, without the raw report", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1197, failed: 3, details: [MISMATCH] }))));
  const s = w.day();
  assert.equal(s.failed, 3);
  assert.deepEqual(s.failures, { "certificate-host-mismatch route2.mx.cloudflare.net": 3 });
  assert.equal(s.alerted_at, new Date(T0).toISOString());
  assert.equal(w.sent.length, 1);
  const m = w.sent[0];
  assert.equal(m.from, "alerts@cleanway.ai");
  assert.equal(m.to, "founder@example.com");
  assert.match(m.raw, /^From: Cleanway monitor <alerts@cleanway\.ai>\r$/m);
  assert.match(m.raw, /^To: founder@example\.com\r$/m);
  assert.deepEqual(w.subjects(), ["Cleanway: сбои TLS при доставке почты на cleanway.ai (3)"]);
  assert.match(m.raw, /Google Inc\./);
  assert.match(m.raw, /sts cleanway\.ai: .*1197.*3/);
  assert.match(m.raw, /certificate-host-mismatch, route2\.mx\.cloudflare\.net: 3/);
  assert.match(m.raw, /X509_V_ERR_HOSTNAME_MISMATCH/);
  assert.match(m.raw, /testing/);
  // Never the report itself: no sender IPs, no contact address, no attachment.
  for (const leak of ["209.85.220.41", "104.30.0.1", "smtp-tls-reporting@google.com", "policy-string", "H4sI"]) {
    assert.ok(!m.raw.includes(leak), leak);
  }
  assert.deepEqual(w.forwarded, []);
});

test("one alert a day: a second failing report the same day only adds to the summary", async () => {
  const w = world();
  await w.receive(mail(gz(report({ failed: 3, details: [MISMATCH] }))));
  await w.receive(mail(gz(report({ org: "Microsoft Corporation", id: "m-1", failed: 5 }))));
  assert.equal(w.sent.length, 1);
  assert.equal(w.day().failed, 8);
  w.now = T0 + DAY;
  await w.receive(mail(gz(report({ id: "next-day", failed: 1 }))));
  assert.equal(w.sent.length, 2);
  assert.equal(w.day("2026-10-24").failed, 1);
});

test("in enforce mode the alert says mail is not being delivered", async () => {
  const w = world();
  await w.receive(mail(gz(report({ failed: 2 }))), w.env({ MTA_STS_MODE: "enforce" }));
  assert.match(w.sent[0].raw, /enforce/);
  assert.match(w.sent[0].raw, /НЕ доставляют/);
});

test("a failed alert is recorded and retried with the next failing report", async () => {
  const w = world();
  w.sendFails = 1;
  await w.receive(mail(gz(report({ failed: 2 }))));
  assert.equal(w.sent.length, 0);
  assert.equal(w.day().alerted_at, null);
  assert.equal(w.day().alert_error.error, "destination address not verified");
  await w.receive(mail(gz(report({ id: "second", ok: 10 }))));
  assert.equal(w.sent.length, 0, "a clean report owes no alert");
  await w.receive(mail(gz(report({ id: "third", failed: 1 }))));
  assert.equal(w.sent.length, 1);
  assert.equal(w.day().alert_error, null);
  assert.ok(w.day().alerted_at);
});

test("the same report delivered twice is counted once", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 100 }))));
  await w.receive(mail(gz(report({ ok: 100 }))));
  assert.equal(w.day().reports, 1);
  assert.equal(w.day().successful, 100);
  assert.equal(w.puts.length, 1);
});

test("an uncompressed application/tlsrpt+json part is read too", async () => {
  const w = world();
  await w.receive(mail(JSON.stringify(report({ ok: 55 })), { type: "application/tlsrpt+json", encoding: "" }));
  assert.equal(w.day().successful, 55);
  assert.equal(w.day().errors, 0);
});

test("LF line endings, a single-part report and a mislabelled gzip are read", async () => {
  const w = world();
  await w.receive(mail(gz(report({ id: "lf", ok: 1 })), { eol: "\n" }));
  const single = [
    "From: tlsrpt@example.net",
    "To: tls-reports@cleanway.ai",
    "MIME-Version: 1.0",
    "Content-Type: application/tlsrpt+gzip",
    "Content-Transfer-Encoding: base64",
    "",
    gz(report({ org: "Example Mail", id: "single", ok: 2 })).toString("base64"),
    "",
  ].join("\r\n");
  await w.receive(single);
  await w.receive(mail(gz(report({ org: "Odd Mailer", id: "odd", ok: 4 })), { type: "application/octet-stream" }));
  assert.equal(w.day().reports, 3);
  assert.equal(w.day().successful, 7);
  assert.equal(w.day().errors, 0);
});

test("a Java-style boundary and a quoted-printable JSON part are read", async () => {
  const w = world();
  await w.receive(mail(gz(report({ id: "java", ok: 8 })), { boundary: "----=_Part_17.42+(x)|[y]" }));
  const qp = JSON.stringify(report({ id: "qp", ok: 9 })).replace(/:/g, "=3A").replace(/.{70}/g, "$&=\n");
  await w.receive(mail(qp, { type: "application/tlsrpt+json", encoding: "quoted-printable" }));
  assert.equal(w.day().reports, 2);
  assert.equal(w.day().successful, 17);
  assert.equal(w.day().errors, 0);
});

test("malformed mail is counted as an error, never thrown, never alerted", async () => {
  const w = world();
  const cases = [
    ["From: someone@example.com\r\nSubject: hi\r\n\r\nplain text, no report\r\n", "no report in the mail"],
    [mail(Buffer.from([0x1f, 0x8b, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8])), "bad gzip"],
    [mail(gzipSync(Buffer.from("{ not json"))), "bad JSON"],
    [mail(gz({ hello: "world" })), "not a TLS report"],
    [mail(gz(report({ ok: -5 }))), "bad session count"],
    [mail(gz(report({ failed: "many" }))), "bad session count"],
    [mail(gzipSync(Buffer.alloc(3 * 1024 * 1024, 0x20))), "report too large"],
    [mail("x", { encoding: "base64" }).replace(/^eA==$/m, "e"), "bad base64"],
    [Buffer.from([0, 255, 13, 10, 13, 10, 0x80, 0x9f]), "no report in the mail"],
    ["", "no report in the mail"],
  ];
  for (const [raw] of cases) await w.receive(raw);
  const s = w.day();
  assert.equal(s.reports, 0);
  assert.equal(s.errors, cases.length);
  const kinds = {};
  for (const [, k] of cases) kinds[k] = (kinds[k] || 0) + 1;
  assert.deepEqual(s.error_kinds, kinds);
  assert.equal(w.sent.length, 0);
  assert.deepEqual([w.rejected, w.forwarded], [[], []]);
});

test("a mail over the size limit is not read at all", async () => {
  const w = world();
  const huge = Buffer.alloc(2 * 1024 * 1024, 0x41);
  await w.receive(huge);
  assert.deepEqual(w.day().error_kinds, { "mail too large": 1 });
  assert.equal(w.message.raw.locked, false, "the stream was read");
});

test("hostile names do not break the summary", async () => {
  const w = world();
  await w.receive(mail(gz(report({ org: "Evil\r\nBcc: someone@example.com", id: "e", ok: 4, failed: 1 }))));
  const r = report({ org: "__proto__", ok: 1, failed: 1, details: [{ "result-type": "constructor", "failed-session-count": 1 }] });
  await w.receive(mail(gz(r)));
  await w.receive(mail(gz(report({ org: "constructor", id: "c", ok: 2 }))));
  const s = w.day();
  assert.equal(s.successful, 7);
  assert.deepEqual(s.reporters, { other: 1, constructor: 1, "Evil Bcc: someone@example.com": 1 });
  assert.deepEqual(s.failures, { "constructor ?": 1 });
  assert.equal(Object.getPrototypeOf(s.reporters), Object.prototype);
  // A reporter's name never becomes a mail header.
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /Evil Bcc: someone@example\.com/);
  assert.ok(!/^Bcc:/m.test(w.sent[0].raw));
});

test("a summary holds at most 20 names per list", async () => {
  const w = world();
  for (let i = 0; i < 25; i++) await w.receive(mail(gz(report({ org: `Reporter ${i}`, id: `n${i}`, ok: 1 }))));
  const s = w.day();
  assert.equal(Object.keys(s.reporters).length, 21);
  assert.equal(s.reporters.other, 5);
});

test("a flood of mail stops writing KV after 100 a day", async () => {
  const w = world();
  for (let i = 0; i < 105; i++) await w.receive(mail(gz(report({ id: `r${i}`, ok: 1 }))));
  const s = w.day();
  assert.equal(s.reports, 100);
  assert.equal(s.capped, true);
  assert.equal(w.puts.length, 101);
});

test("a KV outage is logged, not thrown", async () => {
  const w = world();
  const broken = w.env({
    STATE: {
      get: async () => {
        throw new Error("KV unavailable");
      },
      put: async () => {
        throw new Error("KV unavailable");
      },
    },
  });
  const errors = console.error;
  console.error = () => {};
  try {
    await w.receive(mail(gz(report({ failed: 1 }))), broken);
    await w.receive("garbage", broken);
  } finally {
    console.error = errors;
  }
});

// ── the summary page ──

test("GET / on workers.dev shows the mode and the last days, newest first, counts only", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 10, failed: 1, details: [MISMATCH] }))));
  w.now = T0 + DAY;
  await w.receive(mail(gz(report({ id: "d2", ok: 20 }))));
  w.kv.set("day:2026-08-01", JSON.stringify({ day: "2026-08-01", reports: 9 })); // older than 30 days
  const r = await get(DASH_URL, w.env({ MTA_STS_MODE: "enforce" }));
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("cache-control"), "no-store");
  const j = await r.json();
  assert.deepEqual(j.policy, {
    mode: "enforce",
    max_age: 604800,
    mx: ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net"],
  });
  assert.deepEqual(j.days.map((d) => [d.day, d.successful, d.failed]), [["2026-10-24", 20, 0], ["2026-10-23", 10, 1]]);
  const text = JSON.stringify(j);
  for (const leak of ["ids", "209.85.220.41", "104.30.0.1", "smtp-tls-reporting@google.com", "X509_V_ERR"]) {
    assert.ok(!text.includes(leak), leak);
  }
});

test("GET / with nothing recorded yet is an empty list", async () => {
  const w = world();
  const j = await (await get(DASH_URL, w.env())).json();
  assert.equal(j.policy.mode, "testing");
  assert.deepEqual(j.days, []);
});
