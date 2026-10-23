// Tests for the mail-security Worker (MTA-STS policy, reading TLS-RPT
// reports, the summary page), run in Node with KV, the email binding and the
// incoming message stubbed (test-world.mjs). Forged and flooding mail:
// forged.test.mjs. `node --test ops/mail-security-worker/worker.test.mjs
// ops/mail-security-worker/forged.test.mjs` runs both (as does
// tests/test_mail_security_worker.py, so CI's pytest job covers them).
import assert from "node:assert/strict";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { DASH_URL, DAY, GOOGLE, MISMATCH, POLICY_URL, T0, get, gz, mail, report, world } from "./test-world.mjs";

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

test("a gzip report from Google is counted per policy in Google's own entry, kept 30 days, no mail when nothing failed", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1200, failed: 0 }))));
  const s = w.day();
  assert.equal(s.reports, 1);
  assert.equal(s.successful, 1200);
  assert.equal(s.failed, 0);
  assert.deepEqual(s.policies, { "sts cleanway.ai": { successful: 1200, failed: 0 } });
  assert.deepEqual(s.failures, {});
  assert.equal(s.reporters, undefined, "a known reporter's entry is that reporter alone");
  assert.deepEqual(s.covers, ["2026-10-22"]);
  assert.equal(s.errors, 0);
  assert.equal(s.alert, null);
  assert.equal(w.sent.length, 0);
  assert.deepEqual(w.puts.map((p) => [p.k, p.opts]), [["summary:google.com", { expirationTtl: 31 * 86_400 }]]);
  assert.deepEqual([w.rejected, w.forwarded], [[], []]);
});

test("each known reporter is counted on its own, never added to another's", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1200 }))));
  const ms = report({ org: "Microsoft Corporation", id: "133797", ok: 40, failed: 0 });
  ms.policies.push({
    policy: { "policy-type": "no-policy-found", "policy-domain": "cleanway.ai" },
    summary: { "total-successful-session-count": 7, "total-failure-session-count": 0 },
  });
  await w.receive(mail(gz(ms), { from: "TLSRPT <tlsrpt-noreply@microsoft.com>" }));
  assert.deepEqual(w.day().policies, { "sts cleanway.ai": { successful: 1200, failed: 0 } });
  const m = w.day("2026-10-23", "microsoft.com");
  assert.equal(m.reports, 1);
  assert.equal(m.successful, 47);
  assert.deepEqual(m.policies, {
    "sts cleanway.ai": { successful: 40, failed: 0 },
    "no-policy-found cleanway.ai": { successful: 7, failed: 0 },
  });
  assert.equal(w.day("2026-10-23", "unverified"), null);
  assert.deepEqual(w.puts.map((p) => p.k), ["summary:google.com", "summary:microsoft.com"]);
});

test("a report with failed sessions mails the founder once, without the raw report", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 1197, failed: 3, details: [MISMATCH] }))));
  const s = w.day();
  assert.equal(s.failed, 3);
  assert.deepEqual(s.failures, { "certificate-host-mismatch route2.mx.cloudflare.net": 3 });
  assert.equal(s.alert, new Date(T0).toISOString());
  assert.equal(w.sent.length, 1);
  const m = w.sent[0];
  assert.equal(m.from, "alerts@cleanway.ai");
  assert.equal(m.to, "founder@example.com");
  assert.match(m.raw, /^From: Cleanway monitor <alerts@cleanway\.ai>\r$/m);
  assert.match(m.raw, /^To: founder@example\.com\r$/m);
  assert.deepEqual(w.subjects(), ["Cleanway: сбои TLS при доставке почты на cleanway.ai (3)"]);
  assert.match(m.raw, /google\.com/);
  assert.match(m.raw, /«Google Inc\.»/);
  assert.match(m.raw, /2026-10-22T00:00:00Z – 2026-10-22T23:59:59Z/);
  assert.match(m.raw, /sts cleanway\.ai: .*1197.*3/);
  assert.match(m.raw, /certificate-host-mismatch, route2\.mx\.cloudflare\.net: 3/);
  assert.match(m.raw, /X509_V_ERR_HOSTNAME_MISMATCH/);
  assert.match(m.raw, /testing/);
  assert.ok(!/подделк/.test(m.raw), "a known reporter is not flagged");
  // Never the report itself: no sender IPs, no contact address, no attachment.
  for (const leak of ["209.85.220.41", "104.30.0.1", "smtp-tls-reporting@google.com", "policy-string", "H4sI"]) {
    assert.ok(!m.raw.includes(leak), leak);
  }
  assert.deepEqual(w.forwarded, []);
});

test("one alert a day per known reporter: its next failing report that day only adds to the summary", async () => {
  const w = world();
  await w.receive(mail(gz(report({ failed: 3, details: [MISMATCH] }))));
  await w.receive(mail(gz(report({ id: "g-2", failed: 2 }))));
  assert.equal(w.sent.length, 1);
  await w.receive(mail(gz(report({ org: "Microsoft Corporation", id: "m-1", failed: 5 })), { from: "tlsrpt@microsoft.com" }));
  assert.equal(w.sent.length, 2, "Microsoft has an alert of its own");
  assert.match(w.sent[1].raw, /microsoft\.com/);
  assert.equal(w.day().failed, 5);
  assert.equal(w.day("2026-10-23", "microsoft.com").failed, 5);
  assert.ok(w.day().alert && w.day("2026-10-23", "microsoft.com").alert);
  w.now = T0 + DAY;
  await w.receive(mail(gz(report({ id: "next-day", failed: 1 }))));
  assert.equal(w.sent.length, 3);
  assert.equal(w.day("2026-10-24").failed, 1);
});

test("in enforce mode the alert says mail is not being delivered", async () => {
  const w = world();
  await w.receive(mail(gz(report({ failed: 2 }))), w.env({ MTA_STS_MODE: "enforce" }));
  assert.match(w.sent[0].raw, /enforce/);
  assert.match(w.sent[0].raw, /НЕ доставляют/);
});

test("an alert whose send and retry both fail is recorded and retried with the next failing report", async () => {
  const w = world();
  w.sendFails = 2;
  await w.receive(mail(gz(report({ failed: 2 }))));
  assert.equal(w.sent.length, 0);
  assert.equal(w.tries, 2, "the send and one retry");
  assert.equal(w.day().alert, null);
  assert.equal(w.day().alert_error.error, "destination address not verified");
  await w.receive(mail(gz(report({ id: "second", ok: 10 }))));
  assert.equal(w.tries, 2, "a clean report owes no alert");
  await w.receive(mail(gz(report({ id: "third", failed: 1 }))));
  assert.equal(w.sent.length, 1);
  assert.ok(w.day().alert);
  assert.equal(w.day().alert_error.at, new Date(T0).toISOString(), "the failure stays on record");
});

test("the same report delivered twice is counted once", async () => {
  const w = world();
  await w.receive(mail(gz(report({ ok: 100 }))));
  await w.receive(mail(gz(report({ ok: 100 }))));
  assert.equal(w.day().reports, 1);
  assert.equal(w.day().successful, 100);
  assert.equal(w.puts.length, 1);
});

test("a redelivery counts once however it is wrapped: the report's bytes decide", async () => {
  const w = world();
  const r = report({ ok: 100, failed: 1 });
  await w.receive(mail(gz(r)));
  const again = gzipSync(Buffer.from(JSON.stringify(r)), { level: 1 }); // other gzip bytes, same report
  await w.receive(mail(again, { boundary: "other-boundary" }));
  await w.receive(mail(JSON.stringify(r), { type: "application/tlsrpt+json", encoding: "" }));
  assert.equal(w.day().reports, 1);
  assert.equal(w.day().failed, 1);
  assert.equal(w.sent.length, 1);
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
  assert.equal(w.day().reports, 2);
  assert.equal(w.day().successful, 5);
  assert.equal(w.day().errors, 0);
  const u = w.day("2026-10-23", "unverified");
  assert.deepEqual([u.reports, u.successful, u.errors], [1, 2, 0]);
  assert.deepEqual(u.reporters, { "example.net": 1 });
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
  const from = "tlsrpt@example.net";
  const cases = [
    ["From: someone@example.com\r\nSubject: hi\r\n\r\nplain text, no report\r\n", "no report in the mail"],
    [mail(Buffer.from([0x1f, 0x8b, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8]), { from }), "bad gzip"],
    [mail(gzipSync(Buffer.from("{ not json")), { from }), "bad JSON"],
    [mail(gz({ hello: "world" }), { from }), "not a TLS report"],
    [mail(gz(report({ ok: -5 })), { from }), "bad session count"],
    [mail(gz(report({ failed: "many" })), { from }), "bad session count"],
    [mail(gzipSync(Buffer.alloc(3 * 1024 * 1024, 0x20)), { from }), "report too large"],
    [mail("x", { encoding: "base64", from }).replace(/^eA==$/m, "e"), "bad base64"],
    [Buffer.from([0, 255, 13, 10, 13, 10, 0x80, 0x9f]), "no report in the mail"],
    ["", "no report in the mail"],
  ];
  for (const [raw] of cases) await w.receive(raw);
  const s = w.day("2026-10-23", "unverified");
  assert.equal(s.reports, 0);
  assert.equal(s.errors, cases.length);
  const kinds = {};
  for (const [, k] of cases) kinds[k] = (kinds[k] || 0) + 1;
  assert.deepEqual(s.error_kinds, kinds);
  assert.equal(w.sent.length, 0);
  assert.deepEqual([w.rejected, w.forwarded], [[], []]);
});

test("an unreadable mail From a known reporter is counted in that reporter's own entry", async () => {
  const w = world();
  await w.receive(mail(gz({ hello: "world" })));
  assert.deepEqual(w.day().error_kinds, { "not a TLS report": 1 });
  assert.equal(w.day("2026-10-23", "unverified"), null);
});

test("a mail over the size limit is not read at all", async () => {
  const w = world();
  const huge = Buffer.alloc(2 * 1024 * 1024, 0x41);
  await w.receive(huge);
  assert.deepEqual(w.day("2026-10-23", "unverified").error_kinds, { "mail too large": 1 });
  assert.equal(w.message.raw.locked, false, "the stream was read");
});

test("a reporter is the domain of the header From; anything ambiguous is unknown", async () => {
  const w = world();
  const froms = [
    ['"Google" <noreply-smtp-tls-reporting@google.com>', "google.com"],
    ["NoReply@Mail.Example.ORG", "mail.example.org"],
    ["x@evil.example, noreply@google.com", "unknown"],
    [["x@evil.example", GOOGLE], "unknown"], // two From headers
    ['"a@google.com" <x@evil.example>', "evil.example"],
    ["__proto__", "unknown"],
    ["someone@localhost", "unknown"],
    [[], "unknown"],
  ];
  for (const [i, [from]] of froms.entries()) await w.receive(mail(gz(report({ id: `f${i}`, ok: 1 })), { from }));
  assert.equal(w.day().reports, 1);
  const s = w.day("2026-10-23", "unverified");
  assert.equal(s.reports, froms.length - 1);
  assert.deepEqual(s.reporters, { "mail.example.org": 1, unknown: 5, "evil.example": 1 });
  assert.equal(Object.getPrototypeOf(s.reporters), Object.prototype);
});

test("a known reporter is its exact domain: a subdomain is unverified", async () => {
  const w = world();
  const froms = ["x@sub.google.com", "tlsrpt@mail.microsoft.com", "x@google.com.evil.example", "x@notgoogle.com"];
  for (const [i, from] of froms.entries()) await w.receive(mail(gz(report({ id: `s${i}`, ok: 1 })), { from }));
  assert.equal(w.day(), null);
  assert.equal(w.day("2026-10-23", "microsoft.com"), null);
  assert.deepEqual(w.day("2026-10-23", "unverified").reporters, {
    "sub.google.com": 1, "mail.microsoft.com": 1, "google.com.evil.example": 1, "notgoogle.com": 1,
  });
});

test("hostile names never become a summary key or a mail header", async () => {
  const w = world();
  await w.receive(mail(gz(report({ org: "Evil\r\nBcc: someone@example.com", id: "e", ok: 4, failed: 1 }))));
  const r = report({ org: "__proto__", ok: 1, failed: 1, details: [{ "result-type": "constructor", "failed-session-count": 1 }] });
  r.policies[0].policy["policy-type"] = "__proto__";
  r.policies[0].policy["policy-domain"] = "constructor";
  await w.receive(mail(gz(r)));
  const s = w.day();
  assert.equal(s.successful, 5);
  assert.deepEqual(s.policies, {
    "sts cleanway.ai": { successful: 4, failed: 1 },
    "other other-domain": { successful: 1, failed: 1 },
  });
  assert.deepEqual(s.failures, { "other ?": 1 });
  assert.equal(Object.getPrototypeOf(s.policies), Object.prototype);
  assert.equal(w.sent.length, 1);
  assert.ok(!/^Bcc:/m.test(w.sent[0].raw));
  assert.ok(!w.sent[0].raw.includes("Evil"), "a name that is not a plain company name is left out");
});

test("a summary holds at most 20 names per list", async () => {
  const w = world();
  for (let i = 0; i < 25; i++) {
    await w.receive(mail(gz(report({ id: `n${i}`, ok: 1 })), { from: `tlsrpt@reporter${i}.example` }));
  }
  const s = w.day("2026-10-23", "unverified");
  assert.equal(Object.keys(s.reporters).length, 21);
  assert.equal(s.reporters.other, 5);
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
  assert.equal(w.tries, 0, "nothing is sent when the alert cannot be recorded");
});

// ── the summary page ──

test("GET / on workers.dev shows the mode and the last 30 days, newest first, counts only, one KV read per reporter", async () => {
  const w = world();
  w.now = T0 - 31 * DAY;
  await w.receive(mail(gz(report({ id: "old", ok: 5 }))));
  w.now = T0 - 29 * DAY;
  await w.receive(mail(gz(report({ id: "edge", ok: 6 }))));
  w.now = T0;
  await w.receive(mail(gz(report({ ok: 10, failed: 1, details: [MISMATCH] }))));
  await w.receive(mail(gz(report({ id: "u", ok: 2, failed: 1 })), { from: "tlsrpt@example.net" }));
  w.now = T0 + DAY;
  await w.receive(mail(gz(report({ id: "d2", ok: 20 }))));
  w.gets = 0;
  const r = await get(DASH_URL, w.env({ MTA_STS_MODE: "enforce" }));
  assert.equal(w.gets, 3, "google.com, microsoft.com, unverified");
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("cache-control"), "no-store");
  const j = await r.json();
  assert.deepEqual(j.policy, {
    mode: "enforce",
    max_age: 604800,
    mx: ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net"],
  });
  // The page shows 2026-09-25 .. 2026-10-24: 2026-09-24 is one day past it.
  const g = (d) => d.verified["google.com"];
  assert.deepEqual(j.days.map((d) => [d.day, g(d).successful, g(d).failed]), [["2026-10-24", 20, 0], ["2026-10-23", 10, 1]]);
  // Unverified reports are shown apart, never added to a known reporter's.
  assert.deepEqual(j.days.map((d) => [d.day, d.unverified.reports, d.unverified.failed]), [["2026-10-24", 0, 0], ["2026-10-23", 1, 1]]);
  assert.deepEqual(j.days[1].unverified.reporters, { "example.net": 1 });
  assert.deepEqual(Object.keys(j.days[1].verified), ["google.com"], "a reporter that sent nothing that day is not listed");
  assert.equal(j.days[1].verified["google.com"].day, undefined);
  const text = JSON.stringify(j);
  for (const leak of ["ids", "209.85.220.41", "104.30.0.1", "smtp-tls-reporting@google.com", "X509_V_ERR"]) {
    assert.ok(!text.includes(leak), leak);
  }
  // Only today's entry keeps its report digests, and nothing older than 30 days is kept.
  const book = JSON.parse(w.kv.get("summary:google.com"));
  assert.deepEqual(book.days.map((d) => [d.day, Array.isArray(d.ids)]), [["2026-10-24", true], ["2026-10-23", false]]);
  // With no mail since, the window still moves with the clock.
  w.now = T0 + 30 * DAY;
  const later = await w.page();
  assert.deepEqual(later.days.map((d) => d.day), ["2026-10-24"]);
});

test("GET / with nothing recorded yet is an empty list", async () => {
  const w = world();
  const j = await (await get(DASH_URL, w.env())).json();
  assert.equal(j.policy.mode, "testing");
  assert.deepEqual(j.days, []);
});
