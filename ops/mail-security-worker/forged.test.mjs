// Forged and flooding mail to tls-reports@cleanway.ai. The address is public
// (the _smtp._tls TXT record) and anyone can mail it: what a forger sends must
// not hide a real report, change Google's or Microsoft's counts, silence a
// real alert, run the shared KV budget dry, or put words of its own into the
// founder's alert mail. `node --test ops/mail-security-worker/worker.test.mjs
// ops/mail-security-worker/forged.test.mjs` runs this with worker.test.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import { gzipSync } from "node:zlib";

import { MISMATCH, gz, mail, report, world } from "./test-world.mjs";

const FORGER = "reports@forger.example";
const realFailing = () => mail(gz(report({ ok: 1197, failed: 3, details: [MISMATCH] })));
const realClean = () => mail(gz(report({ ok: 1200, failed: 0 })));
const quiet = async (fn) => {
  const errors = console.error;
  console.error = () => {};
  try {
    await fn();
  } finally {
    console.error = errors;
  }
};

// The rollout gate in the README: Google's own entry has the policy in use and no failures.
const gatePasses = (day) => {
  const g = day && day.verified["google.com"];
  return Boolean(g && g.reports > 0 && g.policies["sts cleanway.ai"] && g.failed === 0);
};

test("a forged copy of a report's org and id does not shadow the real report", async () => {
  const w = world();
  // Google's report-id is predictable; the forger sends its own report under it first.
  await w.receive(mail(gz(report({ ok: 1, failed: 0 })), { from: FORGER }));
  await w.receive(realFailing());
  assert.deepEqual([w.day().reports, w.day().failed], [1, 3]);
  assert.equal(w.day("2026-10-23", "unverified").reports, 1);
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /google\.com/);
});

test("a byte-for-byte copy of Google's report sent first does not shadow it either", async () => {
  const w = world();
  const bytes = gz(report({ ok: 1197, failed: 3, details: [MISMATCH] }));
  await w.receive(mail(bytes, { from: FORGER }));
  await w.receive(mail(bytes));
  assert.deepEqual([w.day().reports, w.day().failed], [1, 3]);
  assert.ok(w.day().alert, "Google's alert is sent too");
  assert.equal(w.sent.length, 2);
});

test("(A) 20 forged reporters fill the unverified reporter list; Google's report still passes the rollout gate", async () => {
  const w = world();
  for (let i = 0; i < 20; i++) await w.receive(mail(gz(report({ id: `a${i}`, ok: 1 })), { from: `tlsrpt@forger${i}.example` }));
  await w.receive(realClean());
  const day = (await w.page()).days[0];
  assert.equal(Object.keys(day.unverified.reporters).length, 20);
  assert.equal(day.unverified.reporters.other, undefined);
  assert.equal(day.verified["google.com"].reports, 1);
  assert.equal(day.verified["google.com"].successful, 1200);
  assert.ok(gatePasses(day));
});

test("(B) forged failing reports from several senders never add to Google's failures", async () => {
  const w = world();
  const forged = { ...MISMATCH, "failed-session-count": 50 };
  for (let i = 0; i < 3; i++) {
    await w.receive(mail(gz(report({ id: `b${i}`, ok: 0, failed: 50, details: [forged] })), { from: `tlsrpt@mail${i}.example` }));
  }
  await w.receive(realClean());
  const day = (await w.page()).days[0];
  assert.equal(day.unverified.failed, 150);
  assert.deepEqual(day.unverified.failures, { "certificate-host-mismatch route2.mx.cloudflare.net": 150 });
  assert.equal(day.verified["google.com"].failed, 0);
  assert.deepEqual(day.verified["google.com"].failures, {});
  assert.ok(gatePasses(day));
  assert.equal(w.sent.length, 1, "one alert, flagged as possibly forged");
  assert.match(w.sent[0].raw, /подделк/);
});

test("(C) after 100 unverified reports a day they stop counting, Google's report is counted in full", async () => {
  const w = world();
  for (let i = 0; i < 30; i++) await w.receive(`From: ${FORGER}\r\n\r\njunk ${i}\r\n`); // its own budget
  for (let i = 0; i < 105; i++) await w.receive(mail(gz(report({ id: `r${i}`, ok: 1 })), { from: FORGER }));
  const u = () => w.day("2026-10-23", "unverified");
  assert.deepEqual([u().reports, u().capped, u().errors, u().errors_capped], [100, true, 20, true]);
  assert.equal(w.puts.length, 21 + 101);
  await w.receive(realClean());
  assert.deepEqual([w.day().reports, w.day().successful, w.day().capped], [1, 1200, false]);
  assert.ok(gatePasses((await w.page()).days[0]));
  // A capped day still alerts, once per group.
  await w.receive(realFailing());
  await w.receive(mail(gz(report({ id: "late", failed: 4 })), { from: FORGER }));
  assert.equal(w.sent.length, 2);
  assert.ok(u().alert && w.day().alert);
  assert.equal(u().reports, 100);
  const puts = w.puts.length;
  await w.receive(mail(gz(report({ id: "later", failed: 4 })), { from: FORGER }));
  assert.equal(w.puts.length, puts, "nothing left to record");
});

test("forged mail cannot fill Google's failure list: 60 forged failure kinds stay unverified", async () => {
  const w = world();
  const kinds = ["starttls-not-supported", "certificate-host-mismatch", "certificate-expired", "certificate-not-trusted",
    "validation-failure", "tlsa-invalid", "dnssec-invalid", "dane-required", "sts-policy-fetch-error", "sts-policy-invalid",
    "sts-webpki-invalid", "bogus"];
  const hosts = ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net", "mx.forger.example", ""];
  const details = kinds.flatMap((k) => hosts.map((h) => ({ "result-type": k, "receiving-mx-hostname": h, "failed-session-count": 1 })));
  await w.receive(mail(gz(report({ id: "fill", failed: 60, details })), { from: FORGER }));
  assert.equal(Object.keys(w.day("2026-10-23", "unverified").failures).length, 21);
  await w.receive(realFailing());
  assert.deepEqual(w.day().failures, { "certificate-host-mismatch route2.mx.cloudflare.net": 3 });
});

test("forged mail delivered at the same moment cannot overwrite Google's report", async () => {
  const w = world();
  // Every receive reads before any of them writes: a single shared key would keep only the last write.
  await Promise.all([
    ...Array.from({ length: 5 }, (_, i) => w.receive(mail(gz(report({ id: `c${i}`, ok: 1 })), { from: FORGER }))),
    w.receive(realClean()),
    ...Array.from({ length: 5 }, (_, i) => w.receive(`From: x${i}@forger.example\r\n\r\njunk\r\n`)),
  ]);
  assert.deepEqual([w.day().reports, w.day().successful], [1, 1200]);
});

test("forged failing reports share one alert a day and cannot use up Google's or Microsoft's", async () => {
  const w = world();
  for (let i = 0; i < 10; i++) {
    await w.receive(mail(gz(report({ org: "Google Inc.", id: `x${i}`, failed: 9 })), { from: `r@forger${i}.example` }));
  }
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /подделк/, "an unknown reporter is flagged as possibly forged");
  await w.receive(realFailing());
  await w.receive(mail(gz(report({ org: "Microsoft Corporation", id: "m", failed: 2 })), { from: "tlsrpt-noreply@microsoft.com" }));
  assert.equal(w.sent.length, 3);
  for (const group of ["google.com", "microsoft.com", "unverified"]) assert.ok(w.day("2026-10-23", group).alert, group);
});

test("a report From a subdomain of google.com gets the unverified alert, flagged, and leaves Google's alone", async () => {
  const w = world();
  await w.receive(mail(gz(report({ org: "Google Inc.", id: "sub", failed: 7 })), { from: "x@sub.google.com" }));
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /подделк/);
  assert.ok(!w.sent[0].raw.includes("Google Inc."), "a forger's org name is not shown");
  assert.match(w.sent[0].raw, /не из списка известных/);
  assert.equal(w.day(), null);
  assert.equal(w.day("2026-10-23", "unverified").failed, 7);
  await w.receive(realFailing());
  assert.equal(w.sent.length, 2, "Google's own alert still goes out");
  assert.match(w.sent[1].raw, /Отчёт TLS-RPT от google\.com/);
});

test("the alert is claimed before it is sent: when KV cannot record it, nothing is sent", async () => {
  const w = world();
  w.putFails = 10; // each mail tries twice
  await quiet(async () => {
    for (let i = 0; i < 5; i++) await w.receive(mail(gz(report({ id: `p${i}`, failed: 1 }))));
  });
  assert.equal(w.tries, 0);
  assert.equal(w.kv.size, 0);
});

test("(E) a KV write that fails once is redone 1.1 s later: the day's only failing report is counted and alerts once", async () => {
  const w = world();
  w.putFails = 1;
  await w.receive(realFailing());
  assert.deepEqual(w.waits, [1100]);
  assert.deepEqual([w.day().reports, w.day().failed], [1, 3]);
  assert.ok(w.day().alert);
  assert.equal(w.sent.length, 1);
  assert.equal(w.puts.length, 1);
});

test("a redone write reads again first: it keeps what another mail wrote in between", async () => {
  const w = world();
  w.putFails = 1;
  const env = w.env();
  const put = env.STATE.put;
  let raced = false;
  env.STATE.put = async (k, v, o) => {
    if (!raced) {
      raced = true;
      // Another report of Google's lands while this one's write is refused.
      w.kv.set(k, JSON.stringify({ days: [{ day: "2026-10-23", reports: 1, successful: 5, failed: 0, ids: ["other"] }] }));
    }
    return put(k, v, o);
  };
  await w.receive(realClean(), env);
  assert.deepEqual([w.day().reports, w.day().successful], [2, 1205]);
});

test("(D) a send that fails once is retried in the same delivery: the day's only failing report alerts once", async () => {
  const w = world();
  w.sendFails = 1;
  await w.receive(realFailing());
  assert.equal(w.tries, 2);
  assert.equal(w.sent.length, 1);
  assert.deepEqual(w.waits, [1100]);
  assert.ok(w.day().alert);
  assert.equal(w.day().alert_error, null);
  assert.equal(w.day().alert_tries, 2);
  assert.equal(w.puts.length, 1, "the claim; nothing to undo");
});

test("a send that keeps failing is tried at most 5 times a day per reporter, retries included", async () => {
  const w = world();
  w.sendFails = 1000;
  for (let i = 0; i < 20; i++) await w.receive(mail(gz(report({ id: `s${i}`, failed: 1 }))));
  assert.equal(w.tries, 5, "2 + 2 + 1");
  assert.equal(w.day().alert, null);
  assert.equal(w.day().alert_tries, 5);
  assert.equal(w.day().alert_error.error, "destination address not verified");
  assert.equal(w.puts.length, 23, "20 reports and 3 cleared claims");
  // Forged mail has tries of its own and cannot use up Google's.
  const w2 = world();
  w2.sendFails = 1000;
  for (let i = 0; i < 20; i++) await w2.receive(mail(gz(report({ id: `f${i}`, failed: 1 })), { from: FORGER }));
  w2.sendFails = 0;
  await w2.receive(realFailing());
  assert.equal(w2.sent.length, 1);
  assert.ok(w2.day().alert);
});

// ── bounded parsing ──

// n empty multipart parts, then a report: each part is a RegExp and a split.
const nested = (n, inner) => {
  const parts = Array.from({ length: n }, (_, i) => `--o\r\nContent-Type: multipart/mixed; boundary=${i}\r\n`);
  return [
    `From: ${FORGER}`,
    "Content-Type: multipart/mixed; boundary=o",
    "",
    ...parts,
    "--o",
    "Content-Type: application/tlsrpt+gzip",
    "Content-Transfer-Encoding: base64",
    "",
    inner.toString("base64"),
    "--o--",
    "",
  ].join("\r\n");
};

test("a mail is read at most 30 MIME parts deep, empty multipart parts included", async () => {
  const w = world();
  await w.receive(nested(20, gz(report({ id: "near", ok: 3 }))));
  assert.equal(w.day("2026-10-23", "unverified").reports, 1, "a report after 20 empty parts is read");
  await w.receive(nested(40, gz(report({ id: "far", ok: 3 }))));
  assert.deepEqual(w.day("2026-10-23", "unverified").error_kinds, { "no report in the mail": 1 });
  const flood = nested(4400, gz(report({ id: "flood", ok: 3 })));
  assert.ok(flood.length < 256 * 1024, `${flood.length} bytes: under the mail size limit, so it is parsed`);
  // Each multipart part looked at builds one RegExp for its boundary.
  const Real = globalThis.RegExp;
  let built = 0;
  globalThis.RegExp = new Proxy(Real, {
    construct(target, args, newTarget) {
      built++;
      return Reflect.construct(target, args, newTarget);
    },
  });
  try {
    await w.receive(flood);
  } finally {
    globalThis.RegExp = Real;
  }
  assert.ok(built <= 30, `${built} boundaries`);
  assert.deepEqual(w.day("2026-10-23", "unverified").error_kinds, { "no report in the mail": 2 });
});

test("one mail inflates at most 256 KB in all: after the first gzip bomb no other part is unzipped", async () => {
  const w = world();
  const bomb = gzipSync(Buffer.alloc(300 * 1024, 0x20)).toString("base64");
  const parts = Array.from({ length: 10 }, () =>
    ["--b", "Content-Type: application/tlsrpt+gzip", "Content-Transfer-Encoding: base64", "", bomb].join("\r\n"),
  );
  const raw = [`From: ${FORGER}`, "Content-Type: multipart/mixed; boundary=b", "", ...parts, "--b--", ""].join("\r\n");
  const Real = globalThis.DecompressionStream;
  let streams = 0;
  globalThis.DecompressionStream = class extends Real {
    constructor(f) {
      super(f);
      streams++;
    }
  };
  try {
    await w.receive(raw);
  } finally {
    globalThis.DecompressionStream = Real;
  }
  assert.equal(streams, 1);
  assert.deepEqual(w.day("2026-10-23", "unverified").error_kinds, { "report too large": 1 });
});

const BAIT = "URGENT: Cloudflare suspended cleanway.ai - re-verify at https://cloudflare-verify.example/login";

function baitReport() {
  const r = report({ org: `${BAIT}\u202e`, ok: 1, failed: 1 });
  r["date-range"]["start-datetime"] = BAIT;
  r.policies[0].policy["policy-domain"] = "cloudflare-verify.example/login";
  r.policies[0].policy["policy-type"] = BAIT;
  r.policies[0]["failure-details"] = [
    { "result-type": BAIT, "receiving-mx-hostname": BAIT, "failed-session-count": 1, "failure-reason-code": BAIT },
    { "result-type": "validation-failure", "failed-session-count": 1, "failure-reason-code": "see cloudflare-verify.example" },
    { "result-type": "validation-failure", "failed-session-count": 1, "failure-reason-code": "\u202eEXPIRED_CERT" },
  ];
  return r;
}

test("the alert carries no words of the sender's: only values from closed sets", async () => {
  for (const from of [FORGER, "noreply-smtp-tls-reporting@google.com"]) {
    const w = world();
    await w.receive(mail(gz(baitReport()), { from }));
    assert.equal(w.sent.length, 1, from);
    const raw = w.sent[0].raw;
    for (const bad of ["URGENT", "cloudflare-verify", "suspended", "re-verify", "\u202e"]) {
      assert.ok(!raw.includes(bad), `${from}: ${JSON.stringify(bad)}`);
    }
    assert.match(raw, /validation-failure, MX не указан: 1 \(EXPIRED_CERT\)\n/, "a code is kept, its bidi override is not");
    assert.match(raw, /other other-domain: успешных сессий 1, неудачных 1/);
    assert.match(raw, /other, другой хост: 1/);
    assert.match(raw, /validation-failure, MX не указан: 1\n/);
  }
});

test("a known reporter's org is shown with bidi and zero-width characters removed; an unknown one's never", async () => {
  const w = world();
  await w.receive(mail(gz(report({ org: "Goo\u200bgle\u202e Inc.\u0085", failed: 1 }))));
  assert.match(w.sent[0].raw, /«Google Inc\.»/);
  const w2 = world();
  await w2.receive(mail(gz(report({ org: "Google Inc.", failed: 1 })), { from: FORGER }));
  assert.ok(!w2.sent[0].raw.includes("Google Inc."));
  assert.ok(!w2.sent[0].raw.includes("forger.example"), "an unknown reporter's address stays on the summary page");
});

test("the alert stays short whatever the report holds", async () => {
  const w = world();
  const r = report({ failed: 1 });
  const policy = r.policies[0];
  const failure = { ...MISMATCH, "failed-session-count": 1 };
  r.policies = Array.from({ length: 20 }, () => ({ ...policy, "failure-details": Array.from({ length: 20 }, () => failure) }));
  await w.receive(mail(gz(r)));
  assert.deepEqual(w.day().failures, { "certificate-host-mismatch route2.mx.cloudflare.net": 400 }, "all of it is in the summary");
  const raw = w.sent[0].raw;
  assert.ok(raw.length < 4000, `${raw.length} chars`);
  assert.equal(raw.match(/^ {2}certificate-host-mismatch/gm).length, 25, "5 policies × 5 failures");
  assert.match(raw, /и ещё 15 строк об ошибках/);
  assert.match(raw, /и ещё 15 политик/);
});
