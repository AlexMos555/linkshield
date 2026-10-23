// Forged and flooding mail to tls-reports@cleanway.ai. The address is public
// (the _smtp._tls TXT record) and anyone can mail it: what a forger sends must
// not hide a real report, silence a real alert, run the shared KV budget dry,
// or put words of its own into the founder's alert mail.
// `node --test ops/mail-security-worker/` runs this with worker.test.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";

import { MISMATCH, gz, mail, report, world } from "./test-world.mjs";

const FORGER = "reports@forger.example";
const realFailing = () => mail(gz(report({ ok: 1197, failed: 3, details: [MISMATCH] })));

test("a forged copy of a report's org and id does not shadow the real report", async () => {
  const w = world();
  // Google's report-id is predictable; the forger sends its own report under it first.
  await w.receive(mail(gz(report({ ok: 1, failed: 0 })), { from: FORGER }));
  await w.receive(realFailing());
  const s = w.day();
  assert.equal(s.reports, 2);
  assert.equal(s.failed, 3);
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /google\.com/);
});

test("junk mail has its own budget: 100 of them do not stop a real report or its alert", async () => {
  const w = world();
  for (let i = 0; i < 100; i++) await w.receive(`From: x${i}@forger.example\r\n\r\nnot a report ${i}\r\n`);
  await w.receive(realFailing());
  const s = w.day();
  assert.equal(s.errors, 20);
  assert.equal(s.errors_capped, true);
  assert.equal(s.reports, 1);
  assert.equal(s.failed, 3);
  assert.equal(w.sent.length, 1);
  assert.equal(w.puts.length, 22, "20 errors, the cap flag, the report");
});

test("after 100 reports a day it stops counting, but a failing report still alerts", async () => {
  const w = world();
  for (let i = 0; i < 30; i++) await w.receive(`From: ${FORGER}\r\n\r\njunk ${i}\r\n`); // its own budget
  for (let i = 0; i < 105; i++) await w.receive(mail(gz(report({ id: `r${i}`, ok: 1 })), { from: FORGER }));
  assert.equal(w.day().reports, 100);
  assert.equal(w.day().capped, true);
  assert.equal(w.puts.length, 21 + 101);
  await w.receive(realFailing());
  assert.equal(w.sent.length, 1);
  assert.ok(w.day().alerts["google.com"]);
  assert.equal(w.day().reports, 100);
  assert.equal(w.puts.length, 21 + 102, "one write for the alert");
  await w.receive(mail(gz(report({ id: "g-2", failed: 1 }))));
  assert.equal(w.puts.length, 21 + 102, "nothing left to record");
});

test("forged failing reports share one alert a day and cannot use up Google's or Microsoft's", async () => {
  const w = world();
  for (let i = 0; i < 10; i++) {
    await w.receive(mail(gz(report({ org: "Google Inc.", id: `x${i}`, failed: 9 })), { from: `r@forger${i}.example` }));
  }
  assert.equal(w.sent.length, 1);
  assert.match(w.sent[0].raw, /подделк/, "an unknown reporter is flagged as possibly forged");
  await w.receive(realFailing());
  await w.receive(mail(gz(report({ org: "Microsoft Corporation", id: "m", failed: 2 })), { from: "tlsrpt@microsoft.com" }));
  assert.equal(w.sent.length, 3);
  assert.deepEqual(Object.keys(w.day().alerts).sort(), ["google.com", "microsoft.com", "other"]);
});

test("the alert is claimed before it is sent: when KV cannot record it, nothing is sent", async () => {
  const w = world();
  w.putFails = 5;
  const errors = console.error;
  console.error = () => {};
  try {
    for (let i = 0; i < 5; i++) await w.receive(mail(gz(report({ id: `p${i}`, failed: 1 }))));
  } finally {
    console.error = errors;
  }
  assert.ok(w.tries <= 1, `${w.tries} sends`);
  assert.equal(w.tries, 0);
});

test("a send that keeps failing is tried at most 5 times a day", async () => {
  const w = world();
  w.sendFails = 1000;
  for (let i = 0; i < 20; i++) await w.receive(mail(gz(report({ id: `s${i}`, failed: 1 }))));
  assert.equal(w.tries, 5);
  assert.deepEqual(w.day().alerts, {});
  assert.equal(w.day().alert_tries, 5);
  assert.equal(w.day().alert_error.error, "destination address not verified");
  assert.equal(w.puts.length, 25, "20 reports and 5 cleared claims");
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
