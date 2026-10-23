// Cleanway mail security — a Cloudflare Worker for MTA-STS (RFC 8461) and
// TLS-RPT (RFC 8460) on cleanway.ai.
//
//   * fetch, on mta-sts.cleanway.ai: GET /.well-known/mta-sts.txt is the
//     policy — the three Cloudflare Email Routing MX hosts, in the mode of the
//     plain-text binding MTA_STS_MODE ("testing" unless it says "enforce", or
//     "none" to retire the policy). Lines end in CRLF as RFC 8461 §3.2 says
//     (its ABNF takes LF as well; mta-sts.google.com serves CRLF). Senders
//     cache a policy themselves for max_age and must not use HTTP caching, so
//     nothing in between may: no-store. Everything else is a 404.
//   * email: senders mail their daily TLS reports to tls-reports@cleanway.ai
//     and an Email Routing rule hands them to this Worker. It adds up
//     successful and failed sessions per policy into one summary per UTC day
//     (the day the mail arrived), and when a report counts failed sessions it
//     mails the founder. Anyone can mail that address, so everything is kept
//     apart by trust: Google and Microsoft (vouched for by DMARC, see
//     KNOWN_REPORTERS) each have a KV key, counts, budgets, dedup list and
//     daily alert of their own, and everyone else shares an "unverified" one.
//     Forged mail can skew only the unverified counts. A report is
//     deduplicated by its bytes, not by labels a forger can copy; junk and
//     reports have separate daily budgets; and the alert repeats only values
//     from closed sets, never the sender's words. The report itself is never
//     forwarded or stored (no IPs, no contact addresses). A mail it cannot
//     read is counted as an error and dropped, never thrown — a thrown error
//     would make the sender retry.
//   * GET / on workers.dev: the policy in force and the last 30 summaries,
//     verified and unverified apart, in one KV read per key.
//
// Deploy: see ops/mail-security-worker/README.md.

import { EmailMessage } from "cloudflare:email";

const POLICY_HOST = "mta-sts.cleanway.ai";
const POLICY_PATH = "/.well-known/mta-sts.txt";
// The zone's MX records (Cloudflare → Email → Email Routing). Change both
// together, and bump the _mta-sts id after the new policy is live.
const MX_HOSTS = ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net"];
const MAX_AGE_S = { testing: 86_400, enforce: 604_800, none: 86_400 };

const DOMAIN = "cleanway.ai";
const FROM = "alerts@cleanway.ai";
const SUMMARY_URL = "https://cleanway-mail-security.amoskotin.workers.dev/";
// Reporters by the exact domain of the header From. These publish DMARC
// p=reject, and Email Routing rejects mail that fails the From domain's DMARC
// policy, so a report From them is theirs. Not their subdomains: one can
// publish a weaker _dmarc record of its own. Real reports come From
// noreply-smtp-tls-reporting@google.com and tlsrpt-noreply@microsoft.com.
const KNOWN_REPORTERS = ["google.com", "microsoft.com"];
const UNVERIFIED = "unverified"; // everyone else, forged or not
const GROUPS = [...KNOWN_REPORTERS, UNVERIFIED];
// One KV key per group, so forged mail never writes where Google's counts are
// (KV allows one write a second to a key and has no atomic update). The
// public page costs one read per key: the free plan's 100,000 reads a day are
// the whole account's, and the uptime monitor reads every minute.
const KEY_PREFIX = "summary:";
const SHOW_DAYS = 30;
const DAY_MS = 86_400_000;
// KV writes are 1,000 a day for the whole account on the free plan, shared
// with the uptime monitor (~150). A known reporter mails one or two reports a
// day; anyone can mail as an unverified one. These caps hold all of it to
// about 190 writes a day, and forged mail cannot use up a known reporter's.
const BUDGET = {
  known: { reports: 20, errors: 5 },
  unverified: { reports: 100, errors: 20 }, // junk has its own budget and cannot use up the reports'
};
const MAX_ALERT_TRIES = 5; // sends a day per group, retries and failed ones included
const SENDS_PER_CLAIM = 2; // a send, and one retry in the same delivery
const RETRY_MS = 1_100; // past KV's one write a second to a key
// A report mail is a few KB. These limits keep one mail well inside the free
// plan's 10 ms of CPU: at most MAX_PARTS MIME parts are looked at, multipart
// ones included, and all of a mail's gzip parts together inflate to at most
// MAX_JSON_BYTES (a gzip bomb stops there, and so does the reading).
const MAX_RAW_BYTES = 256 * 1024;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_PARTS = 30;
const MAX_LEAVES = 10;
const MAX_NAMES = 20; // per list in a day summary; the rest is counted as "other"
const REPORT_TYPES = ["application/tlsrpt+gzip", "application/tlsrpt+json"];
// RFC 8460 §4.3 and §4.4: the only values a summary or an alert repeats.
const POLICY_TYPES = ["sts", "tlsa", "no-policy-found"];
const RESULT_TYPES = [
  "starttls-not-supported", "certificate-host-mismatch", "certificate-expired", "certificate-not-trusted",
  "validation-failure", "tlsa-invalid", "dnssec-invalid", "dane-required",
  "sts-policy-fetch-error", "sts-policy-invalid", "sts-webpki-invalid",
];
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const REASON_CODE = /^[A-Za-z0-9_:-]{1,64}$/; // no spaces, no dots: no sentence, no link
const ALERT_POLICIES = 5;
const ALERT_FAILURES = 5; // per policy

// ── the policy ──

function stsMode(env) {
  const m = String((env && env.MTA_STS_MODE) || "").trim().toLowerCase();
  return Object.hasOwn(MAX_AGE_S, m) ? m : "testing";
}

function policyText(mode) {
  const lines = ["version: STSv1", `mode: ${mode}`, ...MX_HOSTS.map((h) => `mx: ${h}`), `max_age: ${MAX_AGE_S[mode]}`];
  return lines.map((l) => `${l}\r\n`).join("");
}

const NO_STORE = { "cache-control": "no-store", "x-content-type-options": "nosniff" };

function text(body, status, method) {
  return new Response(method === "HEAD" ? null : body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", ...NO_STORE },
  });
}

// ── reading the mail (RFC 2045/2046) ──

class Unreadable extends Error {} // its message is the error kind counted in the summary

// Only the headers the reading uses, each the first of its name: a regex
// over the whole block, not a loop over every line of a huge one.
const PART_HEADERS = {
  "content-type": /^[ \t]*content-type[ \t]*:(.*)$/im,
  "content-transfer-encoding": /^[ \t]*content-transfer-encoding[ \t]*:(.*)$/im,
};

function entity(s) {
  const m = /^\r?\n|\r?\n\r?\n/.exec(s);
  const head = (m ? s.slice(0, m.index) : s).replace(/\r?\n[ \t]+/g, " ");
  const headers = new Map();
  for (const [name, re] of Object.entries(PART_HEADERS)) {
    const h = re.exec(head);
    if (h) headers.set(name, h[1].trim());
  }
  return { headers, body: m ? s.slice(m.index + m[0].length) : "" };
}

function boundaryOf(contentType) {
  const m = /;\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  return m ? m[1] || m[2] : "";
}

// The non-multipart parts, depth first. `budget.parts` counts every part
// looked at, so empty multipart parts cannot make the work unbounded.
function leaves(e, budget, depth = 0, out = []) {
  if (budget.parts <= 0) return out;
  budget.parts--;
  const ct = e.headers.get("content-type") || "text/plain";
  const type = ct.split(";")[0].trim().toLowerCase();
  if (!type.startsWith("multipart/")) {
    out.push({ type, e });
    return out;
  }
  const boundary = boundaryOf(ct);
  if (!boundary || depth >= 4) return out;
  const delimiter = new RegExp(`(?:^|\\r?\\n)--${boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`);
  for (const piece of e.body.split(delimiter, budget.parts + 1).slice(1)) {
    if (piece.startsWith("--") || out.length >= MAX_LEAVES || budget.parts <= 0) break; // the close delimiter
    leaves(entity(piece.replace(/^[ \t]*\r?\n/, "")), budget, depth + 1, out);
  }
  return out;
}

const B64 = new Int8Array(128).fill(-1);
for (const [i, ch] of [..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"].entries()) B64[ch.charCodeAt(0)] = i;

// Base64 straight to bytes in one pass, skipping anything outside the
// alphabet (line breaks, padding) as atob does once those are stripped; a
// regex strip of a junk-filled body costs ~4 ms of CPU.
function base64Bytes(s) {
  const out = new Uint8Array(Math.ceil((s.length * 3) / 4));
  let n = 0;
  let acc = 0;
  let bits = 0;
  let count = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64[c] : -1;
    if (v < 0) continue;
    count++;
    acc = ((acc << 6) | v) & 0xfff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (acc >> bits) & 0xff;
    }
  }
  if (count % 4 === 1) throw new Unreadable("bad base64");
  return out.subarray(0, n);
}

const hexValue = (c) => (c >= 48 && c <= 57 ? c - 48 : (c | 32) >= 97 && (c | 32) <= 102 ? (c | 32) - 87 : -1);

// Quoted-printable straight to bytes, without a callback per "=XX" (that
// costs ~20 ms of CPU on a 256 KB mail). Soft line breaks go first, so an
// "=XX" split by one still decodes; anything not "=" + two hex digits is kept.
function qpBytes(body) {
  const s = body.replace(/=\r?\n/g, "");
  const out = new Uint8Array(s.length);
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 61) {
      const hi = hexValue(s.charCodeAt(i + 1));
      const lo = hexValue(s.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0) {
        out[n++] = hi * 16 + lo;
        i += 2;
        continue;
      }
    }
    out[n++] = c;
  }
  return out.subarray(0, n);
}

function decode(e) {
  const cte = (e.headers.get("content-transfer-encoding") || "").trim().toLowerCase();
  if (cte === "base64") return base64Bytes(e.body);
  if (cte === "quoted-printable") return qpBytes(e.body);
  return new TextEncoder().encode(e.body); // 7bit / 8bit: the JSON as text
}

class TooLarge extends Unreadable {}

// `budget.inflated` is what is left of MAX_JSON_BYTES for the whole mail.
async function gunzip(bytes, budget) {
  const reader = new Response(bytes).body.pipeThrough(new DecompressionStream("gzip")).getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      budget.inflated -= value.length;
      if (budget.inflated < 0) throw new TooLarge("report too large");
      chunks.push(value);
    }
  } catch (err) {
    reader.cancel().catch(() => {});
    throw err instanceof Unreadable ? err : new Unreadable("bad gzip");
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

// Reporter-supplied text: one line, bounded, no invisible or direction-
// changing characters (C1 controls, zero-width, bidi overrides and isolates).
const clean = (v, max = 100) =>
  typeof v === "string"
    ? v
        .replace(/[\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]+/g, "")
        .replace(/[\u0000-\u001f\u007f-\u009f\s]+/g, " ")
        .trim()
        .slice(0, max)
    : "";

const oneOf = (v, set) => {
  const s = clean(v, 64).toLowerCase();
  return set.includes(s) ? s : "other";
};

function mxName(v) {
  if (v === undefined || v === null || v === "") return "?";
  const host = clean(v, 255).toLowerCase().replace(/\.$/, "");
  return MX_HOSTS.includes(host) ? host : "other-host";
}

// A company name ("Google Inc.", "Microsoft Corporation"), or nothing: no
// domain, no URL, no sentence.
function orgName(v) {
  const s = clean(v, 100);
  return /^[A-Za-z0-9][A-Za-z0-9 .,&'()-]{0,47}$/.test(s) && !/[A-Za-z0-9]\.[A-Za-z0-9]/.test(s) ? s : "";
}

function sessions(v) {
  if (v === undefined || v === null) return 0;
  const n = typeof v === "string" && /^\d{1,15}$/.test(v) ? Number(v) : v;
  if (!Number.isSafeInteger(n) || n < 0) throw new Unreadable("bad session count");
  return n;
}

// RFC 8460 §4.4, keeping only what the summary and the alert use.
function parseReport(j) {
  if (!j || typeof j !== "object" || !Array.isArray(j.policies)) throw new Unreadable("not a TLS report");
  const policies = j.policies.slice(0, 50).map((p) => {
    const policy = (p && p.policy) || {};
    const summary = (p && p.summary) || {};
    const details = Array.isArray(p && p["failure-details"]) ? p["failure-details"].slice(0, 50) : [];
    const domain = clean(policy["policy-domain"], 255).toLowerCase().replace(/\.$/, "");
    return {
      name: `${oneOf(policy["policy-type"], POLICY_TYPES)} ${domain === DOMAIN ? DOMAIN : "other-domain"}`,
      successful: sessions(summary["total-successful-session-count"]),
      failed: sessions(summary["total-failure-session-count"]),
      failures: details.map((f) => {
        const reason = clean(f && f["failure-reason-code"], 64);
        return {
          type: oneOf(f && f["result-type"], RESULT_TYPES),
          mx: mxName(f && f["receiving-mx-hostname"]),
          count: sessions(f && f["failed-session-count"]),
          reason: REASON_CODE.test(reason) ? reason : "",
        };
      }),
    };
  });
  const range = j["date-range"] || {};
  const time = (v) => (typeof v === "string" && ISO_TIME.test(v) ? v : "");
  return {
    org: orgName(j["organization-name"]),
    from: time(range["start-datetime"]),
    to: time(range["end-datetime"]),
    policies,
  };
}

async function readPart(leaf, budget) {
  let bytes = decode(leaf.e);
  // By content, not label: some senders call it octet-stream. Not zipped, it
  // is at most MAX_RAW_BYTES.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = await gunzip(bytes, budget);
  let json;
  try {
    json = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Unreadable("bad JSON");
  }
  // A redelivered report is the same JSON byte for byte; a forged one with the
  // same organization and report-id is not, so it cannot shadow the real one.
  return { report: parseReport(json), digest: await shortHash(bytes) };
}

async function readReport(message) {
  if (message.rawSize > MAX_RAW_BYTES) throw new Unreadable("mail too large");
  const raw = new Uint8Array(await new Response(message.raw).arrayBuffer());
  if (raw.length > MAX_RAW_BYTES) throw new Unreadable("mail too large");
  // Mail on the wire is text (SMTP has no binary parts without BINARYMIME):
  // the report is base64 (gzip) or the JSON as 7bit / 8bit UTF-8.
  const budget = { parts: MAX_PARTS, inflated: MAX_JSON_BYTES };
  const all = leaves(entity(new TextDecoder().decode(raw)), budget);
  const candidates = [
    ...all.filter((l) => REPORT_TYPES.includes(l.type)),
    ...all.filter((l) => !REPORT_TYPES.includes(l.type) && !l.type.startsWith("text/")),
  ];
  let first = null;
  for (const leaf of candidates) {
    try {
      return await readPart(leaf, budget);
    } catch (err) {
      first = first || err;
      if (err instanceof TooLarge) break; // the mail's inflate budget is spent
    }
  }
  throw first || new Unreadable("no report in the mail");
}

// The domain of the header From, or "unknown" when there is not exactly one
// plain address. For a KNOWN_REPORTERS domain Email Routing's DMARC check
// vouches for it; for any other domain it is the sender's claim.
function reporterOf(message) {
  const h = message && message.headers && typeof message.headers.get === "function" ? message.headers.get("from") : "";
  const bare = String(h || "").replace(/"(?:[^"\\]|\\.)*"/g, '""');
  if (bare.includes(",")) return "unknown"; // a list, or two From headers joined
  const angle = /<([^<>]*)>\s*$/.exec(bare);
  const m = /^[^\s@<>]+@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)$/.exec((angle ? angle[1] : bare).trim());
  return m && m[1].length <= 100 ? m[1].toLowerCase() : "unknown";
}

// Whose counts, budgets and daily alert a mail uses: a known reporter's own
// (an exact match), or the unverified group's.
const groupOf = (reporter) => (KNOWN_REPORTERS.includes(reporter) ? reporter : UNVERIFIED);

// ── the daily summary ──

// One group's day. `reporters` only for the unverified group: a known
// reporter's entry is that reporter alone.
function emptyDay(day, group) {
  return {
    day, reports: 0, successful: 0, failed: 0, policies: {}, failures: {},
    ...(group === UNVERIFIED && { reporters: {} }),
    covers: [], capped: false, errors: 0, error_kinds: {}, errors_capped: false,
    alert: null, alert_tries: 0, alert_error: null, ids: [],
  };
}

const isDay = (d) => d && typeof d === "object" && typeof d.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d.day);
const oldestShown = (now) => new Date(now - (SHOW_DAYS - 1) * DAY_MS).toISOString().slice(0, 10);

// The stored summaries, newest first; missing or unreadable is none.
function readBook(raw) {
  try {
    const b = JSON.parse(raw);
    if (b && Array.isArray(b.days)) return { days: b.days.filter(isDay) };
  } catch {
    // missing or unreadable: no summaries yet
  }
  return { days: [] };
}

function dayIn(book, day, group) {
  const i = book.days.findIndex((d) => d.day === day);
  if (i < 0) book.days.unshift(emptyDay(day, group));
  else book.days[i] = { ...emptyDay(day, group), ...book.days[i] };
  return book.days[Math.max(i, 0)];
}

const withoutIds = ({ ids: _ids, ...counts }) => counts;

// Names come from reporters: never a prototype key, and a bounded list.
function slot(map, name) {
  return name !== "__proto__" && (Object.hasOwn(map, name) || Object.keys(map).length < MAX_NAMES) ? name : "other";
}

function bump(map, name, n) {
  const k = slot(map, name);
  map[k] = (Object.hasOwn(map, k) ? map[k] : 0) + n;
}

function addReport(s, r, reporter) {
  s.reports++;
  if (s.reporters) bump(s.reporters, reporter, 1);
  const covered = r.from.slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(covered) && !s.covers.includes(covered) && s.covers.length < 10) s.covers.push(covered);
  for (const p of r.policies) {
    s.successful += p.successful;
    s.failed += p.failed;
    const k = slot(s.policies, p.name);
    const was = Object.hasOwn(s.policies, k) ? s.policies[k] : { successful: 0, failed: 0 };
    s.policies[k] = { successful: was.successful + p.successful, failed: was.failed + p.failed };
    for (const f of p.failures) bump(s.failures, `${f.type} ${f.mx}`, f.count);
  }
}

async function shortHash(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...d.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── the alert ──

function rawEmail(to, subject, body) {
  const id = `<${crypto.randomUUID()}@cleanway.ai>`;
  return [
    `From: Cleanway monitor <${FROM}>`,
    `To: ${to}`,
    `Subject: =?UTF-8?B?${btoa(unescape(encodeURIComponent(subject)))}?=`,
    `Message-ID: ${id}`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 8bit",
    "",
    body,
  ].join("\r\n");
}

async function notify(env, subject, body) {
  const msg = new EmailMessage(FROM, env.ALERT_TO, rawEmail(env.ALERT_TO, subject, body));
  await env.ALERT.send(msg);
}

const MX_LABEL = { "?": "MX не указан", "other-host": "другой хост" };

// Only values from closed sets, numbers, and — for a known reporter, whose
// From is vouched for — its domain and plain company name.
function alertBody(r, reporter, known, mode, stamp) {
  const range = r.from && r.to ? ` за ${r.from} – ${r.to}` : "";
  const lines = known
    ? [`Отчёт TLS-RPT от ${reporter}${r.org ? ` (в отчёте назван «${r.org}»)` : ""}${range}, получен ${stamp}.`, ""]
    : [
        `Отчёт TLS-RPT от отправителя не из списка известных (KNOWN_REPORTERS в worker.js)${range}, получен ${stamp}.`,
        "На tls-reports@cleanway.ai может написать кто угодно: это может быть подделка. Его адрес — в сводке: unverified → reporters.",
        "Такие отчёты считаются отдельно от Google и Microsoft и сами по себе не повод откатывать MTA-STS.",
        "",
      ];
  for (const p of r.policies.slice(0, ALERT_POLICIES)) {
    lines.push(`${p.name}: успешных сессий ${p.successful}, неудачных ${p.failed}`);
    for (const f of p.failures.slice(0, ALERT_FAILURES)) {
      lines.push(`  ${f.type}, ${MX_LABEL[f.mx] || f.mx}: ${f.count}${f.reason ? ` (${f.reason})` : ""}`);
    }
    if (p.failures.length > ALERT_FAILURES) lines.push(`  … и ещё ${p.failures.length - ALERT_FAILURES} строк об ошибках`);
  }
  if (r.policies.length > ALERT_POLICIES) lines.push(`… и ещё ${r.policies.length - ALERT_POLICIES} политик (в сводке)`);
  lines.push(
    "",
    mode === "enforce"
      ? "Режим MTA-STS: enforce. Отправители с такими ошибками НЕ доставляют почту на cleanway.ai (повторяют попытки до нескольких дней)."
      : `Режим MTA-STS: ${mode}. Почта пока доставляется и с такими ошибками — это предупреждение перед enforce.`,
    "",
    "Что делать: ops/mail-security-worker/README.md, раздел «When the alert arrives».",
    `Сводка за 30 дней: ${SUMMARY_URL}`,
    known
      ? `Сегодня других писем об отчётах от ${reporter} не будет: они — только в сводке.`
      : "Сегодня других писем об отчётах от неизвестных отправителей не будет: они — только в сводке.",
  );
  return lines.join("\n");
}

// ── handlers ──

// The Workers runtime has scheduler.wait; setTimeout elsewhere.
const pause = (ms) =>
  globalThis.scheduler && typeof globalThis.scheduler.wait === "function"
    ? globalThis.scheduler.wait(ms)
    : new Promise((done) => setTimeout(done, ms));

// Keeps the last SHOW_DAYS days; only today's needs its report digests.
async function save(env, group, book, now) {
  const today = new Date(now).toISOString().slice(0, 10);
  const oldest = oldestShown(now);
  const days = book.days
    .filter((d) => d.day >= oldest)
    .sort((a, b) => (a.day < b.day ? 1 : -1))
    .slice(0, SHOW_DAYS)
    .map((d) => (d.day === today ? d : withoutIds(d)));
  await env.STATE.put(KEY_PREFIX + group, JSON.stringify({ days }), { expirationTtl: (SHOW_DAYS + 1) * 86_400 });
}

// Reads one group's book, lets `change` edit today's entry (false: nothing to
// write) and writes it back. A write that fails (KV allows one a second to a
// key) is redone once, RETRY_MS later, on a fresh read: this mail is not lost
// and the mail that got in first is not overwritten. A second failure throws.
async function update(env, group, now, change) {
  for (let attempt = 1; ; attempt++) {
    const book = readBook(await env.STATE.get(KEY_PREFIX + group));
    if (!change(dayIn(book, new Date(now).toISOString().slice(0, 10), group))) return false;
    try {
      await save(env, group, book, now);
      return true;
    } catch (err) {
      if (attempt >= 2) throw err;
      await pause(RETRY_MS);
    }
  }
}

// KV has no atomic update and its reads can be up to 60 s stale elsewhere, so
// under concurrent delivery within one group the daily caps are best effort.
async function receive(message, env, now) {
  const stamp = new Date(now).toISOString();
  const reporter = reporterOf(message);
  const group = groupOf(reporter);
  const budget = BUDGET[group === UNVERIFIED ? "unverified" : "known"];
  let got;
  try {
    got = await readReport(message);
  } catch (err) {
    const kind = err instanceof Unreadable ? err.message : "unreadable";
    await update(env, group, now, (s) => {
      if (s.errors < budget.errors) {
        s.errors++;
        bump(s.error_kinds, kind, 1);
        return true;
      }
      if (s.errors_capped) return false;
      s.errors_capped = true;
      return true;
    });
    return;
  }
  const { report: r, digest } = got;
  const failed = r.policies.reduce((n, p) => n + p.failed, 0);
  let sends = 0;
  const written = await update(env, group, now, (s) => {
    if (s.ids.includes(digest)) return false; // the same report again: counted once
    let changed = true;
    if (s.reports < budget.reports) {
      s.ids.push(digest);
      addReport(s, r, reporter);
    } else if (!s.capped) {
      s.capped = true;
    } else {
      changed = false; // capped: no longer counted, but it may still owe an alert
    }
    // Claimed before it is sent, with the sends it may use: if this write
    // fails, nothing is sent (the error is logged).
    sends = failed > 0 && !s.alert ? Math.min(SENDS_PER_CLAIM, MAX_ALERT_TRIES - s.alert_tries) : 0;
    if (sends > 0) {
      s.alert = stamp;
      s.alert_tries += sends;
    }
    return changed || sends > 0;
  });
  if (!written || sends <= 0) return;
  const known = group !== UNVERIFIED;
  const subject = `Cleanway: сбои TLS при доставке почты на cleanway.ai (${failed}${known ? "" : ", отправитель не проверен"})`;
  const body = alertBody(r, reporter, known, stsMode(env), stamp);
  let error;
  for (let i = 0; i < sends; i++) {
    if (i > 0) await pause(RETRY_MS);
    try {
      await notify(env, subject, body);
      return;
    } catch (err) {
      error = err;
    }
  }
  // None went out: the claim is undone, and the next failing report of that
  // group tries again while the day's sends last.
  await update(env, group, now, (s) => {
    if (s.alert === stamp) s.alert = null;
    s.alert_error = { at: stamp, error: String((error && error.message) || error).slice(0, 300) };
    return true;
  });
}

// Each day: the known reporters that mailed that day under `verified`, and
// everyone else under `unverified` (zeros when nobody did). Never added up.
async function summaries(env, now) {
  const mode = stsMode(env);
  const oldest = oldestShown(now);
  const books = await Promise.all(GROUPS.map(async (g) => [g, readBook(await env.STATE.get(KEY_PREFIX + g))]));
  const byDay = new Map();
  const entry = (day) => byDay.get(day) || byDay.set(day, { day, verified: {}, unverified: null }).get(day);
  for (const [group, { days }] of books) {
    for (const d of days.filter((x) => x.day >= oldest)) {
      const { day: _day, ...counts } = withoutIds({ ...emptyDay(d.day, group), ...d });
      if (group === UNVERIFIED) entry(d.day).unverified = counts;
      else entry(d.day).verified[group] = counts;
    }
  }
  const none = (day) => {
    const { day: _day, ...counts } = withoutIds(emptyDay(day, UNVERIFIED));
    return counts;
  };
  return {
    policy: { mode, max_age: MAX_AGE_S[mode], mx: MX_HOSTS },
    days: [...byDay.values()]
      .sort((a, b) => (a.day < b.day ? 1 : -1))
      .map((e) => ({ ...e, unverified: e.unverified || none(e.day) })),
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.hostname === POLICY_HOST) {
      const ok = (req.method === "GET" || req.method === "HEAD") && url.pathname === POLICY_PATH;
      return ok ? text(policyText(stsMode(env)), 200, req.method) : text("not found\n", 404, req.method);
    }
    if (url.hostname.endsWith(".workers.dev") && req.method === "GET" && url.pathname === "/") {
      return Response.json(await summaries(env, Date.now()), { headers: NO_STORE });
    }
    return text("not found\n", 404, req.method);
  },

  async email(message, env) {
    try {
      await receive(message, env, Date.now());
    } catch (err) {
      console.error("tls-rpt: report not recorded", String((err && err.message) || err));
    }
  },
};
