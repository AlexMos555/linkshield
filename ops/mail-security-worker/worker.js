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
//     (the day the mail arrived), all 30 days in one KV key, and when a report
//     counts failed sessions it mails the founder. Anyone can mail that
//     address, so: a report is deduplicated by its bytes, not by labels a
//     forger can copy; junk and reports have separate daily budgets; the
//     alert goes once a day per known reporter (Google, Microsoft), plus once
//     for everyone else together; and it repeats only values from closed sets,
//     never the sender's words. The report itself is never forwarded or
//     stored (no IPs, no contact addresses). A mail it cannot read is counted
//     as an error and dropped, never thrown — a thrown error would make the
//     sender retry.
//   * GET / on workers.dev: the policy in force and the last 30 summaries, in
//     one KV read.
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
// Every day's summary sits in this one key, so the public page costs one KV
// read: the free plan's 100,000 reads a day are the whole account's, and the
// uptime monitor reads every minute.
const KEY = "summary";
const SHOW_DAYS = 30;
const DAY_MS = 86_400_000;
// KV writes are 1,000 a day for the whole account on the free plan, shared
// with the uptime monitor (~150). Real senders mail a handful of reports a
// day; these caps hold forged mail to about 130 writes a day.
const MAX_REPORTS_PER_DAY = 100;
const MAX_ERRORS_PER_DAY = 20; // junk mail has its own budget and cannot use up the reports'
const MAX_ALERT_TRIES = 5; // sends attempted a day, failed ones included
// Reporters by the domain of the header From. These publish DMARC p=reject,
// and Email Routing rejects mail that fails the From domain's DMARC policy,
// so a report From them is theirs. Each has an alert a day of its own; all
// other reporters share one, so forgers cannot silence these.
const KNOWN_REPORTERS = ["google.com", "microsoft.com"];
// A report mail is a few KB. Both limits keep one mail well inside the free
// plan's 10 ms of CPU: gunzip stops at MAX_JSON_BYTES (a gzip bomb).
const MAX_RAW_BYTES = 256 * 1024;
const MAX_JSON_BYTES = 256 * 1024;
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

// atob and quoted-printable give one char per byte.
function bytesOf(binary) {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function entity(s) {
  const m = /^\r?\n|\r?\n\r?\n/.exec(s);
  const headers = new Map();
  const head = m ? s.slice(0, m.index) : s;
  for (const line of head.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
    const i = line.indexOf(":");
    const name = line.slice(0, i).trim().toLowerCase();
    if (i > 0 && !headers.has(name)) headers.set(name, line.slice(i + 1).trim());
  }
  return { headers, body: m ? s.slice(m.index + m[0].length) : "" };
}

function boundaryOf(contentType) {
  const m = /;\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType);
  return m ? m[1] || m[2] : "";
}

function leaves(e, depth = 0, out = []) {
  const ct = e.headers.get("content-type") || "text/plain";
  const type = ct.split(";")[0].trim().toLowerCase();
  if (!type.startsWith("multipart/")) {
    out.push({ type, e });
    return out;
  }
  const boundary = boundaryOf(ct);
  if (!boundary || depth >= 4) return out;
  const delimiter = new RegExp(`(?:^|\\r?\\n)--${boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`);
  for (const piece of e.body.split(delimiter).slice(1)) {
    if (piece.startsWith("--") || out.length >= 10) break; // the close delimiter
    leaves(entity(piece.replace(/^[ \t]*\r?\n/, "")), depth + 1, out);
  }
  return out;
}

function decode(e) {
  const cte = (e.headers.get("content-transfer-encoding") || "").trim().toLowerCase();
  if (cte === "base64") {
    try {
      return bytesOf(atob(e.body.replace(/[^A-Za-z0-9+/]/g, "")));
    } catch {
      throw new Unreadable("bad base64");
    }
  }
  if (cte === "quoted-printable") {
    const s = e.body.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    return bytesOf(s);
  }
  return new TextEncoder().encode(e.body); // 7bit / 8bit: the JSON as text
}

async function gunzip(bytes) {
  const reader = new Response(bytes).body.pipeThrough(new DecompressionStream("gzip")).getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_JSON_BYTES) throw new Unreadable("report too large");
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

async function readPart(leaf) {
  let bytes = decode(leaf.e);
  // By content, not label: some senders call it octet-stream. Not zipped, it
  // is at most MAX_RAW_BYTES.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = await gunzip(bytes);
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
  const all = leaves(entity(new TextDecoder().decode(raw)));
  const candidates = [
    ...all.filter((l) => REPORT_TYPES.includes(l.type)),
    ...all.filter((l) => !REPORT_TYPES.includes(l.type) && !l.type.startsWith("text/")),
  ];
  let first = null;
  for (const leaf of candidates) {
    try {
      return await readPart(leaf);
    } catch (err) {
      first = first || err;
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

// Whose daily alert a report would use: a known reporter's own, or "other".
const alertKeyOf = (reporter) => KNOWN_REPORTERS.find((k) => reporter === k || reporter.endsWith(`.${k}`)) || "other";

// ── the daily summary ──

function emptyDay(day) {
  return {
    day, reports: 0, successful: 0, failed: 0, policies: {}, failures: {}, reporters: {}, covers: [],
    errors: 0, error_kinds: {}, errors_capped: false, capped: false,
    alerts: {}, alert_tries: 0, alert_error: null, ids: [],
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

function dayIn(book, day) {
  const i = book.days.findIndex((d) => d.day === day);
  if (i < 0) book.days.unshift(emptyDay(day));
  else book.days[i] = { ...emptyDay(day), ...book.days[i] };
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
  bump(s.reporters, reporter, 1);
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
        "На tls-reports@cleanway.ai может написать кто угодно: это может быть подделка. Его адрес — в сводке, поле reporters.",
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

// Keeps the last SHOW_DAYS days; only today's needs its report digests.
async function save(env, book, now) {
  const today = new Date(now).toISOString().slice(0, 10);
  const oldest = oldestShown(now);
  const days = book.days
    .filter((d) => d.day >= oldest)
    .sort((a, b) => (a.day < b.day ? 1 : -1))
    .slice(0, SHOW_DAYS)
    .map((d) => (d.day === today ? d : withoutIds(d)));
  await env.STATE.put(KEY, JSON.stringify({ days }), { expirationTtl: (SHOW_DAYS + 1) * 86_400 });
}

// KV has no atomic update and its reads can be up to 60 s stale elsewhere, so
// under concurrent delivery the daily caps are best effort.
async function receive(message, env, now) {
  const stamp = new Date(now).toISOString();
  const book = readBook(await env.STATE.get(KEY));
  const s = dayIn(book, stamp.slice(0, 10));
  let got;
  try {
    got = await readReport(message);
  } catch (err) {
    if (s.errors >= MAX_ERRORS_PER_DAY) {
      if (s.errors_capped) return;
      s.errors_capped = true;
    } else {
      s.errors++;
      bump(s.error_kinds, err instanceof Unreadable ? err.message : "unreadable", 1);
    }
    return save(env, book, now);
  }
  const { report: r, digest } = got;
  if (s.ids.includes(digest)) return; // the same report again: counted once
  const reporter = reporterOf(message);
  let changed = true;
  if (s.reports < MAX_REPORTS_PER_DAY) {
    s.ids.push(digest);
    addReport(s, r, reporter);
  } else if (!s.capped) {
    s.capped = true;
  } else {
    changed = false; // capped: no longer counted, but it may still owe an alert
  }
  const failed = r.policies.reduce((n, p) => n + p.failed, 0);
  const alertKey = alertKeyOf(reporter);
  const owed = failed > 0 && !Object.hasOwn(s.alerts, alertKey) && s.alert_tries < MAX_ALERT_TRIES;
  if (!changed && !owed) return;
  if (owed) {
    s.alerts[alertKey] = stamp;
    s.alert_tries++;
  }
  // Claimed before it is sent: if this write fails, nothing is sent (the
  // error is logged) and the next failing report tries again.
  await save(env, book, now);
  if (!owed) return;
  try {
    const body = alertBody(r, reporter, alertKey !== "other", stsMode(env), stamp);
    await notify(env, `Cleanway: сбои TLS при доставке почты на cleanway.ai (${failed})`, body);
  } catch (err) {
    delete s.alerts[alertKey]; // the next failing report under that key retries
    s.alert_error = { at: stamp, error: String((err && err.message) || err).slice(0, 300) };
    await save(env, book, now);
  }
}

async function summaries(env, now) {
  const mode = stsMode(env);
  const oldest = oldestShown(now);
  const { days } = readBook(await env.STATE.get(KEY));
  return {
    policy: { mode, max_age: MAX_AGE_S[mode], mx: MX_HOSTS },
    days: days.filter((d) => d.day >= oldest).map(withoutIds),
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
