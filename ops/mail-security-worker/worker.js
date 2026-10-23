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
//     (the day the mail arrived) in KV, kept 90 days, and when a report counts
//     failed sessions it mails the founder — once a day at most: anyone can
//     mail that address, so a flood of forged reports is one mail. The report
//     itself is never forwarded or stored (no IPs, no contact addresses). A
//     mail it cannot read is counted as an error and dropped, never thrown —
//     a thrown error would make the sender retry.
//   * GET / on workers.dev: the policy in force and the last 30 summaries.
//
// Deploy: see ops/mail-security-worker/README.md.

import { EmailMessage } from "cloudflare:email";

const POLICY_HOST = "mta-sts.cleanway.ai";
const POLICY_PATH = "/.well-known/mta-sts.txt";
// The zone's MX records (Cloudflare → Email → Email Routing). Change both
// together, and bump the _mta-sts id after the new policy is live.
const MX_HOSTS = ["route1.mx.cloudflare.net", "route2.mx.cloudflare.net", "route3.mx.cloudflare.net"];
const MAX_AGE_S = { testing: 86_400, enforce: 604_800, none: 86_400 };

const FROM = "alerts@cleanway.ai";
const SUMMARY_URL = "https://cleanway-mail-security.amoskotin.workers.dev/";
const DAY_TTL_S = 90 * 86_400;
const SHOW_DAYS = 30;
// KV writes are 1,000 a day for the whole account on the free plan, shared
// with the uptime monitor; real senders mail a handful of reports a day.
const MAX_MAILS_PER_DAY = 100;
// A report mail is a few KB. Both limits keep one mail well inside the free
// plan's 10 ms of CPU: gunzip stops at MAX_JSON_BYTES (a gzip bomb).
const MAX_RAW_BYTES = 256 * 1024;
const MAX_JSON_BYTES = 256 * 1024;
const MAX_NAMES = 20; // per list in a day summary; the rest is counted as "other"
const REPORT_TYPES = ["application/tlsrpt+gzip", "application/tlsrpt+json"];

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

// Reporter-supplied text: one line, bounded.
const clean = (v, max = 100) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max) : "");

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
    return {
      name: `${clean(policy["policy-type"], 20) || "unknown"} ${clean(policy["policy-domain"]) || "?"}`,
      successful: sessions(summary["total-successful-session-count"]),
      failed: sessions(summary["total-failure-session-count"]),
      failures: details.map((f) => ({
        type: clean(f && f["result-type"], 40) || "unknown",
        mx: clean(f && f["receiving-mx-hostname"]),
        count: sessions(f && f["failed-session-count"]),
        reason: clean(f && f["failure-reason-code"], 200),
      })),
    };
  });
  const range = j["date-range"] || {};
  return {
    org: clean(j["organization-name"]) || "unknown",
    id: clean(j["report-id"], 200),
    from: clean(range["start-datetime"], 30),
    to: clean(range["end-datetime"], 30),
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
  return parseReport(json);
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

// ── the daily summary ──

function emptyDay(day) {
  return {
    day, reports: 0, successful: 0, failed: 0, policies: {}, failures: {}, reporters: {}, covers: [],
    errors: 0, error_kinds: {}, alerted_at: null, alert_error: null, capped: false, ids: [],
  };
}

function readDay(raw, day) {
  try {
    const s = JSON.parse(raw);
    if (s && typeof s === "object" && s.day === day) return { ...emptyDay(day), ...s };
  } catch {
    // missing or unreadable: no summary for that day
  }
  return null;
}

// Names come from reporters: never a prototype key, and a bounded list.
function slot(map, name) {
  return name !== "__proto__" && (Object.hasOwn(map, name) || Object.keys(map).length < MAX_NAMES) ? name : "other";
}

function bump(map, name, n) {
  const k = slot(map, name);
  map[k] = (Object.hasOwn(map, k) ? map[k] : 0) + n;
}

function addReport(s, r) {
  s.reports++;
  bump(s.reporters, r.org, 1);
  const covered = r.from.slice(0, 10);
  if (/^\d{4}-\d{2}-\d{2}$/.test(covered) && !s.covers.includes(covered) && s.covers.length < 10) s.covers.push(covered);
  for (const p of r.policies) {
    s.successful += p.successful;
    s.failed += p.failed;
    const k = slot(s.policies, p.name);
    const was = Object.hasOwn(s.policies, k) ? s.policies[k] : { successful: 0, failed: 0 };
    s.policies[k] = { successful: was.successful + p.successful, failed: was.failed + p.failed };
    for (const f of p.failures) bump(s.failures, `${f.type} ${f.mx || "?"}`, f.count);
  }
}

async function shortHash(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
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

function alertBody(r, mode, stamp) {
  const lines = [`Отчёт TLS-RPT от ${r.org}${r.from ? ` за ${r.from} – ${r.to}` : ""}, получен ${stamp}.`, ""];
  for (const p of r.policies) {
    lines.push(`${p.name}: успешных сессий ${p.successful}, неудачных ${p.failed}`);
    for (const f of p.failures.slice(0, 10)) {
      lines.push(`  ${f.type}, ${f.mx || "MX не указан"}: ${f.count}${f.reason ? ` (${f.reason})` : ""}`);
    }
  }
  lines.push(
    "",
    mode === "enforce"
      ? "Режим MTA-STS: enforce. Отправители с такими ошибками НЕ доставляют почту на cleanway.ai (повторяют попытки до нескольких дней)."
      : `Режим MTA-STS: ${mode}. Почта пока доставляется и с такими ошибками — это предупреждение перед enforce.`,
    "",
    "Что делать: ops/mail-security-worker/README.md, раздел «When the alert arrives».",
    `Сводка за 30 дней: ${SUMMARY_URL}`,
    "Сегодня других писем об этом не будет: следующие отчёты дня — только в сводке.",
  );
  return lines.join("\n");
}

// ── handlers ──

async function save(env, key, s) {
  await env.STATE.put(key, JSON.stringify(s), { expirationTtl: DAY_TTL_S });
}

async function receive(message, env, now) {
  const stamp = new Date(now).toISOString();
  const day = stamp.slice(0, 10);
  const key = `day:${day}`;
  const s = readDay(await env.STATE.get(key), day) || emptyDay(day);
  if (s.reports + s.errors >= MAX_MAILS_PER_DAY) {
    if (s.capped) return;
    s.capped = true;
    return save(env, key, s);
  }
  let r;
  try {
    r = await readReport(message);
  } catch (err) {
    s.errors++;
    bump(s.error_kinds, err instanceof Unreadable ? err.message : "unreadable", 1);
    return save(env, key, s);
  }
  if (r.id) {
    const id = await shortHash(`${r.org}\n${r.id}`);
    if (s.ids.includes(id)) return; // the same report again: counted once
    s.ids.push(id);
  }
  addReport(s, r);
  const failed = r.policies.reduce((n, p) => n + p.failed, 0);
  if (failed > 0 && !s.alerted_at) {
    try {
      await notify(env, `Cleanway: сбои TLS при доставке почты на cleanway.ai (${failed})`, alertBody(r, stsMode(env), stamp));
      s.alerted_at = stamp;
      s.alert_error = null;
    } catch (err) {
      s.alert_error = { at: stamp, error: String((err && err.message) || err).slice(0, 300) }; // the next failing report retries
    }
  }
  return save(env, key, s);
}

async function summaries(env, now) {
  const mode = stsMode(env);
  const days = Array.from({ length: SHOW_DAYS }, (_, i) => new Date(now - i * 86_400_000).toISOString().slice(0, 10));
  const rows = await Promise.all(days.map(async (d) => readDay(await env.STATE.get(`day:${d}`), d)));
  return {
    policy: { mode, max_age: MAX_AGE_S[mode], mx: MX_HOSTS },
    days: rows.filter(Boolean).map(({ ids: _ids, ...counts }) => counts),
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
