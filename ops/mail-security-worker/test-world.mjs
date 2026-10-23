// The test world for the mail-security Worker: worker.js loaded in Node with
// KV, the email binding and the incoming message stubbed, and TLS reports as
// senders mail them. Used by worker.test.mjs and forged.test.mjs.
import { register } from "node:module";
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
export const worker = (await import("./worker.js")).default;

export const DAY = 86_400_000;
export const T0 = Date.parse("2026-10-23T09:00:00Z");
export const POLICY_URL = "https://mta-sts.cleanway.ai/.well-known/mta-sts.txt";
export const DASH_URL = "https://cleanway-mail-security.amoskotin.workers.dev/";

// ── a TLS report as Google mails it (RFC 8460 §5.3) ──

export function report({ org = "Google Inc.", id = "2026-10-22T00:00:00Z_cleanway.ai", ok = 1200, failed = 0, details } = {}) {
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

export const MISMATCH = {
  "result-type": "certificate-host-mismatch",
  "sending-mta-ip": "209.85.220.41",
  "receiving-mx-hostname": "route2.mx.cloudflare.net",
  "receiving-ip": "104.30.0.1",
  "failed-session-count": 3,
  "failure-reason-code": "X509_V_ERR_HOSTNAME_MISMATCH",
};

const BOUNDARY = "000000000000c7c1a40615c0e1f2";

export const GOOGLE = "noreply-smtp-tls-reporting@google.com";

export function mail(
  attachment,
  { type = "application/tlsrpt+gzip", encoding = "base64", eol = "\r\n", boundary = BOUNDARY, from = GOOGLE } = {},
) {
  const body = encoding === "base64" ? Buffer.from(attachment).toString("base64").replace(/.{76}/g, "$&\n") : String(attachment);
  const file = "google.com!cleanway.ai!1792627200!1792713599!001.json.gz";
  return [
    "Received: from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69])",
    ...[from].flat().map((f) => `From: ${f}`),
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

export const gz = (r) => gzipSync(Buffer.from(JSON.stringify(r)));

// ── world ──

export function world() {
  const w = {
    kv: new Map(), gets: 0, puts: [], putFails: 0, sent: [], tries: 0, sendFails: 0, now: T0, rejected: [], forwarded: [],
    waits: [],
  };
  Date.now = () => w.now;
  // The Workers runtime's scheduler.wait, recorded instead of waited for.
  globalThis.scheduler = {
    wait: async (ms) => {
      w.waits.push(ms);
    },
  };
  w.env = (extra = {}) => ({
    ALERT_TO: "founder@example.com",
    STATE: {
      get: async (k) => {
        w.gets++;
        return w.kv.get(k) ?? null;
      },
      put: async (k, v, opts) => {
        if (w.putFails > 0) {
          w.putFails--;
          throw new Error("KV PUT failed: 429 Too Many Requests");
        }
        w.puts.push({ k, opts });
        w.kv.set(k, v);
      },
    },
    ALERT: {
      send: async (msg) => {
        w.tries++;
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
      from: "bounce@scoutcamp.bounces.google.com",
      to: "tls-reports@cleanway.ai",
      headers: headersOf(bytes),
      raw: new Response(bytes).body,
      rawSize: bytes.length,
      setReject: (r) => w.rejected.push(r),
      forward: async (to) => w.forwarded.push(to),
      reply: async () => w.forwarded.push("reply"),
    };
    w.message = message;
    await worker.email(message, env, { waitUntil() {} });
  };
  // One reporter's entry for a day, as stored: "google.com", "microsoft.com"
  // or "unverified" (everyone else), each in its own KV key.
  w.day = (d = "2026-10-23", group = "google.com") =>
    JSON.parse(w.kv.get(`summary:${group}`) || '{"days":[]}').days.find((x) => x.day === d) ?? null;
  w.page = async (env = w.env()) => (await get(DASH_URL, env)).json();
  w.subjects = () => w.sent.map((m) => decodeSubject(m.raw));
  return w;
}

// The message's own header block, unfolded, as message.headers carries it.
function headersOf(bytes) {
  const text = Buffer.from(bytes).toString("latin1");
  const end = text.search(/\r?\n\r?\n/);
  const h = new Headers();
  for (const line of (end < 0 ? text : text.slice(0, end)).replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    try {
      h.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
    } catch {
      // not a valid header name: the runtime would not carry it either
    }
  }
  return h;
}

export function decodeSubject(raw) {
  const b64 = raw.match(/^Subject: =\?UTF-8\?B\?(.+)\?=$/m)[1];
  return Buffer.from(b64, "base64").toString("utf8");
}

export const get = (url, env, method = "GET") => worker.fetch(new Request(url, { method }), env);
