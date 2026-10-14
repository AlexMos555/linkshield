// Cleanway uptime monitor — a Cloudflare Worker on a 1-minute cron.
//
// Checks the landing, the API health and a real DNS-over-HTTPS answer. After
// FAIL_THRESHOLD consecutive failures it emails the founder once (Cloudflare
// Email Routing send_email binding, destination must be a verified address),
// and once more when everything is back. State lives in KV and is written only
// when it changes, so the free KV write quota is never an issue.
//
// Deploy: see ops/uptime-worker/README.md.

import { EmailMessage } from "cloudflare:email";

const CHECKS = [
  { name: "landing", url: "https://cleanway.ai/", expect: (r) => r.status === 200 },
  {
    name: "api",
    url: "https://api.cleanway.ai/health",
    expect: async (r) => r.status === 200 && (await r.json()).status === "ok",
  },
  {
    name: "doh",
    // google.com A, RFC 8484 GET wire format (id 0, RD set).
    url: "https://dns.cleanway.ai/dns-query?dns=AAABAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ",
    init: { headers: { accept: "application/dns-message" } },
    expect: async (r) => {
      if (r.status !== 200) return false;
      const b = new Uint8Array(await r.arrayBuffer());
      // RCODE 0 and at least one answer.
      return b.length > 12 && (b[3] & 0x0f) === 0 && ((b[6] << 8) | b[7]) > 0;
    },
  },
];

const FAIL_THRESHOLD = 2;
const TIMEOUT_MS = 10_000;
const FROM = "alerts@cleanway.ai";

async function runCheck(check) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(check.url, { ...(check.init || {}), signal: ctrl.signal, cf: { cacheTtl: 0 } });
    return (await check.expect(r)) ? null : `HTTP ${r.status}`;
  } catch (e) {
    return String(e && e.name === "AbortError" ? "timeout" : e);
  } finally {
    clearTimeout(t);
  }
}

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

export default {
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(tick(env));
  },
  // GET /  → current state (no secrets); handy for a manual look.
  async fetch(_req, env) {
    return Response.json(JSON.parse((await env.STATE.get("state")) || "{}"));
  },
};

async function tick(env) {
  const prev = JSON.parse((await env.STATE.get("state")) || '{"fails":{},"down":[]}');
  const results = await Promise.all(CHECKS.map(async (c) => [c.name, await runCheck(c)]));
  const fails = {};
  for (const [name, err] of results) fails[name] = err ? (prev.fails[name] || 0) + 1 : 0;

  const down = Object.keys(fails).filter((n) => fails[n] >= FAIL_THRESHOLD);
  const newlyDown = down.filter((n) => !prev.down.includes(n));
  const recovered = prev.down.filter((n) => !down.includes(n));
  const errors = Object.fromEntries(results.filter(([, e]) => e));

  const changed =
    JSON.stringify(fails) !== JSON.stringify(prev.fails) || newlyDown.length || recovered.length;
  if (!changed) return;

  if (newlyDown.length) {
    await notify(
      env,
      `Cleanway: не работает ${newlyDown.join(", ")}`,
      `Проверка ${new Date().toISOString()} UTC.\n\n` +
        newlyDown.map((n) => `${n}: ${errors[n] || "ошибка"}`).join("\n") +
        `\n\nПисьмо придёт ещё раз, когда всё восстановится.`,
    );
  }
  if (recovered.length) {
    await notify(
      env,
      `Cleanway: снова работает ${recovered.join(", ")}`,
      `Проверка ${new Date().toISOString()} UTC: ${recovered.join(", ")} отвечает нормально.`,
    );
  }
  await env.STATE.put("state", JSON.stringify({ fails, down, at: new Date().toISOString(), errors }));
}
