// Cleanway uptime monitor — a Cloudflare Worker on a 1-minute cron.
//
// Watches what users depend on, from outside Railway and Vercel:
//   * the landing and the page people install from;
//   * the API end to end — /health/deep, which pages on Redis and Supabase
//     (/health is always 200 and turned "degraded" whenever a third-party
//     threat-intel breaker opened, which says nothing about users);
//   * each protection warning /health/deep raises, as its own check, so one
//     warning that stays red never hides the next: the list phones sync, the
//     gateway's block decision, the Supabase server key;
//   * the public DNS path both ways: a real name resolves, and the list canary
//     gets OUR NXDOMAIN (SOA blocked.cleanway.ai) — not upstream's;
//   * optionally the age of the newest nightly backup (R2 binding BACKUPS).
//
// After FAIL_THRESHOLD consecutive failures it emails the founder once
// (Cloudflare Email Routing send_email binding, destination must be a verified
// address), and once more when the check is back. A send that fails is
// retried the next minute and recorded as `alert_error` until a mail goes
// out or none is owed any more. State lives in KV,
// written on change and at least every HEARTBEAT_MS; GET / shows it, and the
// DNS canary (scripts/dns_canary.py) fails when the heartbeat is stale, so a
// dead monitor is noticed too.
//
// Deploy: see ops/uptime-worker/README.md.

import { EmailMessage } from "cloudflare:email";

const DEEP_URL = "https://api.cleanway.ai/health/deep";
const DOH_URL = "https://dns.cleanway.ai/dns-query";
const BLOCK_SOA_MNAME = "blocked.cleanway.ai"; // api/services/dns_wire.py
const LIST_CANARY = "list-canary.cleanway.ai"; // api/services/blocklist_artifact.py
const KNOWN_WARNINGS = ["blocklist", "doh", "supabase_server_key"];

const FAIL_THRESHOLD = 2;
const TIMEOUT_MS = 10_000;
const HEARTBEAT_MS = 10 * 60_000;
const BACKUP_MAX_AGE_H = 30; // nightly cron, which GitHub starts up to ~5 h late
const FROM = "alerts@cleanway.ai";
const SKIP = Symbol("skip"); // nothing to judge this minute: keep the last count

// ── DNS wire format (RFC 1035 / 8484) ──

function dnsQuery(name) {
  const labels = [];
  for (const label of name.split(".")) labels.push(label.length, ...new TextEncoder().encode(label));
  const bytes = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, 1, 0, 1]; // id 0, RD, A IN
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function readName(b, pos) {
  const labels = [];
  let after = -1;
  for (let hops = 0; hops < 128; hops++) {
    if (pos >= b.length) throw new Error("DNS name runs past the end");
    const len = b[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= b.length) throw new Error("truncated DNS name pointer");
      if (after < 0) after = pos + 2;
      pos = ((len & 0x3f) << 8) | b[pos + 1];
      continue;
    }
    if (len === 0) return [labels.join(".").toLowerCase(), after < 0 ? pos + 1 : after];
    labels.push(String.fromCharCode(...b.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  throw new Error("DNS name loop");
}

function parseDns(b) {
  if (b.length < 12) throw new Error(`short DNS answer (${b.length} bytes)`);
  const u16 = (i) => {
    if (i + 1 >= b.length) throw new Error("truncated DNS answer");
    return (b[i] << 8) | b[i + 1];
  };
  const [qd, an, ns] = [u16(4), u16(6), u16(8)];
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(b, pos)[1] + 4; // QTYPE + QCLASS
  for (let i = 0; i < an; i++) {
    pos = readName(b, pos)[1];
    pos += 10 + u16(pos + 8); // TYPE CLASS TTL RDLENGTH + RDATA
  }
  let soa = null;
  for (let i = 0; i < ns; i++) {
    pos = readName(b, pos)[1];
    if (u16(pos) === 6 && soa === null) soa = readName(b, pos + 10)[0];
    pos += 10 + u16(pos + 8);
  }
  return { rcode: b[3] & 0x0f, answers: an, soa };
}

// ── probes ──

async function fetchOnce(url, init = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(url, { ...init, signal: ctrl.signal, cf: { cacheTtl: 0 } });
    return { status: r.status, body: new Uint8Array(await r.arrayBuffer()) };
  } finally {
    clearTimeout(t);
  }
}

// One request per URL per run: the api check and the warning checks share
// the same /health/deep answer.
function fetcher() {
  const seen = new Map();
  return (url, init) => {
    if (!seen.has(url)) seen.set(url, fetchOnce(url, init));
    return seen.get(url);
  };
}

async function readDeep(get) {
  try {
    const r = await get(DEEP_URL);
    return { status: r.status, json: JSON.parse(new TextDecoder().decode(r.body)) };
  } catch {
    return null;
  }
}

const page = (url) => async (get) => {
  const r = await get(url);
  return r.status === 200 ? null : `HTTP ${r.status}`;
};

const doh = (name, judge) => async (get) => {
  const r = await get(`${DOH_URL}?dns=${dnsQuery(name)}`, { headers: { accept: "application/dns-message" } });
  return r.status === 200 ? judge(parseDns(r.body)) : `HTTP ${r.status}`;
};

function warningCheck(name, warning, help) {
  return {
    name,
    help,
    run: async (get) => {
      const deep = await readDeep(get);
      if (!deep || !Array.isArray(deep.json.warnings)) return SKIP; // the api check speaks
      if (!deep.json.warnings.includes(warning)) return null;
      const c = (deep.json.components || {})[warning] || {};
      return `${warning}: ${c.error || (c.status ? `HTTP ${c.status}` : "not ok")}`;
    },
  };
}

async function newestBackupMs(bucket) {
  let cursor;
  let newest = 0;
  for (let i = 0; i < 5; i++) {
    const res = await bucket.list({ prefix: "db/", cursor, limit: 1000 });
    for (const o of res.objects) newest = Math.max(newest, new Date(o.uploaded).getTime());
    if (!res.truncated) break;
    cursor = res.cursor;
  }
  return newest;
}

const CHECKS = [
  { name: "landing", help: "cleanway.ai не открывается (Vercel).", run: page("https://cleanway.ai/") },
  {
    name: "install_page",
    help: "Страница установки cleanway.ai/ru/android не открывается.",
    run: page("https://cleanway.ai/ru/android"),
  },
  {
    name: "api",
    help: "API не отвечает или не видит Redis / Supabase (/health/deep).",
    run: async (get) => {
      const r = await get(DEEP_URL);
      let body;
      try {
        body = JSON.parse(new TextDecoder().decode(r.body));
      } catch {
        return `HTTP ${r.status}, body is not JSON`;
      }
      if (r.status === 200 && body.status === "ok") return null;
      const failing = ["redis", "supabase"].filter((n) => !((body.components || {})[n] || {}).ok);
      return `HTTP ${r.status}, status=${body.status}` + (failing.length ? `, failing: ${failing.join(", ")}` : "");
    },
  },
  warningCheck("blocklist", "blocklist",
    "Список опасных сайтов для телефонов устарел или пуст: проверьте workflow Refresh dangerous domains."),
  warningCheck("dns_filter", "doh",
    "DNS-фильтр не блокирует: набор dangerous_domains истёк или Redis недоступен."),
  warningCheck("server_key", "supabase_server_key",
    "Серверный ключ Supabase не работает: удаление аккаунтов и записи сервера падают."),
  {
    name: "warnings_other",
    help: "В /health/deep появилось предупреждение, которого монитор не знает: посмотрите warnings.",
    run: async (get) => {
      const deep = await readDeep(get);
      if (!deep || !Array.isArray(deep.json.warnings)) return SKIP;
      const unknown = deep.json.warnings.filter((w) => !KNOWN_WARNINGS.includes(w));
      return unknown.length ? `warnings: ${unknown.join(", ")}` : null;
    },
  },
  {
    name: "doh_resolve",
    help: "dns.cleanway.ai не отвечает на обычные запросы: у iPhone с DNS-защитой не открываются сайты.",
    // google.com must resolve: RCODE 0 and at least one answer.
    run: doh("google.com", (a) => (a.rcode === 0 && a.answers > 0 ? null : `rcode ${a.rcode}, ${a.answers} answers`)),
  },
  {
    name: "doh_block",
    help: "dns.cleanway.ai не блокирует проверочное имя из списка: DNS-защита не работает.",
    run: doh(LIST_CANARY, (a) =>
      a.rcode === 3 && a.soa === BLOCK_SOA_MNAME ? null : `rcode ${a.rcode}, soa ${a.soa || "none"} (not our block)`),
  },
  {
    name: "backup",
    help: `Ночной резервной копии базы больше ${BACKUP_MAX_AGE_H} ч: проверьте workflow DB backup (docs/runbooks/restore.md).`,
    enabled: (env) => Boolean(env.BACKUPS),
    run: async (_get, env, now) => {
      const newest = await newestBackupMs(env.BACKUPS);
      if (!newest) return "no object under db/ in R2";
      const ageH = (now - newest) / 3_600_000;
      return ageH > BACKUP_MAX_AGE_H ? `newest backup is ${ageH.toFixed(1)} h old` : null;
    },
  },
];

async function runCheck(check, get, env, now) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { name: "AbortError" })), TIMEOUT_MS + 2_000);
  });
  try {
    return await Promise.race([check.run(get, env, now), timeout]);
  } catch (e) {
    return e && e.name === "AbortError" ? "timeout" : String((e && e.message) || e);
  } finally {
    clearTimeout(timer);
  }
}

// ── alerts ──

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

const HELP = Object.fromEntries(CHECKS.map((c) => [c.name, c.help]));

function readState(raw) {
  let s = {};
  try {
    s = JSON.parse(raw || "{}") || {};
  } catch {
    s = {};
  }
  return { fails: s.fails || {}, down: s.down || [], heartbeat_at: s.heartbeat_at || null, alert_error: s.alert_error || null };
}

async function tick(env, now = Date.now()) {
  const prev = readState(await env.STATE.get("state"));
  const get = fetcher();
  const checks = CHECKS.filter((c) => !c.enabled || c.enabled(env));
  const results = await Promise.all(checks.map(async (c) => [c.name, await runCheck(c, get, env, now)]));

  const fails = {};
  const errors = {};
  for (const [name, err] of results) {
    if (err === SKIP) {
      if (name in prev.fails) fails[name] = prev.fails[name];
      continue;
    }
    // Capped, so a long outage does not rewrite KV every minute.
    fails[name] = err ? Math.min((prev.fails[name] || 0) + 1, FAIL_THRESHOLD) : 0;
    if (err) errors[name] = err;
  }
  const failing = Object.keys(fails).filter((n) => fails[n] >= FAIL_THRESHOLD);
  let down = prev.down.filter((n) => n in fails); // what the founder was told is down
  const newlyDown = failing.filter((n) => !down.includes(n));
  const recovered = down.filter((n) => !failing.includes(n));
  const stamp = new Date(now).toISOString();
  let sendError = null;

  if (newlyDown.length) {
    try {
      await notify(
        env,
        `Cleanway: не работает ${newlyDown.join(", ")}`,
        `Проверка ${stamp} UTC.\n\n` +
          newlyDown.map((n) => `${n}: ${errors[n] || "ошибка"}\n  ${HELP[n] || ""}`).join("\n\n") +
          `\n\nЧто делать: docs/runbooks/monitoring.md. Письмо придёт ещё раз, когда всё восстановится.`,
      );
      down = [...down, ...newlyDown];
    } catch (e) {
      sendError = String((e && e.message) || e); // not marked as told: retried next minute
    }
  }
  if (recovered.length) {
    try {
      await notify(
        env,
        `Cleanway: снова работает ${recovered.join(", ")}`,
        `Проверка ${stamp} UTC: ${recovered.join(", ")} отвечает нормально.`,
      );
      down = down.filter((n) => !recovered.includes(n));
    } catch (e) {
      sendError = sendError || String((e && e.message) || e);
    }
  }
  // No send was tried this minute only when no mail is owed (down matches
  // failing), so an earlier send error is history: kept, it would leave the
  // DNS canary red after a check that recovered before anyone was told.
  const alertError = sendError ? { at: stamp, error: sendError.slice(0, 300) } : null;

  const heartbeatDue = !prev.heartbeat_at || now - Date.parse(prev.heartbeat_at) >= HEARTBEAT_MS;
  const changed =
    JSON.stringify(fails) !== JSON.stringify(prev.fails) ||
    JSON.stringify(down) !== JSON.stringify(prev.down) ||
    JSON.stringify(alertError) !== JSON.stringify(prev.alert_error);
  if (!changed && !heartbeatDue) return;
  try {
    await env.STATE.put(
      "state",
      JSON.stringify({ fails, down, errors, at: stamp, heartbeat_at: stamp, alert_error: alertError }),
    );
  } catch (e) {
    console.error("state write failed", String(e));
  }
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(tick(env, (event && event.scheduledTime) || Date.now()));
  },
  // GET /  → current state (no secrets); read by the DNS canary as a heartbeat.
  async fetch(_req, env) {
    return Response.json(JSON.parse((await env.STATE.get("state")) || "{}"), {
      headers: { "cache-control": "no-store" },
    });
  },
};
