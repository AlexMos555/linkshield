// Cleanway backup sink — a Cloudflare Worker with an R2 binding.
//
// The nightly GitHub Actions job (.github/workflows/db-backup.yml) PUTs an
// age-encrypted pg_dump here. There is no long-lived R2 key anywhere: the job
// authenticates with its short-lived GitHub OIDC token, and this Worker only
// accepts tokens minted for this repository's db-backup workflow on main.
//
// Deploy: see ops/backup-sink/README.md.

const ISSUER = "https://token.actions.githubusercontent.com";
const AUDIENCE = "cleanway-backup";
const REPOSITORY = "AlexMos555/linkshield";
const WORKFLOW_REF_PREFIX = "AlexMos555/linkshield/.github/workflows/db-backup.yml@refs/heads/main";
const MAX_BYTES = 200 * 1024 * 1024;
const KEY_RE = /^db\/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z\.dump\.age$/;

let jwksCache = { at: 0, keys: [] };

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function githubKeys(force = false) {
  if (!force && Date.now() - jwksCache.at < 10 * 60_000 && jwksCache.keys.length) return jwksCache.keys;
  const r = await fetch(`${ISSUER}/.well-known/jwks`);
  if (!r.ok) throw new Error(`jwks ${r.status}`);
  jwksCache = { at: Date.now(), keys: (await r.json()).keys || [] };
  return jwksCache.keys;
}

async function verifyOidc(token) {
  const [h, p, s] = token.split(".");
  if (!h || !p || !s) throw new Error("malformed");
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
  if (header.alg !== "RS256") throw new Error("alg");
  let jwk = (await githubKeys()).find((k) => k.kid === header.kid);
  if (!jwk) jwk = (await githubKeys(true)).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("kid");
  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
  );
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(s), new TextEncoder().encode(`${h}.${p}`),
  );
  if (!ok) throw new Error("signature");
  const c = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));
  const now = Math.floor(Date.now() / 1000);
  if (c.iss !== ISSUER) throw new Error("iss");
  if (c.aud !== AUDIENCE) throw new Error("aud");
  if (typeof c.exp !== "number" || c.exp < now) throw new Error("exp");
  if (typeof c.nbf === "number" && c.nbf > now + 60) throw new Error("nbf");
  if (c.repository !== REPOSITORY) throw new Error("repository");
  if (c.ref !== "refs/heads/main") throw new Error("ref");
  if (typeof c.workflow_ref !== "string" || !c.workflow_ref.startsWith(WORKFLOW_REF_PREFIX)) {
    throw new Error("workflow");
  }
  return c;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method !== "PUT" || !url.pathname.startsWith("/upload/")) {
      return new Response("not found", { status: 404 });
    }
    const auth = req.headers.get("authorization") || "";
    if (!auth.startsWith("Bearer ")) return new Response("unauthorized", { status: 401 });
    let claims;
    try {
      claims = await verifyOidc(auth.slice(7));
    } catch (e) {
      return new Response(`forbidden: ${e.message}`, { status: 403 });
    }
    const key = decodeURIComponent(url.pathname.slice("/upload/".length));
    if (!KEY_RE.test(key)) return new Response("bad key", { status: 400 });
    const len = Number(req.headers.get("content-length") || "0");
    if (!len || len > MAX_BYTES) return new Response("bad length", { status: 413 });
    if (await env.BACKUPS.head(key)) return new Response("exists", { status: 409 });
    await env.BACKUPS.put(key, req.body, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { run_id: String(claims.run_id || ""), sha: String(claims.sha || "") },
    });
    return Response.json({ stored: key, bytes: len });
  },
};
