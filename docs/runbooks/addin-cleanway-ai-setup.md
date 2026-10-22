# Outlook plugin hosting on `addin.cleanway.ai`

The Outlook add-in's `manifest.xml` references absolute URLs under
`https://addin.cleanway.ai/outlook/…` (taskpane, commands, icon assets).
Microsoft validates these are reachable at submit time and Outlook
clients fetch them at runtime, so the subdomain has to resolve to a
TLS endpoint serving those files.

We host the plugin **on the same Vercel project as the marketing
landing**, with `addin.cleanway.ai` added as a domain alias. The
plugin's source stays in `email-plugin-outlook/`; a build-time script
copies it into `landing/public/outlook/` so Vercel's static-asset
pipeline picks it up automatically. No reverse proxy, no rewrites, no
separate Vercel project.

## Architecture

```
email-plugin-outlook/                ← single source of truth
├── manifest.xml
├── taskpane/{taskpane.html,css,js}
├── commands/{commands.html,js}
└── assets/{icon-32.png,icon-64.png,icon-128.png}    ← TODO

scripts/sync-addin.cjs               ← runs as `prebuild` in landing/
                                       wipes-and-replaces:
                                          ↓
landing/public/outlook/              ← gitignored build artifact

Vercel landing project serves        ← any domain pointed at it sees
  /outlook/* on every alias domain     `landing/public/outlook/*`
                                       at the same path
```

## What's already done in code

- `scripts/sync-addin.cjs` — copies `email-plugin-outlook/*` into
  `landing/public/outlook/*` excluding `README.md` and macOS junk.
- `landing/package.json` — `"prebuild": "node ../scripts/sync-addin.cjs"`
  fires on every `next build` (including Vercel's CI build).
- `landing/.gitignore` — excludes `public/outlook/` so the artifact
  doesn't pollute git history.
- `landing/next.config.ts` (2026-10-22) — `/outlook/*` gets its own
  headers: a CSP that lets `https://appsforoffice.microsoft.com` serve
  office.js, `connect-src` only to `api.cleanway.ai`, `frame-ancestors`
  only Outlook's web hosts (outlook.office.com, outlook.office365.com,
  outlook.live.com, outlook.cloud.microsoft, *.office.com,
  *.office365.com, *.officeapps.live.com, *.cloud.microsoft), and no
  `X-Frame-Options`. Before this the site-wide policy (frame-ancestors
  'none', X-Frame-Options DENY, no Microsoft script host) stopped the
  add-in from starting at all. Every other path keeps the site policy.
  On the `addin.cleanway.ai` host, anything outside `/outlook/` redirects
  (308) to `https://cleanway.ai/…`, so the alias is not a second copy of
  the site. Pinned by `landing/e2e/outlook-addin.spec.ts`.
- `api/config.py` — `https://addin.cleanway.ai` is in the default CORS
  list (the task pane calls `/api/v1/email/analyze` and
  `/api/v1/feedback/report` from that origin; a preflight from it used to
  answer 400). Pinned by `tests/test_outlook_addin.py`.

After the next Vercel deploy, files are live at
`cleanway.ai/outlook/manifest.xml`, `cleanway.ai/outlook/taskpane/...`,
etc. The `addin.` subdomain just needs to be aliased to this same
project — the only part that is not code.

## DNS + Vercel + Railway — what the founder does

As of 2026-10-22 `dig addin.cleanway.ai @1.1.1.1` returns only the SOA:
there is no record, so Outlook cannot load the manifest's URLs.

### 1. Vercel custom domain

- Vercel Dashboard → project **landing** → **Settings → Domains**.
- "Add Domain" → `addin.cleanway.ai` → Add.
- Vercel shows a CNAME target (typically `cname.vercel-dns.com`).
  Note it down.

### 2. DNS (Cloudflare)

- Cloudflare dashboard → cleanway.ai → DNS → Records (the zone moved from
  Squarespace to Cloudflare in 2026-10). Proxy status: DNS only.
- Add: `Type=CNAME`, `Name=addin`, `Target=` the value Vercel showed in
  step 1 (typically `cname.vercel-dns.com`), proxy status **DNS only**
  (grey cloud — Vercel issues the certificate itself), TTL Auto.
- Save. The zone's CAA records already allow Let's Encrypt, which Vercel
  uses.

### 3. Wait for propagation + Vercel's TLS provisioning

- ~5–10 minutes for DNS to propagate.
- Vercel auto-issues a Let's Encrypt cert; status flips
  green ("Valid Configuration") in Domains settings.

### 4. Railway: only if `ALLOWED_ORIGINS` is set

The API's default origin list now includes `https://addin.cleanway.ai`.
If the Railway service has its own `ALLOWED_ORIGINS` variable, it replaces
the default — append `,https://addin.cleanway.ai` to it and redeploy.

### 5. Smoke test

```bash
curl -sI https://addin.cleanway.ai/outlook/manifest.xml
# Expect: HTTP/2 200, content-type: application/xml

curl -sI https://addin.cleanway.ai/outlook/taskpane/taskpane.html | grep -i -E 'content-security|x-frame'
# Expect: a CSP with appsforoffice.microsoft.com and frame-ancestors
# listing outlook.office.com …; no x-frame-options line.

curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS \
  -H 'Origin: https://addin.cleanway.ai' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  https://api.cleanway.ai/api/v1/email/analyze
# Expect: 200 (it was 400 before the API change)
```

If all three pass — sideload-test, then the AppSource submission.

## Sideload-test the plugin (optional, before AppSource)

Outlook on the web → ⚙️ → Get Add-ins → My add-ins → Custom add-ins
→ "Add from URL" → `https://addin.cleanway.ai/outlook/manifest.xml`
→ Install.

The Cleanway ribbon group should appear on the Home tab. Click any
email; "Scan with Cleanway" opens the taskpane.

While the pane is open, check its console (Outlook on the web: F12, pick
the add-in's frame) for `Content-Security-Policy` violations. office.js
has no published list of the hosts it needs; if it reports a blocked
Microsoft host (a script, a connection, or a frame-ancestor), add that
exact host to the `/outlook/*` policy in `landing/next.config.ts`.

## Caveats

- **Icons.** `email-plugin-outlook/assets/` now carries icon-16/32/64/80/128
  (every size the manifest names; `tests/test_outlook_addin.py` fails if a
  manifest URL points at a missing file). AppSource may still ask for a
  sharper 128 px logo.
- **What it sends.** A scan sends the open email's sender, reply-to,
  subject, text, HTML and SPF/DKIM/DMARC results to the API, which checks
  it in memory and stores nothing; a report sends only the sender's
  domain (kept 1 year in `feedback_reports`). The manifest's descriptions
  and the privacy policy (section 8 and 15) say exactly this — change all
  three together.
- **manifest.xml is also served.** That's intentional — sideload
  testing references it. AppSource submission uploads the file
  separately, so the public copy doesn't actually drive the
  production install.
- **Build coupling.** A bug in `landing/` that breaks `next build`
  also breaks the addin host. Acceptable for Phase E5; if it
  becomes a problem we split into a separate Vercel project (which
  is a 5-minute change: remove the `prebuild` hook, create a new
  Vercel project pointing at `email-plugin-outlook/`, point the
  same CNAME at it). Nothing else needs to migrate.

## Migration plan if we ever split the projects

1. Create new Vercel project `cleanway-outlook-addin` with project
   root = `email-plugin-outlook/`, framework preset = "Other"
   (or static).
2. In the new project: Settings → Domains → add `addin.cleanway.ai`.
   Vercel transfers the alias automatically (it can only be on one
   project at a time).
3. Remove `prebuild` from `landing/package.json`. Drop the script
   `sync-addin.cjs` from prebuild references (can leave the file
   for any future use).
4. Delete `landing/public/outlook/` entry from `.gitignore`.

No code changes needed in `email-plugin-outlook/` itself.
