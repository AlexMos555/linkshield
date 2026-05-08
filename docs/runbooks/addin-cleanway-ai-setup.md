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

After the next Vercel deploy, files are live at
`cleanway.ai/outlook/manifest.xml`, `cleanway.ai/outlook/taskpane/...`,
etc. The `addin.` subdomain just needs to be aliased to this same
project.

## DNS + Vercel — what the user does

### 1. Vercel custom domain

- Vercel Dashboard → project **landing** → **Settings → Domains**.
- "Add Domain" → `addin.cleanway.ai` → Add.
- Vercel shows a CNAME target (typically `cname.vercel-dns.com`).
  Note it down.

### 2. DNS (Squarespace)

- Squarespace DNS → Custom Records.
- Add: `Type=CNAME`, `Host=addin`, `Data=cname.vercel-dns.com`,
  `TTL=4 Hrs` (default fine).
- Save.

### 3. Wait for propagation + Vercel's TLS provisioning

- ~5–10 minutes for DNS to propagate.
- Vercel auto-issues a Let's Encrypt cert; status flips
  green ("Valid Configuration") in Domains settings.

### 4. Smoke test

```bash
curl -sI https://addin.cleanway.ai/outlook/manifest.xml
# Expect: HTTP/2 200, content-type: application/xml
```

If 200 — Microsoft AppSource submission is unblocked.

## Sideload-test the plugin (optional, before AppSource)

Outlook on the web → ⚙️ → Get Add-ins → My add-ins → Custom add-ins
→ "Add from URL" → `https://addin.cleanway.ai/outlook/manifest.xml`
→ Install.

The Cleanway ribbon group should appear on the Home tab. Click any
email; "Scan with Cleanway" opens the taskpane.

## Caveats

- **Icons missing.** `email-plugin-outlook/assets/` is empty in the
  current commit. Manifest references `icon-{32,64,128}.png` —
  Microsoft AppSource will reject without them. Add 3 PNG files
  (cleanway green-on-white logo) before submission. For sideload
  testing, missing icons surface as a tiny broken-image but the
  add-in still works.
- **CSP.** If Microsoft AppSource review flags missing
  `Content-Security-Policy` on taskpane.html, add it via Vercel
  `headers()` config in `next.config.ts` for paths matching
  `/outlook/(taskpane|commands)/*.html`.
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
