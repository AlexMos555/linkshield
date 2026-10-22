# Outlook add-in hosting on `cleanway.ai/outlook/`

The Outlook add-in's `manifest.xml` references absolute URLs under
`https://cleanway.ai/outlook/…` (taskpane, commands, icon assets).
Microsoft validates these are reachable at submit time and Outlook
clients fetch them at runtime.

We host the add-in **inside the marketing landing**, on the site's own
host. Its source stays in `email-plugin-outlook/`; a build-time script
copies it into `landing/public/outlook/` so Vercel's static-asset
pipeline picks it up automatically. No reverse proxy, no rewrites, no
separate Vercel project, no extra domain.

Until 2026-10-22 the manifest named `addin.cleanway.ai`, meant as an alias
of the landing project. That host never got a DNS record, so the add-in
could not load; it would also have needed a Vercel alias and its own CORS
entry on the API. The same files were already live at
`cleanway.ai/outlook/` and that origin is already allowed by the API, so
the manifest now points there. A separate origin would not have isolated
anything that matters: inside Outlook on the web the pane is a third-party
frame whose storage the browser partitions anyway, and the pages read no
site cookies or storage.

## Architecture

```
email-plugin-outlook/                ← single source of truth
├── manifest.xml
├── taskpane/{taskpane.html,css,js}
├── commands/{commands.html,js}
└── assets/{icon-16,32,64,80,128}.png

scripts/sync-addin.cjs               ← runs as `prebuild` in landing/
                                       wipes-and-replaces:
                                          ↓
landing/public/outlook/              ← gitignored build artifact

Vercel landing project serves        ← https://cleanway.ai/outlook/*
  `landing/public/outlook/*`           (a path with a dot skips the
                                       locale middleware)
```

## What's done in code

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
  Pinned by `landing/e2e/outlook-addin.spec.ts`, which also requests
  every URL the manifest names and expects a 200 without a redirect.
- `email-plugin-outlook/manifest.xml` — every URL is on
  `https://cleanway.ai/outlook/`; `tests/test_outlook_addin.py` fails on
  any other host or on a URL whose file is missing from the folder.
- `api/config.py` — nothing to add: the task pane calls
  `/api/v1/email/analyze` and `/api/v1/feedback/report` from
  `https://cleanway.ai`, which is in the default CORS list (and must stay
  in any `ALLOWED_ORIGINS` override on Railway, as it already must for
  the site itself).

There is no manual hosting step: the landing deploy from `main` publishes
the files and their headers.

## Smoke test after the landing deploy

```bash
curl -sI https://cleanway.ai/outlook/manifest.xml
# Expect: HTTP/2 200, content-type: application/xml

curl -sI https://cleanway.ai/outlook/taskpane/taskpane.html | grep -i -E 'content-security|x-frame'
# Expect: a CSP with appsforoffice.microsoft.com and frame-ancestors
# listing outlook.office.com …; no x-frame-options line.

curl -sI https://cleanway.ai/ | grep -i -E 'x-frame|frame-ancestors'
# Expect: x-frame-options: DENY and frame-ancestors 'none' — the rest of
# the site still refuses to be framed.

curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS \
  -H 'Origin: https://cleanway.ai' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type' \
  https://api.cleanway.ai/api/v1/email/analyze
# Expect: 200
```

If all four pass — sideload-test, then the AppSource submission.

## Sideload-test the add-in (before AppSource)

Outlook on the web → ⚙️ → Get Add-ins → My add-ins → Custom add-ins
→ "Add from URL" → `https://cleanway.ai/outlook/manifest.xml`
→ Install.

The Cleanway ribbon group should appear on the Home tab. Click any
email; "Scan with Cleanway" opens the taskpane.

While the pane is open, check its console (Outlook on the web: F12, pick
the add-in's frame) for `Content-Security-Policy` violations. office.js
has no published list of the hosts it needs; if it reports a blocked
Microsoft host (a script, a connection, or a frame-ancestor), add that
exact host to the `/outlook/*` policy in `landing/next.config.ts`.

## Caveats

- **Icons.** `email-plugin-outlook/assets/` carries icon-16/32/64/80/128
  (every size the manifest names; `tests/test_outlook_addin.py` fails if a
  manifest URL points at a missing file). AppSource may still ask for a
  sharper 128 px logo.
- **What it sends.** A scan sends the open email's sender, reply-to,
  subject, text, HTML and SPF/DKIM/DMARC results to the API, which checks
  it in memory and stores nothing; a report sends only the sender's
  domain (kept 1 year in `feedback_reports`). The manifest's descriptions
  and the privacy policy (sections 8 and 16, and the legal bases in
  section 15) say exactly this — change all of them together.
- **manifest.xml is also served.** That's intentional — sideload
  testing references it. AppSource submission uploads the file
  separately, so the public copy doesn't actually drive the
  production install.
- **Build coupling.** A bug in `landing/` that breaks `next build`
  also breaks the add-in's files. Acceptable while the add-in is not
  published; if it becomes a problem, split it into its own Vercel
  project (below).

## If we ever split the add-in into its own project

1. Create a Vercel project with root `email-plugin-outlook/`, framework
   preset "Other" (static), on its own domain — add the domain in the
   project's Settings → Domains and its DNS record in Cloudflare
   (DNS only).
2. Change every URL in `manifest.xml` to that domain, and the host in
   `tests/test_outlook_addin.py` and `landing/e2e/outlook-addin.spec.ts`.
3. Give the new project the same headers as `/outlook/*` here (a
   `vercel.json` `headers` block), and add its origin to the API's CORS
   list (`api/config.py`, plus `ALLOWED_ORIGINS` on Railway if set).
4. Remove `prebuild` from `landing/package.json`, the `/outlook/*` rule
   from `landing/next.config.ts`, and the `landing/public/outlook/` entry
   from `.gitignore`.
