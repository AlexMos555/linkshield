# Cleanway for Outlook

Inbox phishing protection for Microsoft Outlook (desktop + web + Mac).

## Architecture

```
email-plugin-outlook/
├── manifest.xml          — Office Add-in manifest (v1.1 schema)
├── taskpane/             — The sidebar UI shown on "Scan email"
│   ├── taskpane.html
│   ├── taskpane.css
│   └── taskpane.js       — Reads Office.context.mailbox.item, POSTs to API
├── commands/             — Ribbon-button handlers (no UI)
│   ├── commands.html
│   └── commands.js       — `reportPhishing` fire-and-forget report
└── assets/               — icons (TODO: export from design source)
```

Analysis runs server-side at `POST /api/v1/email/analyze` using the shared
`api.services.email_analyzer` module — the same logic that powers the
Gmail content script, so findings are consistent across both clients.

## Privacy contract

On **Scan email**, only the **minimum headers + body** leave Outlook:

- `from_address`, `from_display`, `reply_to`, `subject`
- `spf` / `dkim` / `dmarc` (parsed from `Authentication-Results`)
- `body_text` + (if available) `body_html`

The server checks them in memory and stores none of it (the one log line
holds the verdict, score and counts — `api/routers/email.py`).

On **Report phishing** (ribbon or task pane), only the sender's **domain**
goes to `POST /api/v1/feedback/report`, with `comment: "[outlook]"`. Reports
are kept for 1 year (`api/services/retention.py`, policy section 16).

**Not sent:** recipients, CC/BCC, attachment content, thread metadata,
routing headers, tenant identifiers. The Outlook Permissions declaration
is `ReadItem` — the narrowest scope that still lets us read the open
message. `manifest.xml`'s descriptions say the same, and
`tests/test_outlook_addin.py` holds the code and the manifest to it.

Domain-reputation lookups (Safe Browsing, our ML model) happen on the
backend so the anon key never ships to end users. See
[`docs/runbooks/outlook-addin-hosting.md`](../docs/runbooks/outlook-addin-hosting.md)
for the hosting (`cleanway.ai/outlook/`, CSP, CORS) and the sideload test.

## Local dev

Outlook add-ins need to load from HTTPS. In dev we use `office-addin-dev-certs`
for a locally-trusted cert.

```bash
# One-time cert install
npx --yes office-addin-dev-certs install

# Serve taskpane/commands at https://localhost:3443
npx --yes http-server ./email-plugin-outlook \
  --ssl \
  --cert ~/.office-addin-dev-certs/localhost.crt \
  --key  ~/.office-addin-dev-certs/localhost.key \
  -p 3443
```

Then edit `manifest.xml` temporarily: replace every
`https://cleanway.ai/outlook/` with `https://localhost:3443/`, sideload
via the Outlook web UI:

1. Outlook on the web → gear icon → **Get Add-ins** → **My Add-ins** → **Custom add-ins** → **Add from file…** → pick `manifest.xml`.
2. Open any email. The "Cleanway" ribbon group appears on the Home tab.

Revert `manifest.xml` before committing.

## Production deploy

1. Build the taskpane/commands bundle (no bundler today — assets are raw HTML/CSS/JS, served as-is).
2. Deploy the landing: its `prebuild` copies this folder to `landing/public/outlook/`, served on `cleanway.ai/outlook/` — the URLs the manifest names (`docs/runbooks/outlook-addin-hosting.md`).
3. Submit `manifest.xml` to the [Microsoft 365 Admin Center](https://admin.microsoft.com) (for org-managed distribution) or to [AppSource](https://appsource.microsoft.com/) (for general availability).
4. AppSource review typically takes 5–10 business days.

## Testing matrix (pre-release smoke)

- [ ] Outlook on Windows (classic + new Outlook)
- [ ] Outlook on macOS
- [ ] Outlook on the web (Microsoft 365)
- [ ] Outlook mobile (Android) — Office.js limited on mobile; expect feature parity gaps
- [ ] Outlook mobile (iOS) — same

Functional smoke for each platform:

- [ ] Clean email (plain newsletter) → verdict = safe, ~0 findings
- [ ] Known phishing fixture (e.g., PayPal-spoof from `tests/fixtures/phishing-*.eml`) → verdict = dangerous, findings highlight sender_spoofing + body_pattern
- [ ] Offline (VPN disconnected) → surfaces the "couldn't reach server" error with a Rescan button
- [ ] Report phishing button → success notification + the sender's **domain** (only) appears in the backend's `feedback_reports` table, with comment `[outlook]`
- [ ] DevTools console of the task pane (Outlook on the web: F12 on the pane's frame) shows no `Content-Security-Policy` violation

## Roadmap

- **SSO via Outlook identity** — use `Office.auth.getAccessToken()` so the add-in runs as the signed-in user, matching quotas on the mobile app.
- **Attachment scanning** — SHA-256 + AV lookup; needs `ReadWriteItem` permission bump + an AppSource re-review.
- **Classify into folders** — move confirmed phishing into a "Cleanway Quarantine" folder; same permission bump.
- **Per-org admin rules** — enterprise customers configure "always block senders matching *" from their admin console.
