# Chrome Web Store — Submission Pack (Cleanway 0.2.0)

Code-grounded, copy-paste-ready answers for the CWS submission form. Everything
here was derived from the **actual extension source** (`packages/extension-core/src/`)
via a verified data-egress audit (2026-07-06), not from marketing copy. The whole
point of this file: an accurate Privacy-Practices declaration so the listing
survives review. A declaration that doesn't match the code gets the extension
**rejected or taken down**.

> Human steps that only you can do: create the $5 CWS developer account, upload the
> ZIP, paste the answers below, upload 5 screenshots, submit. Target: ~15 minutes.

---

## 0. Pre-flight

| Item | Value |
|---|---|
| Artifact | `dist/store-artifacts/cleanway-0.2.0-chrome.zip` (also valid for Edge/Opera/Brave/Vivaldi) |
| Version | 0.2.0 (from `extension/manifest.json`; same in the Firefox and Safari manifests) |
| SHA-256 | see `dist/store-artifacts/cleanway-0.2.0-sha256.txt` |
| Manifest | MV3, no remote code, no `eval`/obfuscation |
| Icons | 16/32/48/128 present in `extension/public/icons/` |
| Privacy policy URL | https://cleanway.ai/privacy-policy |

Rebuild artifacts (if source changed): `bash scripts/build-extensions.sh && bash scripts/build-store-artifacts.sh`

---

## 1. Store listing

Paste name, summary and description from **`extension/STORE_LISTING.md`** — the
only listing source, checked against the code on 2026-10-08. The name Chrome
renders is the manifest's `extension_name`: **Cleanway — Protection from scam
links**. The older draft that used to sit here ("on-device link scanning",
"known-safe and cached sites are never sent anywhere", "16 threat-intelligence
sources plus an ML model") overstated what stays local and named an unverifiable
source count; do not paste it.

**Category:** Productivity

---

## 2. Single-purpose description (CWS requires this)

> Cleanway warns users when a website or an open webmail message is a phishing or
> scam attempt, by scoring the page's domain (and, if the user opts in, the open
> message's content) with a local engine and the Cleanway backend.

---

## 3. Permission justifications

Paste one per permission. All 6 permissions and both install-time host
permissions are **actually exercised** in code (verified) — none are removable.
The four webmail hosts are **optional** host permissions, requested only when
the user switches the webmail scanner on in Settings.

| Permission | Justification |
|---|---|
| `activeTab` | Reads the active tab's URL only when the user runs the "Check page" command or a context-menu action, to score that page. |
| `storage` | Stores user settings, local protection statistics, the opt-in webmail switch, sign-in tokens (if the user signs in), the random install ID and Family Hub key material in `chrome.storage.local`. |
| `alarms` | Runs periodic background jobs that must survive MV3 service-worker suspension: local history pruning (30 days), refreshing the sign-in before it expires, and the Family Hub notification poll. |
| `contextMenus` | Adds right-click items "Check with Cleanway" (links) and "Privacy Audit" (pages) so users can trigger a check on demand. |
| `notifications` | Shows OS notifications for Family Hub alerts (a family member's device blocked a dangerous site), with a click handler that opens the relevant page (`utils/family-notifier.js`). |
| `scripting` | Registers the opt-in webmail scanner (`src/content/webmail.js`) on Gmail / Outlook / Yahoo Mail only after the user switches it on in Settings and grants those sites, and unregisters it when they switch it off (`scripting.registerContentScripts` / `unregisterContentScripts`, plus `executeScript` into mail tabs already open). Nothing else is injected this way. |

**Host permissions:**

| Host | Justification |
|---|---|
| `https://api.cleanway.ai/*` | Primary backend: domain safety checks, optional webmail analysis, breach check, feedback, user settings. |
| `https://*.cleanway.ai/*` | First-party only. Covers `cleanway.ai/extension/connect`, the sign-in page where `src/content/connect-relay.js` (manifest content script limited to that path) hands the user's session to the extension, and the API subdomain. |

**Optional host permissions** (`optional_host_permissions`; not granted at install,
requested from the Settings switch "Scan emails I open in Gmail, Outlook and Yahoo
for phishing", given back when it is switched off):

| Host | Justification |
|---|---|
| `https://mail.google.com/*` | Opt-in webmail phishing scan for Gmail. |
| `https://outlook.office.com/*` | Opt-in webmail phishing scan for Outlook (work/edu). |
| `https://outlook.live.com/*` | Opt-in webmail phishing scan for Outlook.com (consumer). |
| `https://mail.yahoo.com/*` | Opt-in webmail phishing scan for Yahoo Mail. |

**Content scripts on `<all_urls>`:** justified — they mark links on the page,
show the full-page warning and watch password forms where they appear. They read
the page inside the browser; what leaves it is listed in §4 (host names of the
page and its links, except official / user-content hosts answered locally by
`src/background/trusted-hosts.js` and verdicts cached for an hour).

**Remote code:** **No.** The background is a module service worker that loads only
local bundled files through static `import` statements (the vendored TweetNaCl
included). No `eval`, no `new Function`, no remotely-hosted scripts.

---

## 4. Data usage — CWS "Privacy practices" form

For each CWS data category, here is the truthful answer, grounded in the 16 verified
egress paths. **Bold = you must tick "collected" and disclose.**

| CWS data type | Collected? | What / why (grounded in code) |
|---|---|---|
| **Web history** | **YES** | Domain (hostname only, no full URL/path/query) of unknown links/pages is sent to `api.cleanway.ai/api/v1/public/check` to score safety. Known-safe + cached domains are never sent. `feedback/report` sends a domain when the user reports a wrong verdict. |
| **Personal communications** | **YES** | Webmail scan (opt-in, off by default, Gmail/Outlook/Yahoo) sends **each message the user opens** — subject, sender name and address, Reply-To, body text, and the address and text of each link (not the HTML) — to `api/v1/email/analyze` for phishing analysis. Processed in memory, not stored. No other messages, recipients, thread IDs, or attachments. |
| **Authentication info** | **YES** | Breach check sends only the **first 5 hex chars of the SHA-1** of a typed password (k-anonymity) to `api/v1/breach/check` — never the password or full hash. Signed-in users send the access token on account calls; the refresh token goes only to our Supabase project. Tokens are stored in `chrome.storage.local` and deleted by "Sign out". |
| **Personally identifiable info** | **YES (signed-in users)** | Sign-in happens on cleanway.ai; the extension stores the email address and account ID locally. Device registration (`POST /api/v1/me/devices`) sends the random install ID, the browser's name and the extension version. Family Hub (optional) sends a display name and invite; alert contents are **end-to-end encrypted**. |
| **User activity** | **YES** | Aggregate: dangerous-block counts (integer only, signed-in users), device display settings, and the site name the user reports with "Wrong result?". |
| Location | No | — |
| Financial / payment info | No | Billing is on the website (Stripe), not in the extension. |
| Health info | No | — |
| Website content | No (beyond the webmail case above) | Link *domains* are read locally; only domains (not content) egress for scoring. |

**Required certifications (all TRUE):**
- ✅ I do **not** sell or transfer user data to third parties (outside approved use cases). *(Verified: zero third-party hosts — every network call goes to cleanway.ai. The backend consults threat-intel providers server-side to provide the service; the browser never contacts them.)*
- ✅ I do **not** use or transfer data for purposes unrelated to the item's single purpose.
- ✅ I do **not** use or transfer data to determine creditworthiness / for lending.

**Privacy policy URL:** https://cleanway.ai/privacy-policy (must be live before submit;
source of truth is `docs/PRIVACY.md`).

---

## 5. Data-flow honesty note (read before writing any copy)

The extension **is** privacy-respecting, but "your browsing data never leaves your
device" is **not literally true** and must not appear in the listing or landing:
- Domains of **unknown** sites are sent to Cleanway to be scored (full URLs, paths,
  query strings, and page content are **not**).
- On webmail, if the user switched the scanner on in Settings (off by default), each
  **opened message's** subject, sender, reply-to, text and links are sent for analysis.

Accurate framing to use instead: *"We check domains, not your full URLs or page
content,"* and *"we never sell your data."* Both are true and on-brand. See
`memory/reference_privacy_posture.md`.

---

## 6. Screenshots (need 5, 1280×800 or 640×400)

Shot-list (capture on a real page with the extension loaded):
1. A page with mixed red/yellow/green link badges visible.
2. The popup showing a verdict for the current tab.
3. A blocked dangerous site (the block-page overlay).
4. The webmail phishing banner on an open Gmail/Outlook message.
5. The Privacy Audit / scorecard for a domain.

Small promo tile (440×280) optional but improves placement.

---

## 7. Before submitting

- The public privacy policy (cleanway.ai/privacy-policy, section 8 "The browser
  extension") now lists everything above; deploy the landing site before you
  submit, so the reviewer reads the same text.
- `docs/marketing/chrome-web-store-listing.md` is retired as a listing source
  (it still carries old claims); paste only from `extension/STORE_LISTING.md`.

---

## 8. Upload checklist

1. [ ] Create/sign in to the CWS developer account ($5 one-time).
2. [ ] Upload `cleanway-0.2.0-chrome.zip`.
3. [ ] Paste listing name / summary / description from `extension/STORE_LISTING.md` (§1).
4. [ ] Paste single-purpose (§2) + permission justifications (§3).
5. [ ] Fill Privacy practices (§4): tick every category marked YES, add the
       justification text, tick the 3 certifications, add the privacy-policy URL.
6. [ ] "Are you using remote code?" → **No**.
7. [ ] Upload 5 screenshots (§6).
8. [ ] Submit. Chrome review is typically 1–3 business days.

Then repeat for Edge/Opera with the same ZIP (Edge validator is pickier on
screenshots; the same justifications must match exactly). Firefox uses the
`-firefox.zip`; Safari needs the Xcode conversion of the staged `-safari/` dir.
See `docs/STORES.md` for per-store nuances.
