# Chrome Web Store — Submission Pack (Cleanway 0.1.1)

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
| Artifact | `dist/store-artifacts/cleanway-0.1.1-chrome.zip` (also valid for Edge/Opera/Brave/Vivaldi) |
| Version | 0.1.1 (from `extension/manifest.json`) |
| SHA-256 | see `dist/store-artifacts/cleanway-0.1.1-sha256.txt` |
| Manifest | MV3, no remote code, no `eval`/obfuscation |
| Icons | 16/32/48/128 present in `extension/public/icons/` |
| Privacy policy URL | https://cleanway.ai/privacy-policy |

Rebuild artifacts (if source changed): `bash scripts/build-extensions.sh && bash scripts/build-store-artifacts.sh`

---

## 1. Store listing

**Name:** Cleanway — Phishing & Scam Protection

**Summary (≤132 chars):**
> Warns you before you fall for phishing. On-device link scanning, badges on every
> link, and a privacy-first design.

**Category:** Productivity (or Communication)

**Detailed description** (honest — see §5 for the data reality; do NOT reintroduce
"your browsing data never leaves your device", which is not accurate — Cleanway
sends the *domain* of unknown links to check them):

```
Cleanway flags phishing and scam links before you click.

• Every link on a page gets a red / yellow / green safety badge.
• A local scoring engine runs on-device first — known-safe and cached sites are
  never sent anywhere.
• For unknown domains, Cleanway checks the DOMAIN (not the full URL, not the page
  content) against 16 threat-intelligence sources plus an ML model.
• Optional webmail scanning (Gmail, Outlook, Yahoo) checks an open message for
  phishing. This reads the open message's content — see the privacy section.
• Optional breach check warns if a password you type appears in a known breach,
  using k-anonymity (only the first 5 characters of a SHA-1 hash ever leave the
  device — never your password).
• Family Hub (optional, signed-in): end-to-end encrypted alerts to family members.

We publish our detection rate weekly against Cloudflare and Google Safe Browsing at
cleanway.ai/transparency.
```

---

## 2. Single-purpose description (CWS requires this)

> Cleanway warns users when a website or an open webmail message is a phishing or
> scam attempt, by scoring the page's domain (and, if the user opts in, the open
> message's content) with a local engine and the Cleanway backend.

---

## 3. Permission justifications

Paste one per permission. All 5 permissions and all 6 host-permissions are
**actually exercised** in code (verified) — none are removable.

| Permission | Justification |
|---|---|
| `activeTab` | Reads the active tab's URL only when the user runs the "Check page" command or a context-menu action, to score that page. |
| `storage` | Stores user settings, local protection statistics, auth token, and Family Hub key material in `chrome.storage.local`. |
| `alarms` | Runs periodic background jobs that must survive MV3 service-worker suspension: local history pruning and the Family Hub notification poll. |
| `contextMenus` | Adds right-click items "Check with Cleanway" (links) and "Privacy Audit" (pages) so users can trigger a check on demand. |
| `notifications` | Shows OS notifications for dangerous-site and Family Hub alerts, with a click handler to open the relevant page. |

**Host permissions:**

| Host | Justification |
|---|---|
| `https://api.cleanway.ai/*` | Primary backend: domain safety checks, optional webmail analysis, breach check, feedback, user settings. |
| `https://*.cleanway.ai/*` | First-party only. Covers the API subdomain and account/pricing links. (Could be narrowed to `api.cleanway.ai` — see §7.) |
| `https://mail.google.com/*` | Webmail phishing scan for Gmail (opt-in feature). |
| `https://outlook.office.com/*` | Webmail phishing scan for Outlook (work/edu). |
| `https://outlook.live.com/*` | Webmail phishing scan for Outlook.com (consumer). |
| `https://mail.yahoo.com/*` | Webmail phishing scan for Yahoo Mail. |

**Content scripts on `<all_urls>`:** justified — the injected scripts run a
100%-on-device scoring engine (`src/utils/local-scorer.js`) and badge links locally;
no page data is sent for known-safe/cached domains.

**Remote code:** **No.** `importScripts` loads only local bundled files via
`chrome.runtime.getURL`. No `eval`, no `new Function`, no remotely-hosted scripts.

---

## 4. Data usage — CWS "Privacy practices" form

For each CWS data category, here is the truthful answer, grounded in the 16 verified
egress paths. **Bold = you must tick "collected" and disclose.**

| CWS data type | Collected? | What / why (grounded in code) |
|---|---|---|
| **Web history** | **YES** | Domain (hostname only, no full URL/path/query) of unknown links/pages is sent to `api.cleanway.ai/api/v1/public/check` to score safety. Known-safe + cached domains are never sent. `feedback/report` sends a domain when the user reports a wrong verdict. |
| **Personal communications** | **YES** | Webmail scan (opt-in, Gmail/Outlook/Yahoo) sends the **open message's** sender, subject, and body (text+HTML) to `api/v1/email/analyze` for phishing analysis. No other messages, recipients, thread IDs, or attachments. |
| **Authentication info** | **YES** | Breach check sends only the **first 5 hex chars of the SHA-1** of a typed password (k-anonymity) to `api/v1/breach/check` — never the password or full hash. Signed-in users send a JWT on authenticated calls. |
| **Personally identifiable info** | **YES (Family Hub only)** | If the user creates/joins a Family Hub, a display name and invite are sent. Alert contents between members are **end-to-end encrypted** (server stores ciphertext only). |
| **User activity** | **YES** | Aggregate: dangerous-block counts (integer only), user settings (skill level, font scale), a per-install random device id (UUID, not hardware-derived). |
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
- On webmail, the **open message content** is sent for analysis (opt-in feature).

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

## 7. Optional pre-submit polish (not blockers)

- Narrow `https://*.cleanway.ai/*` → `https://api.cleanway.ai/*` if no other
  subdomain is actually contacted from the extension (reviewers prefer tight scopes).
- Landing/listing claims to reconcile (fixed in EN this session — see
  `git show` for the i18n commit; other locales still carry the old strings):
  - hero "browsing data never leaves your device" → accurate domain-only framing
  - "16 threat databases" → "16 threat-intelligence sources"
  - "24,000 verified domains. 0.95 AUC." → drop the hardcoded AUC; "~24,000 domains"
  - FAQ "8 additional threat sources" → consistent with the 16 total

---

## 8. Upload checklist

1. [ ] Create/sign in to the CWS developer account ($5 one-time).
2. [ ] Upload `cleanway-0.1.1-chrome.zip`.
3. [ ] Paste listing name / summary / description (§1).
4. [ ] Paste single-purpose (§2) + permission justifications (§3).
5. [ ] Fill Privacy practices (§4): tick the 4 collected categories, add the
       justification text, tick the 3 certifications, add the privacy-policy URL.
6. [ ] "Are you using remote code?" → **No**.
7. [ ] Upload 5 screenshots (§6).
8. [ ] Submit. Chrome review is typically 1–3 business days.

Then repeat for Edge/Opera with the same ZIP (Edge validator is pickier on
screenshots; the same justifications must match exactly). Firefox uses the
`-firefox.zip`; Safari needs the Xcode conversion of the staged `-safari/` dir.
See `docs/STORES.md` for per-store nuances.
