# Chrome Web Store Listing

Used for Chrome, Edge, Opera and Firefox (runbook: `docs/STORES.md`; paste-ready
text: `docs/STORE_SUBMISSION_KIT.md` §2). Every claim was checked against
`extension/manifest.json` and `extension/src/` on 2026-10-08 — evidence and open
TODOs are below.

## Name
Cleanway — Protection from scam links
<!-- AUTHORITATIVE: this equals the manifest _locales extension_name — the string Chrome actually renders. To change it, edit extension/src/_locales/*/messages.json + rebuild. -->

## Short and detailed description

Moved to **`docs/STORE_SUBMISSION_KIT.md` §2** (English §2.1, Russian §2.2,
AMO summaries §5) — the one place to paste from for Chrome, Edge, Firefox and
Opera. Chrome and Edge take the short description from the manifest
(`extension_description` in `_locales`), not from the dashboard. Any change to
the copy must keep matching the evidence below.

## Category
Productivity

## Language
English (the extension itself ships in 10 languages: en, ru, es, pt, fr, de, it, id, hi, ar)

## Website
https://cleanway.ai

## Support URL
https://cleanway.ai/support

## Privacy Policy URL
https://cleanway.ai/privacy-policy

---

## Evidence (manifest version 0.2.0)

| Claim | Code |
|---|---|
| Content scripts on every page → Chrome's "all websites" warning | `extension/manifest.json` `content_scripts[0].matches: ["<all_urls>"]` |
| Host permissions: `api.cleanway.ai`, `*.cleanway.ai`; Gmail, Outlook (office + live), Yahoo Mail only as optional | `extension/manifest.json` `host_permissions`, `optional_host_permissions` |
| Permissions: `activeTab`, `storage`, `alarms`, `contextMenus`, `notifications`, `scripting` | `extension/manifest.json` `permissions` |
| Site checks send the host only; official / user-content hosts answered locally | `extension/src/background/index.js:211-238` (`/api/v1/public/check/{host}`), `extension/src/background/trusted-hosts.js` |
| No local blocklist: the name-rule scorer is a fallback when the API does not answer | `extension/src/background/index.js:166-173`, `:236-257` |
| Webmail check is off until switched on in Settings; then sends subject, sender, reply-to, text and links (no HTML), not stored | `extension/src/background/webmail-scanner.js` (registers `webmail.js` only while `webmailScannerEnabled === true`), `extension/src/content/webmail.js` `buildPayload()`, `extension/src/options/options.js` (switch + `permissions.request`), `api/routers/email.py` (logs verdict and counts only) |
| Password leak check sends a 5-char SHA-1 prefix | `extension/src/content/password-pwned.js:1-10`, `:82` |
| Sign-in tokens in `chrome.storage.local`; browser linked as an account device | `extension/src/utils/auth-session.js:39`, `extension/src/background/auth.js:38`; `docs/ACCOUNTS_BILLING_PLAN.md` §9 |
| Privacy Audit runs in the page | `extension/src/content/index.js:311-336` |
| Notifications = family warnings only | `extension/src/utils/family-notifier.js:141` (only `notifications.create`) |

### Inaccuracies fixed on 2026-10-08

- ❌ "Your browsing data NEVER leaves your device" / "never page content" —
  the webmail check sends whole emails; site names of visited pages go to the
  server too.
- ❌ "host access scoped to api.cleanway.ai and the 3 webmail hosts — NOT all
  websites" — the `<all_urls>` content scripts give access to every page, and
  Chrome says so on install.
- ❌ "Most checks resolve instantly on-device against a local blocklist" /
  "Unlimited local checks (bloom filter)" — the extension has no blocklist;
  only official and user-content hosts are answered locally.
- ❌ "16 threat-intelligence signals … IPQualityScore … LLM judge" and the "Even
  if our servers are breached, attackers learn nothing" line — an unverifiable
  list (several sources can be switched off by licence) and an absolute claim.
- ❌ Free plan "10 API checks per day", Personal $4.99, Family $9.99 "up to 6
  devices", Weekly Security Report, Security Score — none matches the current
  plan (`docs/ACCOUNTS_BILLING_PLAN.md` §5) or is purchasable in the extension.
- ❌ Permission list missing `alarms`, `contextMenus`, `notifications` and the
  `*.cleanway.ai` host.
- ❌ "Open source clients" → "Source code: …" (the repo is public; the wording
  claims only what is true).

### TODO for the founder

- [x] **Webmail has no off switch.** Fixed: the email check is a Settings
      switch, off by default (also for updated installs); the mail sites are
      optional host permissions requested from that switch. The copy above
      describes it. The public privacy policy (cleanway.ai/privacy-policy,
      section 8 "The browser extension", all 10 languages) carries it since
      2026-10-08, together with sign-in, device registration and the
      password-hash prefix. Firefox 140+ also asks for its own data-collection
      consent when the switch is turned on.
- [ ] **Pricing.** The copy says "Free." When the subscription is sold for
      browsers, add: "Optional subscription: $0.99 a month or $9.99 a year for 3
      devices (phone, tablet, or browser with the extension); each extra device
      $0.49 a month." Confirm the numbers (`docs/ACCOUNTS_BILLING_PLAN.md` §5)
      and that a browser can actually buy or use it.
- [x] `docs/marketing/chrome-web-store-listing.md` is marked retired at the top
      (it still carries "Your browsing data never leaves your device"); paste
      only from this file.
