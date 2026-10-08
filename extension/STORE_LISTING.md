# Chrome Web Store Listing

Used for Chrome, Edge, Opera and Firefox (runbook: `docs/STORES.md`). Paste only
the text inside the code blocks; the notes around them are for us. Every claim
was checked against `extension/manifest.json` and `extension/src/` on
2026-10-08 — evidence and open TODOs are at the end.

## Name
Cleanway — Protection from scam links
<!-- AUTHORITATIVE: this equals the manifest _locales extension_name — the string Chrome actually renders. To change it, edit extension/src/_locales/*/messages.json + rebuild. -->

## Short Description (132 chars max)

112 characters:

```text
Warns you about scam and phishing sites before you type a password or card number. Plain language, for everyone.
```

## Detailed Description

```text
Cleanway warns you about scam and phishing websites before you type a password or card number. Everything is in plain language, for you and for your parents.

WHAT IT DOES
- Marks links on the pages you visit: a green tick, a yellow warning or a red cross, with the reason when you hover.
- Stops you on a dangerous page with a full-screen warning that explains why, in your language.
- Warns you on login forms that send your password to a different site than the one you see, and on fake "browser windows" drawn inside a page.
- Tells you if a password you type has appeared in known data leaks.
- Optional, off until you switch it on in Settings: checks emails you open in Gmail, Outlook and Yahoo Mail and shows a short banner: looks safe, suspicious, or likely a scam.
- Right-click any link to check it. Right-click a page for a Privacy Audit: trackers, cookies and forms that ask for personal data. The audit runs in your browser.
- Removes common tracking tags such as utm_ and fbclid from web addresses.
- Family: with an account, family members can send each other end-to-end encrypted warnings about dangerous sites.

WHAT LEAVES YOUR BROWSER, HONESTLY
- Site names. To check a site, Cleanway sends only its name (for example, example.com) to our server, never the full address, the page content or your history. This happens for the page you open and for links on it, except well-known official sites the extension recognises on its own. The server checks the name, including with outside lists of dangerous sites such as Google Safe Browsing.
- Emails, only if you switch the email check on. It is off until you turn on "Scan emails I open in Gmail, Outlook and Yahoo for phishing" in Settings. While it is on, for each email you open in Gmail, Outlook or Yahoo Mail, Cleanway sends its subject, the sender's name and address, the reply-to address, the text, and the address and text of each link (not the email's HTML) to our server to check it for scams. The email is checked and not stored. Switch it off any time and the checks stop at once.
- Password leak check. When you leave a password field, Cleanway sends only a short scrambled piece of it (the first 5 characters of its SHA-1 hash), never the password itself. The match is made in your browser.
- Your check history and counters stay in your browser; history is deleted after 30 days.
- Signing in is optional. If you sign in through cleanway.ai, the extension keeps its sign-in keys in the browser's extension storage, this browser appears as a device in your Cleanway account (you can unlink it there), and your settings are saved to the account. "Sign out" in Settings deletes the keys.
- No ads, no analytics inside the extension, and we don't sell data.

WHAT CLEANWAY DOESN'T PROMISE
New scam sites appear every day, and no tool catches them all. If something feels wrong, don't enter your details.

PRICE
Free.

PERMISSIONS EXPLAINED
- "Read and change all your data on all websites": Chrome shows this because Cleanway's scripts run on every page. They are needed to mark links, show the warning page and watch password forms where they appear. They read the page inside your browser; only what is listed above leaves it.
- Gmail, Outlook and Yahoo Mail sites (optional): asked for only when you switch the email check on, and given back when you switch it off.
- Scripting: turns the email check on and off; it runs on those mail sites only while it is switched on.
- cleanway.ai: our checking server (api.cleanway.ai) and the sign-in page that hands your session to the extension.
- Active tab: check the page you are on when you click the icon or press Ctrl+Shift+K.
- Storage: settings, counters and (if you sign in) sign-in keys, on your device.
- Context menus: "Check this link" and "Privacy Audit" in the right-click menu.
- Alarms: housekeeping on a timer: refresh sign-in, delete history older than 30 days, look for family warnings.
- Notifications: show family warnings.

Source code: github.com/AlexMos555/linkshield
Privacy policy: https://cleanway.ai/privacy-policy
```

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
