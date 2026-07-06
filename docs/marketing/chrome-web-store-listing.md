# Chrome Web Store listing copy

> Re-verify numbers against `data/model_meta.json` + latest `docs/benchmarks/` before submitting. Google can reject for unverifiable claims.

---

## Title (fills "Extension name" — 45 chars max)

```
Cleanway — Privacy-first Anti-Phishing
```

> AUTHORITATIVE published title = the manifest `_locales` `extension_name`, currently **"Cleanway — Protection from scam links"** (that is the string Chrome actually renders). To use a different title, change `extension/src/_locales/*/messages.json` `extension_name` and rebuild — do NOT just paste a different title here.

Backup if rejected for trademark concerns: `Cleanway: Scam Link Protection`

---

## Short description (132 chars max — appears in search results)

```
Real-time scam link protection. Phishing recall published weekly. Your browsing data never leaves your device.
```

Alternative shorter (if 132 too tight):

```
Privacy-first scam link protection. 16 threat sources + ML. Your browsing data stays on your device.
```

Character counts: option 1 = 113, option 2 = 102. Pick whichever feels honest.

---

## Detailed description (the long box — ~16,000 char max, but 400-700 words is sweet spot)

```
Cleanway protects you from phishing, scam, and impersonation websites — without sending your browsing history to a server.

## What it does

Cleanway checks every link you see, in real time, against 16 threat intelligence sources plus a CatBoost machine learning model. Dangerous links get a red badge before you click. The warning explains *why* in plain language — no "Trust us, it's bad."

## What makes it different

**Privacy by design.** Most security extensions ship your full URL to their server so they can check it. Cleanway extracts the domain client-side and sends only the domain — never the full URL, never the page content, never your account email linked to the check. Even our server can't reconstruct your browsing history.

**Honest about detection rate.** We publish our weekly benchmark at cleanway.ai/transparency/methodology — the script, the dataset, and the per-vendor comparison vs Cloudflare 1.1.1.1 for Families, Google Safe Browsing, PhishTank, and VirusTotal. Per-vendor recall, precision, and denominators (including our own unknown/rate-limited bucket) are shown side-by-side on that page and refresh every Monday. Static baseline: AUC 0.95 on a held-out test set of 24,000 verified domains.

**Smart explanations, not just warnings.** Cleanway shows *why* a link looks dangerous — credential form mismatch, brand impersonation, fresh certificate from a high-risk registrar, unusual entropy in the domain name. Four skill levels (Grandma, Regular, Kids, Pro) tune the explanation to your reader.

**Cultural scam awareness.** Russian users see references to СберБанк / Госуслуги / Авито. Spanish users see Mercado Libre / Banco Santander. The cultural explainer is locale-aware — not just machine-translated.

## Features

• Real-time phishing detection on every page
• 16 threat intelligence sources (PhishTank, URLhaus, abuse.ch ThreatFox, Tranco popularity ranking, brand favicon hashes, ML scoring, and more)
• Per-link warning badges with detailed reasoning
• Active credential-form guard: stops you submitting passwords to a lookalike site before you hit enter
• Honeypot Shield: optional decoy password injection on suspected phishing
• Pwned-password check (k-anonymity, server never sees the password)
• Modern-phish guards: Browser-in-the-Browser (BitB) detection, tab-napping reversal, overlay credential traps
• 10 languages: English, Spanish, Hindi, Portuguese, Russian, Arabic, French, German, Italian, Indonesian
• Family Hub (paid): end-to-end encrypted alert sharing across phones, Kids mode, parental dashboard

## Privacy guarantees

• Full URL: never sent
• Page content: never read
• Browsing history: never stored
• Account email: never linked to scans
• Server logs: rotated, no IP retention past request lifetime
• Open-source detection engine: https://github.com/AlexMos555/linkshield (MIT)
• Privacy policy: cleanway.ai/privacy-policy

## Pricing

• Free forever: 10 server checks/day (plus unlimited instant on-device blocklist checks), all detection signals
• Personal ($4.99/month; lower in many regions via PPP): unlimited server checks, cultural explanations, email guard
• Family ($9.99/month, up to 6 devices): encrypted family alerts, Kids mode, parental dashboard

## Permissions explained

Cleanway requests minimum permissions:
• "Access to the page you're actively using + Gmail/Outlook/Yahoo Mail" — required to badge links inline. The domain is extracted on-device; only the domain is checked, never page content.
• "Storage" — saves your scan history locally on your device (never synced to a server).
• "Notifications" — optional, only for paid Family Hub alerts.

We do NOT request: history, cookies, browsing data, screen capture, microphone, camera.

---

Support: hello@cleanway.ai
Security issues: security@cleanway.ai (90-day coordinated disclosure)
Source code: github.com/AlexMos555/linkshield
```

Word count: ~470. Within sweet spot.

---

## Single bullet for the "Highlights" box (5 max)

```
✓ Phishing recall measured weekly + published (cleanway.ai/transparency/methodology)
✓ Server only sees domain — never your full URL or page content
✓ 16 threat sources + CatBoost ML + LLM-judged ambiguous cases
✓ Honest benchmark: cleanway.ai/transparency/methodology
✓ Open source detection engine (MIT)
```

---

## Screenshots — captions (5 required)

1. **Hero / extension installed** — "Cleanway checks every link automatically. No clicks required."
2. **Warning popup on a phishing URL** — "Plain-language warning: why the link is dangerous and what to do next."
3. **Per-link badges in Gmail** — "Inline badges across Gmail, Outlook, Reddit, Discord, every site you read."
4. **Methodology / transparency page** — "Our detection rate is measured weekly and published. No marketing math."
5. **Family Hub view** — "Optional family sharing. End-to-end encrypted. Kids mode tunes warnings for younger readers."

Suggested image size: 1280×800. Show real UI, no mockups.

---

## Permissions justification (required text box for each permission)

**"activeTab"**
> Scans the links on the page you're actively looking at. No access to your other tabs or background browsing.

**"Host access: api.cleanway.ai + Gmail / Outlook / Yahoo Mail"**
> Sends only the domain of a link (never the full URL, page content, cookies, or form values) to api.cleanway.ai for checking. Access to the four webmail hosts is what lets Cleanway badge links inline inside your inbox. It does NOT request access to all websites.

**"Storage"**
> Recent scan results are cached locally so repeat visits don't re-query the server — per-device, never synced to a cloud, expires per entry.

**"Alarms"**
> Schedules periodic background refreshes of the on-device blocklist so local checks stay current.

**"contextMenus"**
> Adds a right-click "Check this link with Cleanway" option.

**"Notifications" (optional)**
> Used only for the Family Hub paid feature to alert you when a family member sees a dangerous link. Disabled by default. Free users never see this permission requested.

---

## What NOT to write

- Do not say "100% protection". Anti-phishing is best-effort defense in depth.
- Do not promise SOC 2 / GDPR / HIPAA unless you have the certification on file. We're not certified yet.
- Do not benchmark against named competitors who are also in the Chrome Web Store (Google's policy disallows competitive comparison in extension store copy). The methodology page is fine because it lives on cleanway.ai, not in the listing.

---

## Submission checklist

- [ ] $5 dev account purchased
- [ ] ZIP is `dist/store-artifacts/cleanway-0.1.1-chrome.zip`, rebuilt clean via `bash scripts/build-extensions.sh && bash scripts/build-store-artifacts.sh`
- [ ] Privacy policy URL works: https://cleanway.ai/privacy-policy
- [ ] Permissions justifications match what manifest.json actually requests
- [ ] 5 screenshots uploaded at 1280×800
- [ ] Promo tile uploaded (440×280)
- [ ] Detailed description ≤ 16000 chars
- [ ] No competitor names in detailed description
- [x] Category = **Productivity** (decided; matches extension/STORE_LISTING.md)
- [ ] Reviewer note: "This is an open-source engine. Source available at github.com/AlexMos555/linkshield. Privacy architecture documented at cleanway.ai/privacy-policy. Independent benchmark at cleanway.ai/transparency/methodology."
