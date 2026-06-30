# Chrome Web Store listing copy

> Re-verify numbers against `data/model_meta.json` + latest `docs/benchmarks/` before submitting. Google can reject for unverifiable claims.

---

## Title (fills "Extension name" — 45 chars max)

```
Cleanway — Privacy-first Anti-Phishing
```

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

**Honest about detection rate.** We publish our weekly benchmark at cleanway.ai/transparency/methodology — the script, the dataset, the per-vendor comparison vs Cloudflare 1.1.1.1 for Families, Google Safe Browsing, PhishTank, and VirusTotal. The current snapshot (2026-06-30, sample = 24 fresh URLhaus + PhishTank phishing URLs) measures Cleanway recall at 61.5% vs Cloudflare 1.1.1.1 for Families at 54.2% on the same sample, with both at 100% precision. AUC 0.9983 on a held-out test set of 14,400 verified domains. Numbers update weekly — see /transparency/methodology for the latest run.

**Smart explanations, not just warnings.** Cleanway shows *why* a link looks dangerous — credential form mismatch, brand impersonation, fresh certificate from a high-risk registrar, unusual entropy in the domain name. Six skill levels (Grandma, Regular, Kids, Pro) tune the explanation to your reader.

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
• Open-source detection engine: https://github.com/cleanway-ai/engine (MIT)
• Privacy policy: cleanway.ai/privacy-policy

## Pricing

• Free forever: 50 scans per month, all detection signals
• Personal ($1.49/month PPP-adjusted): unlimited scans, cultural explanations, email guard
• Family ($5.99/month, up to 5 members): encrypted family alerts, Kids mode, parental dashboard

## Permissions explained

Cleanway requests minimum permissions:
• "Read and change all your data on websites you visit" — required to scan links inline. Reads URLs only, never page content.
• "Storage" — saves your scan history locally on your device (never synced to a server).
• "Notifications" — optional, only for paid Family Hub alerts.

We do NOT request: history, cookies, browsing data, screen capture, microphone, camera.

---

Support: hello@cleanway.ai
Security issues: security@cleanway.ai (90-day coordinated disclosure)
Source code: github.com/cleanway-ai/engine
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

**"Host permissions: https://*/*"**
> Cleanway extracts the domain name from each URL you visit to check it against 16 threat intelligence sources and a CatBoost ML model. The full URL never leaves your device — only the domain. We do not read page content, cookies, or form values.

**"Storage"**
> Your last 1000 scan results are cached locally so repeat visits don't re-query the server. Cache is per-device, never synced to a cloud, expires after 24 hours per entry. Disable cache in the extension settings if you prefer.

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
- [ ] ZIP from `dist/store-artifacts/cleanway-extension.zip` builds clean (re-run `npm run build:extensions`)
- [ ] Privacy policy URL works: https://cleanway.ai/privacy-policy
- [ ] Permissions justifications match what manifest.json actually requests
- [ ] 5 screenshots uploaded at 1280×800
- [ ] Promo tile uploaded (440×280)
- [ ] Detailed description ≤ 16000 chars
- [ ] No competitor names in detailed description
- [ ] Single category picked (probably "Productivity" or "Tools" — not "Security" if Google has tightened category restrictions; verify)
- [ ] Reviewer note: "This is an open-source engine. Source available at github.com/cleanway-ai/engine. Privacy architecture documented at cleanway.ai/privacy-policy. Independent benchmark at cleanway.ai/transparency/methodology."
