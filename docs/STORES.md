# Cleanway extension — store submission runbook

Strategy doc Top-20 **#18**. This is the per-store playbook for
shipping the Cleanway browser extension to every major Chromium-
and Gecko-family store + Safari. Run `bash scripts/build-store-
artifacts.sh` first to produce the upload-ready ZIPs under
`dist/store-artifacts/`.

| Store | Reach | Cost | Manifest | Build artifact |
|---|---|---|---|---|
| Chrome Web Store | ~3 B Chrome + Brave + Vivaldi users | $5 one-time | MV3 | `cleanway-<v>-chrome.zip` |
| Microsoft Edge Add-ons | ~150 M Edge users | Free | MV3 | `cleanway-<v>-edge.zip` |
| Opera add-ons | ~320 M Opera users | Free | MV3 | `cleanway-<v>-opera.zip` |
| Firefox Add-ons (AMO) | ~180 M Firefox + Tor users | Free | MV2 shim | `cleanway-<v>-firefox.zip` |
| Safari App Extensions | ~1 B Safari (Mac + iOS) users | $99/yr (Apple Developer) | MV3 in Xcode wrapper | `cleanway-<v>-safari/` |
| Brave / Vivaldi | (consume CWS) | n/a | n/a — same Chrome upload | n/a |
| Firefox Android | included in AMO listing if `gecko_android` block added | Free | MV2 shim | same firefox.zip |

> **Quick start:** if you only have time for one submission today,
> ship to Chrome Web Store. That single upload reaches Chrome,
> Brave, Vivaldi, Arc (which sideloads CWS items), and Opera GX
> (which can install CWS items via Install Chrome Extensions
> add-on). The other stores compound the reach but don't unlock
> any single new user platform.

---

## Pre-flight (all stores)

```bash
# 1. Run all tests + smoke
pytest tests/ -q --ignore=tests/test_account_lock.py --ignore=tests/test_disposable_email_gate.py

# 2. Rebuild + zip artifacts
bash scripts/build-extensions.sh
bash scripts/build-store-artifacts.sh

# 3. Spot-check the chrome zip (load-unpacked)
#    chrome://extensions → Developer mode ON → Load unpacked → extension/
#    Walk through: badge on safe link, badge on bad link, popup verdict, block page.

# 4. Note the version
grep '"version"' extension/manifest.json
```

---

## 1. Chrome Web Store (chrome.zip)

**Dev account:** https://chrome.google.com/webstore/devconsole/ — $5 one-time fee, Google account required.

**Submission:**
1. Sign in → New item → upload `cleanway-<v>-chrome.zip`
2. Fill listing:
   - **Short description** (≤132 chars): see `STORE-LISTINGS.md → chrome.short_description`
   - **Detailed description**: paste `STORE-LISTINGS.md → chrome.long_description`
   - **Category:** `Productivity → Tools`
   - **Languages:** all 10 we ship (en/es/hi/pt/ru/ar/fr/de/it/id)
3. Privacy practices tab:
   - Single purpose: "Detect and block phishing/scam URLs to protect the user."
   - Permission justification — see `docs/STORE-PRIVACY-JUSTIFICATION.md`
   - Data usage: declare we collect "Domain names of pages user explicitly checked" and "Anonymous threat-protection event counts". Do NOT check "personal communications" or "personally identifiable info".
   - Link the privacy policy: https://cleanway.ai/privacy-policy
4. Screenshots (1280×800 or 640×400):
   - 1. Popup with safe verdict
   - 2. Popup with dangerous verdict + reasons
   - 3. Block page with evidence cards
   - 4. Credential-guardian modal (#7) with three buttons
   - 5. Transparency report on cleanway.ai/transparency
5. Promo tile (440×280): see `marketing/store-assets/chrome-promo-tile.png`
6. Pricing: free
7. **Save draft → Preview → Submit for review.** Reviews typically 1-4 days; expedite by linking the transparency report (proves we publish FP rate).

**After approval:** Brave + Vivaldi pick it up automatically. Arc users can install via the same listing URL.

---

## 2. Microsoft Edge Add-ons (edge.zip)

**Dev account:** https://partner.microsoft.com/en-us/dashboard/microsoftedge/ — free, Microsoft account required.

**Notes:**
- Edge Add-ons accepts the Chrome MV3 build as-is — no manifest changes needed. We still upload `edge.zip` separately so each store can pin its own version history.
- Edge reviews tend to be FAST (24-48h) but pickier on screenshots than Chrome.

**Submission:**
1. Extensions → New → upload `cleanway-<v>-edge.zip`
2. Listing fields are similar to Chrome; reuse `STORE-LISTINGS.md → edge.*`
3. Edge requires a contact email visible in the listing — use `support@cleanway.ai`
4. Privacy: Edge displays each permission inline. The justifications must match the Chrome ones EXACTLY or we get a discrepancy flag.
5. Localisation: Edge accepts the same `_locales/` map Chrome does.

---

## 3. Opera add-ons (opera.zip)

**Dev account:** https://addons.opera.com/developer/ — free, requires GitHub account login.

**Notes:**
- Opera accepts MV3 Chrome zips. Their reviewer is small (1-2 people) so reviews can take 1-2 weeks — submit early.
- Opera will reject extensions that hit `chrome.storage.sync` without `storage` permission — we already declare it.
- Opera GX users (gaming browser) skew young + privacy-conscious. The "honeypot shield" (#8) marketing copy plays well with this audience — highlight it in the long_description for Opera specifically.

**Submission:**
1. Dashboard → Add → upload `cleanway-<v>-opera.zip`
2. Category: `Productivity`
3. Listing: see `STORE-LISTINGS.md → opera.*` — slightly punchier copy than Chrome.

---

## 4. Firefox Add-ons / AMO (firefox.zip)

**Dev account:** https://addons.mozilla.org/developers/ — free, Mozilla account required.

**Notes:**
- We ship MV2 with a `browser.*` Promise shim (see `scripts/build-extensions.sh`). Firefox's MV3 transition is still mid-flight; MV2 keeps the broadest compatibility.
- AMO requires a **source-code submission** for any extension that uses minified or bundled code. Our build is hand-written JS — but AMO's check is heuristic. If they flag, link the GitHub repo: https://github.com/AlexMos555/linkshield.
- Mozilla's review is human-led; expect 3-10 business days. The honest publish-our-FP-rate angle plays VERY well with AMO reviewers.

**Submission:**
1. Submit a new add-on → upload `cleanway-<v>-firefox.zip`
2. Add-on type: `Extension`
3. Listing fields: `STORE-LISTINGS.md → firefox.*`
4. Source code: link the GitHub release tag (e.g. `https://github.com/AlexMos555/linkshield/releases/tag/v<version>`).
5. Add the `gecko_android` block to `manifest.json` before submitting if Firefox Android support is in scope — done already.
6. Privacy policy: AMO requires a public URL. We use https://cleanway.ai/privacy-policy.

---

## 5. Safari App Extensions (safari/)

**Dev account:** https://developer.apple.com/account/ — $99/year (Apple Developer Program), requires Apple ID.

**Notes:**
- Safari extensions can't be uploaded as a zip directly — they must be wrapped in a Mac app bundle via Xcode's `Convert to Safari Web Extension` command. The build-store-artifacts script stages the source for you under `dist/store-artifacts/cleanway-<v>-safari/`.
- The wrapper app needs an App Store Connect listing of its own. Plan for an extra week of round-trips with Apple Review.
- App Sandbox restrictions: Cleanway's content scripts run unchanged, but the popup's `chrome.storage.local` becomes `safari.storage.local` — handled by our existing alias.

**Submission flow:**
1. Open Xcode → `xcrun safari-web-extension-converter dist/store-artifacts/cleanway-<v>-safari/`
2. Choose project name `Cleanway` and bundle id `ai.cleanway.safari`
3. Build → Archive → Distribute → Upload to App Store Connect
4. In App Store Connect, fill the macOS listing per `STORE-LISTINGS.md → safari.*`
5. Submit for review. **Safari review can take 7-14 days** — start the clock first.

---

## After submission

- Pin store URLs in [README.md](../README.md) install badges.
- Update [landing/app/[locale]/page.tsx](../landing/app/[locale]/page.tsx) hero CTA to use the live Chrome Web Store URL once approved.
- Bump the Q3 2026 transparency report's `intel_sources_active` list if we add any new sources between submissions.
- Watch the Chrome Web Store dashboard for "Possible policy violation" notices — common false-positive triggers are the `webRequest` permission (which we now avoid by using `declarativeNetRequest`) and host-permission scope.

## Submission status (update on each release)

| Store | Submitted | Approved | Listing URL |
|---|---|---|---|
| Chrome Web Store | TBD | TBD | TBD |
| Edge Add-ons | TBD | TBD | TBD |
| Opera add-ons | TBD | TBD | TBD |
| Firefox AMO | TBD | TBD | TBD |
| Safari Mac App Store | TBD | TBD | TBD |
