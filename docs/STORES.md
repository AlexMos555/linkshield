# Cleanway extension — store submission runbook

Strategy doc Top-20 **#18**. This is the per-store playbook for
shipping the Cleanway browser extension to every major Chromium-
and Gecko-family store + Safari. Run `bash scripts/build-store-
artifacts.sh` first to produce the upload-ready ZIPs under
`dist/store-artifacts/`.

**Paste-ready for the founder: `docs/STORE_SUBMISSION_KIT.md`** — every text,
image and form answer for Google Play, Chrome, Edge, Firefox and Opera, in
console order. The Android app's **Google Play** evidence (Data safety, VPN and
foreground-service declarations, account-deletion URL, console checklist) is §6
below; the targetSdk-36 build comes from the Expo SDK 54 upgrade (§6.A),
submission still waits for the founder TODOs in §6.0. §7 is the 0.2.2
checklist for the browser stores. The RuStore listing is in
`docs/RUSTORE_SUBMISSION.md` §7.

| Store | Reach | Cost | Manifest | Build artifact |
|---|---|---|---|---|
| Chrome Web Store | ~3 B Chrome + Brave + Vivaldi users | $5 one-time | MV3 | `cleanway-<v>-chrome.zip` |
| Microsoft Edge Add-ons | ~150 M Edge users | Free | MV3 | `cleanway-<v>-edge.zip` |
| Opera add-ons | ~320 M Opera users | Free | MV3 | `cleanway-<v>-opera.zip` |
| Firefox Add-ons (AMO) | ~180 M Firefox + Tor users | Free | MV2 shim | `cleanway-<v>-firefox.zip` |
| Safari App Extensions | ~1 B Safari (Mac + iOS) users | $99/yr (Apple Developer) | MV3 in Xcode wrapper | `cleanway-<v>-safari/` |
| Brave / Vivaldi | (consume CWS) | n/a | n/a — same Chrome upload | n/a |
| Firefox Android | not declared yet (no `gecko_android` block) | Free | MV2 shim | same firefox.zip |

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
   - **Detailed description** (EN and RU), single purpose, permission
     justifications, data usage, images: paste from
     `docs/STORE_SUBMISSION_KIT.md` §2–3. The name and the short description
     come from the manifest (`_locales`), not from the dashboard.
   - **Category:** `Productivity → Tools`
   - **Languages:** all 10 we ship (en/es/hi/pt/ru/ar/fr/de/it/id)
3. Privacy practices tab:
   - Single purpose and one justification per permission plus the host field:
     `docs/STORE_SUBMISSION_KIT.md` §3.2 (the checker fails if a manifest
     permission has no text). Chrome treats the `<all_urls>` content scripts as
     access to all sites, so the host field justifies that, not just `activeTab`.
   - Data usage — declare what the code sends (`docs/PRIVACY.md`):
     - **Web history** — the host name of pages the user visits and of links on
       them goes to `GET /api/v1/public/check/{host}` (official and
       user-content hosts are answered locally, `trusted-hosts.js`); never the
       path or query.
     - **Personal communications** and **Website content** — only if the user
       switches on "Scan emails I open in Gmail, Outlook and Yahoo for
       phishing" in Settings (off by default, also for updated installs): then,
       on Gmail, Outlook and Yahoo Mail, the extension sends each opened email's
       subject, sender name and address, reply-to, text and links (not its
       HTML) to `POST /api/v1/email/analyze` (`extension/src/content/webmail.js`
       `buildPayload()`, registered by `extension/src/background/webmail-scanner.js`
       only while the switch is on). Processed in memory, not stored. The four
       mail sites are optional host permissions requested from that switch;
       justify `scripting` with the text in `docs/STORE_SUBMISSION_KIT.md` §3.2.
     - **Personally identifiable information** — the email address, only if the
       user signs in (the extension stores it locally; the account holds it).
     - **Authentication information** — the first 5 characters of the SHA-1 of
       a typed password (leak check, `content/password-pwned.js`) and, when
       signed in, the account token sent with account calls (tokens are kept in
       `chrome.storage.local`, `utils/auth-session.js`).
     - Do **not** claim "no data collected", and do not leave these boxes
       unticked. Full answers: `docs/CWS_SUBMISSION.md` §4.
   - Link the privacy policy: https://cleanway.ai/privacy-policy
4. Screenshots (1280×800, ready — upload, don't retake): `store-assets/extension/en/`
   (Russian listing: `ru/`), in this order:
   - 1. `01-block-page.png` — block page with the "why we blocked" cards
   - 2. `02-popup-safe.png` — popup, safe verdict
   - 3. `03-popup-caution.png` — popup, caution verdict
   - 4. `04-link-badges.png` — link badges on search results, red tooltip open
   - 5. `05-settings.png` — Settings
   Made by `scripts/store-screenshots/extension.mjs`; what each shows, the upload
   order per language and how to retake them: `store-assets/extension/README.md`.
5. Promo tiles (440×280, 1400×560): `docs/STORE_SUBMISSION_KIT.md` §2.3 (`store-assets/browser-extension/`).
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
2. Listing fields and certification notes: `docs/STORE_SUBMISSION_KIT.md` §4
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
3. Listing: `docs/STORE_SUBMISSION_KIT.md` §2 (same text as Chrome).

---

## 4. Firefox Add-ons / AMO (firefox.zip)

**Dev account:** https://addons.mozilla.org/developers/ — free, Mozilla account required.

**Notes:**
- We ship MV2 with a module background (`"type": "module"`, so Firefox 112+) and a `chrome → browser` alias in `src/utils/browser-alias.js` (the background's first import and the first script of every extension page: Firefox MV2's `chrome.*` there returns no Promises). Firefox's MV3 transition is still mid-flight; MV2 keeps the broadest compatibility. Chromium can't load MV2, so `scripts/test-extension-sw.mjs` does not cover this build; `scripts/smoke-firefox-extension.mjs` does, in a real headless Firefox, before submitting (how to run it, what it checks: `docs/STORE_SUBMISSION_KIT.md` §5.0).
- AMO requires a **source-code submission** for any extension that uses minified or bundled code. Our own code is hand-written, unminified JS, but `src/utils/vendor/` holds two unmodified third-party files from their npm packages (tweetnacl 1.0.3 `nacl-fast.min.js`, minified as published; qrcode-generator 1.4.4 `qrcode.js`, unminified, saved as `qrcode-generator.js`) and `src/utils/scorer-data.js` is generated. So answer "Yes" and upload `dist/store-artifacts/cleanway-<v>-firefox-source.zip`; the reviewer notes with the libraries' URLs and hashes are in `docs/STORE_SUBMISSION_KIT.md` §5.
- Mozilla's review is human-led; expect 3-10 business days. The honest publish-our-FP-rate angle plays VERY well with AMO reviewers.

**Submission:**
1. Submit a new add-on → upload `cleanway-<v>-firefox.zip`
2. Add-on type: `Extension`
3. Listing fields, source archive and reviewer notes: `docs/STORE_SUBMISSION_KIT.md` §5 (the "Read and change all your data" line is Chrome's wording; Firefox shows "Access your data for all websites")
4. Source code: upload `cleanway-<v>-firefox-source.zip` (the command that builds it is in `docs/STORE_SUBMISSION_KIT.md` §5).
5. Firefox for Android is not declared (no `gecko_android` block); untick Android in the AMO upload unless it is tested there. The manifest declares Firefox's `data_collection_permissions` (§7).
6. Privacy policy: AMO requires a public URL. We use https://cleanway.ai/privacy-policy.

---

## 5. Safari App Extensions (safari/)

**Dev account:** https://developer.apple.com/account/ — $99/year (Apple Developer Program), requires Apple ID.

### 5.1 iPhone / iPad: inside the Cleanway iOS app (no separate listing)

Safari on iOS gets the extension through the Cleanway iPhone app: the Expo
config plugin `mobile/plugins/withSafariExtension.js` adds the
`CleanwaySafariExtension` target (`ai.cleanway.app.safari-extension`, iOS
16.4+) and copies the built `extension-safari/` into it at prebuild. It ships
with every `eas build -p ios` and is reviewed with the app — there is no
separate App Store record, price or listing. Details: docs/IOS.md §2.5.

App Store notes for the extension:
- **Identifiers**: App ID `ai.cleanway.app.safari-extension` with the App
  Group `group.ai.cleanway.app` (EAS creates it on the first build from
  `extra.eas.build.experimental.ios.appExtensions`).
- **Review notes**: say how to switch it on (Settings → Apps → Safari →
  Extensions → Cleanway → Allow Extension; Other Websites → Allow) and that it
  sends only site names to api.cleanway.ai. Paste-ready text: docs/IOS.md §3.6.
- **App Privacy**: the extension's traffic is the app's "Browsing History —
  site names, not linked, App Functionality" row (docs/IOS.md §3.5); a
  signed-in extension also sends the account token like the desktop
  extensions (docs/CWS_SUBMISSION.md §2–4 describe the same egress). The
  webmail scanner does not exist on iOS, so no email content is collected.
- **Guideline 4.4 (extensions)**: the extension has no purchases, ads or
  upsell of its own on iOS; it must keep working for a person who never opens
  the app again.
- **Screenshots**: optional; if one shows the block page, use a canary or a
  test host, never a real brand's look-alike.
- **Version**: the extension's `CFBundleShortVersionString` follows the app
  (`app.json` `version`); the manifest keeps its own extension version
  (0.2.2) — Safari shows the app's.

### 5.2 Mac: a separate macOS app

**Notes:**
- Safari extensions can't be uploaded as a zip directly — they must be wrapped in a Mac app bundle via Xcode's `Convert to Safari Web Extension` command. The build-store-artifacts script stages the source for you under `dist/store-artifacts/cleanway-<v>-safari/`.
- The wrapper app needs an App Store Connect listing of its own. Plan for an extra week of round-trips with Apple Review.
- App Sandbox restrictions: Cleanway's content scripts run unchanged, but the popup's `chrome.storage.local` becomes `safari.storage.local` — handled by our existing alias.

**Submission flow:**
1. Open Xcode → `xcrun safari-web-extension-converter dist/store-artifacts/cleanway-<v>-safari/`
2. Choose project name `Cleanway` and bundle id `ai.cleanway.safari`
3. Build → Archive → Distribute → Upload to App Store Connect
4. In App Store Connect, fill the macOS listing from `docs/STORE_SUBMISSION_KIT.md` §2.1
5. Submit for review. **Safari review can take 7-14 days** — start the clock first.

The same tree also says "seen" to its containing app through native
messaging (`nativeMessaging` permission, Safari tree only); the converter's
default handler just echoes, which the extension ignores — no Mac-side code is
needed. Exact converter flags: docs/IOS.md §2.6.

---

## 6. Google Play (Android app) — readiness pack

> **Status (2026-10-08): the build is technically ready, the founder TODOs in
> §6.0 are not.** Google Play requires new apps and updates to target **API 36**
> since 31 Aug 2026 ([Target API level requirements](https://developer.android.com/google/play/requirements/target-sdk);
> an extension to 1 Nov 2026 can be requested). The app moved from Expo SDK 52
> (targetSdk 34) to **Expo SDK 54 / React Native 0.81** and now builds with
> targetSdk 36 — see §6.A. Only upload an AAB built after that change.
> `landing/lib/install-urls.ts` has no Google Play entry yet — the Android button
> leads to `/android` (direct APK). Everything below is what Play Console asks
> for, answered from the code.
>
> **1.1.0 (Expo SDK 58 / RN 0.88, draft #327, 2026-10-24):** the requirements in
> §6.A still hold on a debug-signed compile check — `targetSdkVersion 36`,
> `compileSdkVersion 37`, 16 KB alignment of all `arm64-v8a` libraries, the same
> permissions; the AAB is 49 MB, ARM-only. R8 now minifies release builds:
> upload each release's `mapping.txt` to Play (docs/RUSTORE_SUBMISSION.md §2,
> docs/EXPO_UPGRADE_PLAN.md §10).

Package `ai.cleanway.app`. Build and signing are shared with RuStore:
`docs/RUSTORE_SUBMISSION.md` §1–2 (Play App Signing: upload the AAB signed with
the release key; let Google manage the app signing key). **Decide this once,
before the first upload:** with a Google-generated app signing key, Play installs
and the direct-download / RuStore APK (signed with `cleanway-release.jks`) carry
different signatures and cannot update each other — a phone has to uninstall to
switch channel. Choosing "use existing app signing key" in Console (exported with
Google's PEPK tool) keeps one signature everywhere.

| Play Console field | Value |
|---|---|
| Privacy policy URL | `https://cleanway.ai/privacy-policy` (all 10 languages; covers the app, the extension, the website, payments through Stripe / Google Play / the App Store via RevenueCat) |
| Delete account URL | `https://cleanway.ai/delete-account` (public page: sign in → "Delete account"; what is deleted and kept). The deletion itself: `https://cleanway.ai/account` |
| Terms of service (store listing "Website" or in-app) | `https://cleanway.ai/terms` |
| Support email / website | `support@cleanway.ai` (confirm the mailbox receives mail first — `NEXT_PUBLIC_SUPPORT_EMAIL_LIVE`) / `https://cleanway.ai/support` |
| Ads | **No ads** — no ad SDK in `mobile/package.json` |
| App category | Tools (alternative: Productivity) |
| Contains in-app purchases | **Yes** — the Play build sells the device plan through Google Play Billing (RevenueCat): `cleanway.devices` monthly / yearly. Only a build made with `EXPO_PUBLIC_DISTRIBUTION=play` (see §6.0) |

### 6.A Play technical readiness (verified on the 2026-10-08 build)

| Requirement | Status | Evidence / where |
|---|---|---|
| **Target API 36** (new apps + updates since 31 Aug 2026) | ✅ | `aapt2 dump badging`: `targetSdkVersion 36`, `compileSdkVersion 36` (Expo SDK 54 default, no override). Commands: `docs/RUSTORE_SUBMISSION.md` §2. |
| **16 KB page size** (apps targeting Android 15+; updates blocked from 1 Feb 2027 — [page-size guide](https://developer.android.com/guide/practices/page-sizes)) | ✅ | All 21 `arm64-v8a` `.so` in the APK and AAB have 16 KB LOAD alignment; `zipalign -c -P 16` passes; the AAB requests `PAGE_ALIGNMENT_16K`. On SDK 52, 18 of 23 were 4 KB-aligned. |
| **64-bit native code** | ✅ | `arm64-v8a` (+ `armeabi-v7a`) in the AAB. |
| **Permissions** | ✅ | Identical to the SDK 52 APK, so §6.4 holds (`aapt2 dump permissions`, 2026-10-08). |
| **Foreground service type** (manifest + Play Console for targetSdk 34+) | ✅ manifest / ⏳ Console | `CleanwayVpnService` only: `foregroundServiceType="specialUse"`, subtype `vpn`. Console text: §6.6. |
| **Edge-to-edge (Android 15/16)** | ✅ | Insets handled in the root stack and tab bar; dark system bars (`plugins/withDarkSystemBars.js`). Checked on an Android 16 emulator in gesture and 3-button navigation. |
| **Predictive back (Android 16)** | ✅ | Opted out (`predictiveBackGestureEnabled: false` → `enableOnBackInvokedCallback="false"`) because React Native still uses `onBackPressed`; back works. |
| **App Bundle** | ✅ | `./gradlew bundleRelease` builds (35 MB, ARM-only by design — `plugins/withAbiFilters.js`). |
| **Real-device retest of the release-signed build** | ⏳ | Samsung A16 — see "What is and isn't verified" in `docs/RUSTORE_SUBMISSION.md` §2 (the Android 16 emulator run is listed there too). |

### 6.0 TODO before any Play submission (founder)

- [x] **targetSdk 36** — Expo SDK 54 build (2026-10-08); its `aapt dump
      permissions` matches §6.4. Retest the release-signed build on the phone.
- [x] **Old upgrade screen removed; Play Billing wired** (`feat/play-billing-app`).
      `mobile/app/upgrade.tsx` (hard-coded "$4.99 Personal / $9.99 Family", a
      button to `cleanway.ai/pricing`) now only redirects to the paywall;
      Settings → Plan and the Account screen open the paywall directly. In the
      Play build the paywall sells through Google Play (RevenueCat) at Play's own
      prices and has no "Subscribe on cleanway.ai" button or any other link to a
      web checkout (`webCheckoutAllowed`, pinned by
      `mobile/scripts/test-store-billing.mjs`); the update banner that offers an
      APK download from our server is hidden too (Play forbids self-updates).
      For a plan paid on the site, the Play build only says "Paid on
      cleanway.ai" — no link. Setup and test plan: `docs/runbooks/revenuecat.md` §5.
- [x] **Paywall benefits are only what paying adds in this build**
      (`paywallBenefits`): no build lists "Automatic SMS check" (none reads SMS
      by itself — `smsBenefitShown` is false everywhere) or call protection
      (free for everyone).
- [x] **A Play AAB can no longer come out as the site build.** Every Android
      release must name its store: gradle stops at the start when
      `EXPO_PUBLIC_DISTRIBUTION` is unset or unknown, when an AAB is built as
      `site`, or when `android/` was generated for another store
      (`mobile/plugins/withDistributionGuard.js`). The EAS `production` profile
      carries `play`.
- [ ] **Build the Play AAB** — `docs/RUSTORE_SUBMISSION.md` §2, build C
      (`cleanway-<version>-<code>-play.aab`): `EXPO_PUBLIC_DISTRIBUTION=play`
      for the WHOLE build (prebuild, gradle, bundle) and
      `EXPO_PUBLIC_REVENUECAT_ANDROID_KEY=goog_…` (RevenueCat → API keys → Play
      Store app; never the `sk_` secret; on EAS an environment variable).
      Without `play` the AAB has no billing (no `com.android.vending.BILLING`,
      `mobile/react-native.config.js`) and its paywall links to the web
      checkout — Play would reject it. §2 checks the APK built with the same
      env: `aapt2 dump permissions … | grep -c BILLING` → 1 for Play, 0 for the
      site and RuStore APKs.
- [ ] **Pricing line** in the listing (`docs/STORE_SUBMISSION_KIT.md` §1.2–1.3): the copy says only "Basic
      protection is free." Once the subscriptions are live in Play Console, add
      (confirm numbers first; Play shows its own localised prices in the app): "Blocking known scam sites is free with no limit. 3
      detailed checks a day are free, and everything is unlimited for the first
      7 days. Optional subscription: $0.99 a month or $9.99 a year for 3 devices
      (phone, tablet, or browser with the extension); each extra device $0.49 a
      month." Russian: see `docs/RUSTORE_SUBMISSION.md` §7.0 (99 ₽ / +29 ₽).
- [x] **Screenshots and feature graphic** — EN and RU, 1080×1920, from 1.0.4
      (`mobile/assets/store/google-play/`, README there); feature graphic
      1024×500 per language; icon `mobile/assets/store/icon-512.png`.
- [ ] **Sign-in works for the reviewer** — the reviewer cannot receive our
      emailed code, so they get the review account `review@cleanway.ai` with a
      password: for that address only (`EXPO_PUBLIC_REVIEW_EMAILS`) the app
      shows a password field instead of the code; every other address keeps the
      code. Create it / rotate the password with
      `python3 scripts/create_review_account.py` (password in the macOS
      Keychain), then fill "App access" (§6.9, `docs/STORE_SUBMISSION_KIT.md`
      §1.5). Only builds made with the variable have the field (the first one
      after 2026-10-23) — `docs/runbooks/app-review-account.md`.

### 6.1–6.2 Listing text (EN + RU)

The title, short and full descriptions in English and Russian, the release
notes, the graphics and the click-by-click form answers moved to
**`docs/STORE_SUBMISSION_KIT.md` §1** — the one place to paste from. The
Russian full description there is the RuStore text letter for letter
(`scripts/check_store_submission_kit.py` fails if they drift). The sections
below keep the evidence behind the answers.

### 6.3 Data safety — answers that match the code

Source of truth: `docs/PRIVACY.md` ("The Android app", "Accounts, devices and
purchases"); the full evidence table is `docs/RUSTORE_SUBMISSION.md` §3. Play
counts only data **sent off the device**; data processed only on the phone is
"not collected".

**Overview questions**

| Question | Answer |
|---|---|
| Does your app collect or share any of the required user data types? | **Yes** |
| Is all of the user data collected by your app encrypted in transit? | **Yes** (HTTPS to `api.cleanway.ai`, Supabase, Sentry). Note for yourself, not a form field: DNS lookups of unblocked sites go to the network's resolver in plain DNS, as without the app — that is not data *we* collect. |
| Do you provide a way for users to request that their data is deleted? | **Yes** — in the app (Settings → Delete account), and on the web: `https://cleanway.ai/delete-account` |

**Data types**

| Play category → type | Collected / shared | Optional? | Purposes | Why (code) |
|---|---|---|---|---|
| Web browsing → **Web browsing history** | **Collected.** Shared: see the note below | Required | App functionality; Fraud prevention, security and compliance | The host of every link the person checks (typed, pasted, QR, shared, link guard, max 3 per message) goes to `GET /api/v1/public/check/{host}`; the server caches host + verdict up to 24 h, so do **not** tick "processed ephemerally". Never the full URL. |
| Personal info → **Email address** | Collected, not shared | **Optional** | Account management | Only when the person signs in (Supabase Auth). |
| Personal info → **User IDs** | Collected, not shared | Optional | Account management | The account ID of a signed-in person. In the Play build it is also the app user ID sent to RevenueCat (service provider) when the person opens the paywall, buys or restores; before sign-in the paywall's price lookup uses an anonymous RevenueCat ID. |
| Device or other IDs | Collected, not shared | Required | Fraud prevention, security and compliance; Account management | The random install number `X-Cleanway-Install` (rate limiting, replaced every 24 h) and the device ID in the account's device list. Neither is derived from hardware; no advertising ID. |
| App info and performance → **Crash logs**, **Diagnostics** | Collected, not shared (Sentry is a service provider) | Required | Analytics (app stability) | `@sentry/react-native`. |
| Financial info → **Purchase history** | **Collected, not shared** (RevenueCat = service provider) — Play build | Optional | App functionality; Account management | The store purchase (product, dates, status) via RevenueCat and the entitlement stored with the account (`entitlements`, migrations 023–024). Google Play handles the card; no payment info reaches us or RevenueCat. |
| Messages → **SMS or MMS**, **Other in-app messages** | **Not collected** | — | — | A shared or pasted message is analysed on the phone and never leaves it (`MessageAnalyzer`). Only up to 3 link hosts go out — already declared as web browsing history. |
| Location, contacts, photos and videos, audio, files, calendar, health and fitness, app activity, installed apps, financial info (other than above) | **Not collected** | — | — | No such permission or code path. The camera reads QR codes on the device and discards frames. |

**"Shared" note (decide once, keep in step with the privacy policy):** the
server sends the bare host, with no user identity, to threat-intelligence
services (Google Safe Browsing and the others in `docs/PRIVACY.md`) to answer
the check. Play's definition excludes transfers to service providers that
process data on your behalf; these services answer a lookup under their own
terms, so the conservative answer is **Shared: Web browsing history — Fraud
prevention, security and compliance**. The privacy policy (section 5) already
names them, so either answer is consistent with it.

### 6.4 Permissions in the APK (checked with `aapt2 dump permissions` on the targetSdk-36 build, 2026-10-08)

| Permission | Why | Play declaration needed |
|---|---|---|
| `BIND_VPN_SERVICE` (on the service) | The on-device DNS filter (`CleanwayVpnService`) | **VPN service declaration** — §6.5 |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | The shield runs as a foreground service while protection is on (`foregroundServiceType="specialUse"`, subtype `vpn`, `mobile/modules/cleanway-vpn/android/src/main/AndroidManifest.xml`) | **Foreground service declaration** — §6.6 |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Asks once, after explaining why, to exempt the shield from battery optimisation (`KeepAlive.kt`) | Justify if asked — §6.7 (no separate form; Play reviews it under the "Device and network abuse" policy) |
| `RECEIVE_BOOT_COMPLETED` | Restarts the shield after a reboot if it was on | No |
| `POST_NOTIFICATIONS`, `VIBRATE` | "Protection is on" notification, blocked-site alerts, the after-call reminder | No |
| `CAMERA` | QR-code scanning only, requested at first use | No (disclosed in Data safety as not collected) |
| `INTERNET`, `ACCESS_NETWORK_STATE`, `WAKE_LOCK` | Checks, blocklist refresh, offline detection | No |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | Declared by `expo-secure-store`; the app never prompts | No |
| `com.google.android.c2dm.permission.RECEIVE`, launcher-badge permissions | Declared by `expo-notifications`; no Firebase project, no push token | No |
| `com.android.vending.BILLING` | **Play build only** (`EXPO_PUBLIC_DISTRIBUTION=play`): added by Play Billing Library 8.3.0 through `react-native-purchases` (checked with `aapt2 dump permissions` on the 2026-10-08 Play build). The site APK and RuStore build do not link the SDK and do not have it (`mobile/react-native.config.js`) | No (subscriptions set up in Play Console) |
| `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE` | Every build (not new): declared by the Play Install Referrer library (`installreferrer:2.2`) that `expo-application` pulls in. Not an Advertising ID; no `AD_ID` permission in the build | No |
| Never requested (blocked in `app.json`, pinned by `mobile/scripts/check-android-permissions.mjs`) | SMS, call log, phone state, `QUERY_ALL_PACKAGES`, `REQUEST_INSTALL_PACKAGES`, exact alarms, `RECORD_AUDIO`, `SYSTEM_ALERT_WINDOW`, storage | — |

If `aapt` shows `com.google.android.gms.permission.AD_ID` on the new build (some
libraries add it), answer the "Advertising ID" declaration **No** and block the
permission in `app.json` (`blockedPermissions`) before uploading.

### 6.5 VPN service declaration (Play Console → App content → VPN service)

- **Does your app use the VpnService?** Yes.
- **Use case:** *Device security* (anti-phishing / DNS filter). Not "app that
  connects to a VPN gateway", not a proxy.
- **Description** and **video**: paste from `docs/STORE_SUBMISSION_KIT.md` §1.5
  ("VPN service": a ≤500-character and a full version) and record the video
  from its shot list (§1.6).

### 6.6 Foreground service declaration (`FOREGROUND_SERVICE_SPECIAL_USE`)

- **Foreground service type:** Special use; subtype declared in the manifest:
  `vpn`.
- **Justification**: `docs/STORE_SUBMISSION_KIT.md` §1.5 ("Foreground service
  permissions").
- **User impact if deferred or interrupted:** the user is unprotected without
  knowing it — scam sites open normally.
- Video: the same recording as §6.5 (`docs/STORE_SUBMISSION_KIT.md` §1.6).

### 6.7 `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` justification

> Cleanway is a safety app whose core function is an always-on, on-device DNS
> filter (VpnService) that blocks known scam and phishing sites in every app.
> Battery optimisation and manufacturers' battery managers stop it in the
> background without telling the user, which leaves them unprotected while they
> believe they are protected. The app asks once, from its "Keep protection on"
> checklist and only after explaining why; the user can decline and the app
> keeps working. It does not use the exemption for anything else (no sync, no
> ads, no tracking).

### 6.8 Content rating (IARC questionnaire)

- Category: **Utility, Productivity, Communication or Other**.
- Violence, sexuality, language, controlled substances, gambling: **No** to all.
- Users can interact or exchange content: **No** (Family alerts are automatic,
  end-to-end encrypted warnings about a site between family members who invited
  each other; no free-text chat, no public content).
- Shares the user's location with other users: **No**.
- Allows purchases of digital goods: **Yes** (the Play build sells the device
  subscription through Google Play Billing).
- Unrestricted internet access / web browser: **No** (the app opens links in the
  user's own browser).
- Expected rating: Everyone / PEGI 3.

### 6.9 Target audience and other App content declarations

| Declaration | Answer |
|---|---|
| Target age groups | **18 and over** (the product is for adults and their parents; the policy says it is not for children under 13 to use on their own). Do not tick under-13 groups — that brings in the Families policy. |
| Appeals to children | No |
| Ads | **No, my app does not contain ads** |
| Advertising ID | No (see §6.4 note) |
| Government app | No |
| Financial features | None (no banking, loans, payments between users, crypto) |
| Health | No health features |
| News app | No |
| Data safety | §6.3 |
| App access | **All or some functionality is restricted** — every protection feature works without an account, but the account screens need a sign-in and the reviewer cannot receive the emailed code. Instructions: username `review@cleanway.ai`, the password from the Keychain (`docs/runbooks/app-review-account.md`), and the "Any other information" text from `docs/STORE_SUBMISSION_KIT.md` §1.5 (Settings → Sign in → type the address → a password field appears for it only). Do not let Android use the credentials for automated testing |

### 6.10 Founder checklist in Play Console

1. [ ] Create the app (`Cleanway: Scam Protection`, default language English,
       App, Free) — package `ai.cleanway.app`.
2. [ ] Store listing, graphics, contact details: `docs/STORE_SUBMISSION_KIT.md`
       §1.2–1.4 (Russian translation §1.3).
3. [ ] Privacy policy URL `https://cleanway.ai/privacy-policy`.
4. [ ] App access: "All or some functionality in my app is restricted" →
       Add instructions — `review@cleanway.ai`, the password from the Keychain
       (`python3 scripts/create_review_account.py` first), the text from
       `docs/STORE_SUBMISSION_KIT.md` §1.5; leave "Allow Android to use the
       credentials … for testing" off. After a password rotation, update it here.
5. [ ] Ads: No. Advertising ID: No (after the `aapt` check).
6. [ ] Content rating: §6.8. Target audience: §6.9 (18+).
7. [ ] Data safety: §6.3, including the account-deletion URL
       `https://cleanway.ai/delete-account`.
8. [ ] VPN service declaration: §6.5. Foreground service declaration: §6.6
       (record and upload the video).
9. [ ] Government / financial / health / news declarations: §6.9.
10. [ ] Upload the targetSdk-36 AAB to **Internal testing** first; install from
        Play on a real phone; turn protection on; confirm a known scam host does
        not load and the notification shows.
11. [ ] Closed testing: personal developer accounts created after Nov 2023 need
        **12 testers for 14 days** before production access — start it early.
12. [ ] Billing: after the first AAB with the billing library is uploaded,
        create the subscriptions (`cleanway.devices` and `cleanway.extra_device`,
        base plans `monthly` / `yearly`), add license testers, connect RevenueCat,
        then test on the internal track — `docs/runbooks/revenuecat.md` §1–3, §5.3.
        Data safety (Purchase history) and the content rating (digital purchases)
        are answered for it above.
13. [ ] After approval: add Google Play to `landing/lib/install-urls.ts` and drop
        the "Google Play" rule in `scripts/check-landing-claims.py` (scope
        `landing.android`).

---

## 7. Browser stores — console checklist for 0.2.2

All four uploads come from `bash scripts/build-extensions.sh && bash
scripts/build-store-artifacts.sh` (`dist/store-artifacts/cleanway-0.2.2-*.zip`,
checksums in `cleanway-0.2.2-sha256.txt`). Verify before uploading:

```bash
node scripts/test-extension-core.mjs && node scripts/test-extension-auth.mjs \
  && node scripts/test-local-scorer.mjs && python3 scripts/check-extension-paths.py
npx -y web-ext@8 lint --source-dir extension-firefox   # 0 errors expected
```

What 0.2.2 adds over the never-submitted 0.2.1 (CHANGELOG `[Extension 0.2.2]`):
Firefox's popup, Settings and block page load the `chrome → browser` alias
first (Firefox MV2's `chrome.*` on extension pages returns no Promises); the
password-leak check and the brand's verified sign-in hosts are fetched by the
background (from content scripts, CORS discarded the answers in Chromium);
public checks carry a random install number (`X-Cleanway-Install`, replaced
every 24 h), a 429 pauses link lookups for its `Retry-After` but never the page
check, and an offline fallback is kept minutes instead of an hour; the toolbar
count is per tab and per page (a new page starts it from zero; an SPA's
pushState or a #link keeps it); "Report wrong result" sends the
right direction; the BitB scan no longer reads every div's text; "open
anyway" answers the block page before taking the tab away (Firefox logged the
late answer as an error against blocked.js). Permissions are unchanged.
Firefox: `scripts/smoke-firefox-extension.mjs` opens the popup, Settings and a
block page of the uploaded ZIP in a real Firefox before uploading (Chromium
cannot run the MV2 build); 26 of 26 checks on 2026-10-24.

What 0.2.1 adds over the never-submitted 0.2.0 (CHANGELOG `[Extension 0.2.1]`):
the block page is the extension's own `src/blocked/blocked.html` (PR #207, the
tab is taken there instead of an overlay inside the scam page), the access
token lives in `chrome.storage.session` (#207), the API address is allowlisted
(#196), hosting-tenant and dynamic-DNS name rules (#224), the official unminified
`qrcode.js` of qrcode-generator 1.4.4 instead of jsDelivr's minified build (#189),
the popup over the block page says "scam" instead of "safe" (#248).
Permissions are unchanged.

What 0.2.0 already had: the opt-in webmail scanner (PR #117 — off by default, mail
sites are optional permissions, Firefox's data-collection consent on Firefox
140+) and sign-in through cleanway.ai with device registration (PR #107).

| Store | Founder action |
|---|---|
| Chrome Web Store | Upload `cleanway-0.2.2-chrome.zip`; everything else: `docs/STORE_SUBMISSION_KIT.md` §3 (evidence: `docs/CWS_SUBMISSION.md` §3–5). |
| Edge Add-ons | Upload `cleanway-0.2.2-edge.zip`; `docs/STORE_SUBMISSION_KIT.md` §4. |
| Opera add-ons | Upload `cleanway-0.2.2-opera.zip`; same listing. |
| Firefox AMO | Upload `cleanway-0.2.2-firefox.zip`. The manifest declares Firefox's `data_collection_permissions` (required: browsing activity, authentication information; optional: personal communications, website content — the webmail switch asks for these). Source code: our JS is unminified, but a vendored third-party library (tweetnacl) is minified and `scorer-data.js` is generated — upload `cleanway-0.2.2-firefox-source.zip` and paste the reviewer notes (`docs/STORE_SUBMISSION_KIT.md` §5). Privacy policy URL. Notes for the reviewer: "Webmail scanning is off by default and asks for the mail sites and Firefox's data consent when switched on in Settings." |
| Safari (Mac) | `xcrun safari-web-extension-converter dist/store-artifacts/cleanway-0.2.2-safari/` (§5.2 above). |
| Safari (iPhone) | Nothing separate: ships inside the iOS app (§5.1, docs/IOS.md §2.5). |

---

## After submission

- Pin store URLs in [README.md](../README.md) install badges.
- Update [landing/app/[locale]/page.tsx](../landing/app/[locale]/page.tsx) hero CTA to use the live Chrome Web Store URL once approved.
- Bump the Q3 2026 transparency report's `intel_sources_active` list if we add any new sources between submissions.
- Watch the Chrome Web Store dashboard for "Possible policy violation" notices — a common trigger is host-permission scope. The manifest asks for neither `webRequest` nor `declarativeNetRequest`; the broad scope comes from the `<all_urls>` content scripts, which reviewers will see as "read and change all your data on all websites".

## Submission status (update on each release)

| Store | Submitted | Approved | Listing URL |
|---|---|---|---|
| Chrome Web Store | TBD | TBD | TBD |
| Edge Add-ons | TBD | TBD | TBD |
| Opera add-ons | TBD | TBD | TBD |
| Firefox AMO | TBD | TBD | TBD |
| Safari Mac App Store | TBD | TBD | TBD |
