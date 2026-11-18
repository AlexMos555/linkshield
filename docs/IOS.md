# Cleanway for iPhone — build, targets, App Store

The iOS app is the same Expo app as Android (`mobile/`, Expo SDK 58, React
Native 0.88, New Architecture — the only one since SDK 55), shipped through the App Store only. This
file covers how to build it, what is in the binary today, what comes next, and
what the founder has to set up in Apple's consoles.

Architecture and the choice of iOS mechanisms: `docs/MOBILE_AUTO_PROTECTION.md`.
Payments (server side, RevenueCat): `docs/runbooks/revenuecat.md`.

---

## 1. Build it

### 1.1 Locally (simulator)

The monorepo hoists a different `react-native` to the repo root, which breaks
`expo prebuild` / `pod install` inside the workspace. Build from a mirror
outside the repo. The rsync takes `mobile/.env` along (not in the repo,
`mobile/.env.example`); for any build you upload it must hold
`EXPO_PUBLIC_SUPABASE_URL`, `EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY`
(`sb_publishable_…`), the legacy `EXPO_PUBLIC_SUPABASE_ANON_KEY`,
`EXPO_PUBLIC_CAPTCHA_URL` and `EXPO_PUBLIC_REVIEW_EMAILS` — and
`EXPO_PUBLIC_REVENUECAT_IOS_KEY` only for a build that sells (§3.6):

```bash
M=/tmp/cleanway-ios            # any scratch dir outside the repo
rsync -a --delete --exclude '/node_modules' --exclude '/android' --exclude '/ios' \
  --exclude '/dist' --exclude '/.expo' mobile/ "$M/"
mkdir -p "$M/vendor"
rsync -a --exclude node_modules packages/api-client/ "$M/vendor/api-client/"
rsync -a --exclude node_modules packages/api-types/  "$M/vendor/api-types/"
REPO="$PWD"
cd "$M"
# point the two workspace packages at the vendored copies
node -e '
const fs=require("fs");
const p=JSON.parse(fs.readFileSync("package.json"));
p.dependencies["@cleanway/api-client"]="file:./vendor/api-client";
p.dependencies["@cleanway/api-types"]="file:./vendor/api-types";
fs.writeFileSync("package.json",JSON.stringify(p,null,2)+"\n");
const c=JSON.parse(fs.readFileSync("vendor/api-client/package.json"));
c.dependencies["@cleanway/api-types"]="file:../api-types";
fs.writeFileSync("vendor/api-client/package.json",JSON.stringify(c,null,2)+"\n");'
node "$REPO/mobile/scripts/check-mirror-lock.mjs" --dir "$M"   # "ok:"; "out of step" = regenerate mobile/package-lock.json first (docs/RUSTORE_SUBMISSION.md §2)
npm install                                    # installs mobile/package-lock.json, which came along (1.0.x: then node scripts/test-decode-uri-component.mjs, docs/EXPO_UPGRADE_PLAN.md §1.2)
# The Safari extension target bundles the repo's built extension-safari/
# (plugins/withSafariExtension.js); outside the repo it must be told where.
bash "$REPO/scripts/build-extensions.sh" > /dev/null
CLEANWAY_SAFARI_EXTENSION_DIR="$REPO/extension-safari" CI=1 npx expo prebuild -p ios --no-install
cd ios && LANG=en_US.UTF-8 pod install --repo-update   # --repo-update: RevenueCat's pods are newer than a stale CDN index
SIM="iPhone 16e"   # a name `xcrun simctl list devices available` prints — the set differs per Xcode
xcodebuild -workspace Cleanway.xcworkspace -scheme Cleanway -configuration Debug \
  -sdk iphonesimulator -destination "platform=iOS Simulator,name=$SIM" \
  -derivedDataPath ../build build
```

Debug loads JS from Metro (`npx expo start` in `$M`); Release embeds the bundle.
Both configurations were built and run on the iOS 26.2 simulator with Xcode 26.3
(2026-10-09, Expo SDK 54). `plugins/withXcode26Patches.js` keeps fmt / Sentry /
expo-localization compiling on Xcode 26 (SDK 54). On SDK 58 only its patch 4
acts: expo-modules-jsi on Xcode below 26.4, so this Mac's Xcode 26.3 needs it.
A full build is ~4 GB of DerivedData — delete the mirror and `build/` afterwards.

**Expo SDK 58 (1.1.0, #327, 2026-10-25):** the same recipe builds the Debug
simulator app with Xcode 26.3 (BUILD SUCCEEDED; `pod install` 123 pods —
a session record, the log was not kept). Later SDK 58 builds have logs in
`~/Desktop/cleanway-android-out/logs/`: on 2026-11-02 a Release simulator build
with patch 4 succeeded twice (`ios-1.1.0-sim-release-0211-run1-full.log`,
`…-run2-summary.log`) and launched on the iPhone 16e simulator (a session
record: the launch has no log); then the Release archives below
(`ios-1.1.0-7-archive.log` on 2026-11-02, rebuilt after #392 as
`ios-1.1.0-7b-archive.log` on 2026-11-03). `pod install` was not kept with its full output. Not
yet run on a device: that is the TestFlight phone check
(docs/EXPO_UPGRADE_PLAN.md §6.2, §10.3). Expo
officially wants Xcode 26.4+ from SDK 56, and in #253 the Swift 6.2.4 compiler
crashed on `expo-modules-core`; since `expo@58.0.19` `ExpoModulesCore` and five
other Expo modules come as precompiled xcframeworks, and Xcode 26.3 imports
them. Short on disk, build one architecture without the index or dSYMs (~2 GB
of DerivedData instead of ~4 GB): add `ARCHS=x86_64 ONLY_ACTIVE_ARCH=YES
COMPILER_INDEX_STORE_ENABLE=NO DEBUG_INFORMATION_FORMAT=dwarf` to the
`xcodebuild` line. App Store builds are made here too, with the archive steps
below (founder, 2026-11-02: Xcode 26.3, EAS §1.2 only as the fallback;
docs/EXPO_UPGRADE_PLAN.md §9, decision 3). 1.1.0 (7) was archived that way
and uploaded to TestFlight on 2026-11-03; the logs are
`~/Desktop/cleanway-android-out/logs/ios-1.1.0-7b-archive.log`, `…-checks.txt`
and `ios-1.1.0-7-upload.log`. The upload warns "Upload Symbols Failed" for
four frameworks. React, ReactNativeDependencies and hermesvm come prebuilt
without dSYMs, so crash reports in App Store Connect leave their frames
unsymbolicated. ExpoCameraBarcodeScanning does ship a dSYM with the UUID Apple
asked for, inside its xcframework
(`Pods/ExpoCameraBarcodeScanning/ExpoCameraBarcodeScanning.xcframework/ios-arm64/dSYMs`),
but it did not reach the archive's `dSYMs/`. The upload still succeeds. The
app, its extensions and the other frameworks have dSYMs.

**1.1.0 (8), 2026-11-11 — the first iPhone build that sells.** Same recipe,
mirror `~/Library/Caches/cleanway-dev/cwi110b8`, branch at `30a4a994` (main
up to #344, #411, #403, #408, #409). The mirror's `.env` is `mobile/.env`
with `EXPO_PUBLIC_REVENUECAT_IOS_KEY` plus one added line,
`EXPO_PUBLIC_FREEMIUM_ENABLED=1` (the free limit of #411; without the flag
the build sells but limits nothing). Archive
`~/Desktop/cleanway-android-out/ios/Cleanway-1.1.0-8.xcarchive`, ARCHIVE
SUCCEEDED; uploaded to TestFlight the same day ("Uploaded Cleanway",
EXPORT SUCCEEDED; the same four "Upload Symbols Failed" warnings). Logs in
`~/Desktop/cleanway-android-out/logs/`: `ios-1.1.0-8-npm-install.log`,
`-prebuild.log`, `-pod-install.log` (129 pods, with RevenueCat 5.92.0,
PurchasesHybridCommon 19.5.0, RNPurchases 10.11.0), `-archive.log`,
`-archive-checks.txt`, `-upload.log`, `-device-install.log`. The checks:
1.1.0 (8), `ai.cleanway.app`, iOS 16.4, `ITSAppUsesNonExemptEncryption`
false; Supabase host, review email, publishable and anon keys and the
`appl_` key from `.env` in `main.jsbundle` ("sells"); StoreKit linked,
RevenueCat in the app binary, `RevenueCat.bundle` and
`PurchasesHybridCommon.bundle` in the app; the §3.6 "VPN" search as expected.
Hermes bytecode cannot show the freemium flag, so it was read from an
unminified bundle exported from the same mirror (`npx expo export:embed
--platform ios --dev false --minify false`): `EXPO_PUBLIC_FREEMIUM_ENABLED:
"1"`. Automatic signing archives with the Apple Development certificate and
the team profile, which lists the founder's iPhone, so the archive's
`Cleanway.app` installs on it as it is: `xcrun devicectl device install app
--device <id> …/Products/Applications/Cleanway.app` (done for build 8; the
phone shows 1.1.0 (8)). A development-signed install and a TestFlight install
both buy in the App Store sandbox (§3.4); installing one replaces the other.

**1.1.0 (9), 2026-11-12 — build 8 plus the eight phone fixes of #423.** Same
recipe and the same `.env` (the `appl_` key and
`EXPO_PUBLIC_FREEMIUM_ENABLED=1`), mirror
`~/Library/Caches/cleanway-dev/cwi110b9`, branch at `13721aaf` (main up to
#423). Archive `~/Desktop/cleanway-android-out/ios/Cleanway-1.1.0-9.xcarchive`,
ARCHIVE SUCCEEDED; `ios-1.1.0-9-archive-checks.txt` differs from build 8's
only in the build number and the commit (1.1.0 (9), "sells", StoreKit and
RevenueCat, the §3.6 "VPN" search, entitlements, `codesign --deep --strict`;
the freemium flag read from an unminified export as for build 8), and the
bundle no longer holds the old example `paypa1-verify.tk`. Uploaded to
TestFlight ("Uploaded Cleanway", EXPORT SUCCEEDED, the same four "Upload
Symbols Failed" warnings) and installed on the founder's iPhone with
`devicectl` (the phone lists 1.1.0 (9)). Logs: `ios-1.1.0-9-*.log` in
`~/Desktop/cleanway-android-out/logs/`. Checked on the phone through a UI
test runner (English UI): "Try these" is google.com, list-canary.cleanway.ai,
pay-pal.com; list-canary.cleanway.ai answers "Dangerous" 90/100, "On
Cleanway's list of scam sites"; the back button reads "Back" (was "(tabs)").
The Settings Plan row says "Protection on this phone is free" / Upgrade and
the plan screen offers Subscribe: the phone has no active sandbox
subscription now, so the row's subscribed wording (#423, item 1) is still to
be seen after a sandbox purchase (§3.4).

**For App Store Connect** (how 1.0.6 builds 5 and 6 were made), archive Release
from the same mirror, then check what the bundle carries **before** uploading
(Xcode Organizer, or `xcodebuild -exportArchive` with an `ExportOptions.plist`
of method `app-store-connect`, destination `upload`). The checks print no key:

```bash
cd "$M/ios"
xcodebuild -workspace Cleanway.xcworkspace -scheme Cleanway -configuration Release \
  -destination generic/platform=iOS -archivePath "$M/Cleanway.xcarchive" \
  -derivedDataPath ../build -allowProvisioningUpdates \
  DEVELOPMENT_TEAM=29LQWL23VQ CODE_SIGN_STYLE=Automatic archive
B="$M/Cleanway.xcarchive/Products/Applications/Cleanway.app/main.jsbundle"
LC_ALL=C grep -ac bpyqgzzclsbfvxthyfsf.supabase.co "$B"   # ≥ 1
LC_ALL=C grep -ac review@cleanway.ai "$B"                 # ≥ 1: the reviewers' password sign-in (§3.6)
# The publishable key from .env — not a bare `grep sb_publishable_`: the app's
# prefix check puts that string in every bundle, so 1.0.6 (6), which has no
# key, matches it too.
PK=${EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY:-$(sed -n 's/^EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY=//p' "$M/.env")}
case "$PK" in
  *REPLACE*) echo "STOP: $M/.env has the .env.example placeholder, not the key" ;;
  sb_publishable_?*) LC_ALL=C grep -aqF "$PK" "$B" && echo "publishable key ok" || echo "STOP, no publishable key" ;;
  *) echo "STOP: no EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY in $M/.env" ;;
esac
# Does this build sell? Decides the review notes (§3.6). Read from the bundle,
# not from .env: Expo also loads .env.local / .env.production and strips quotes
# and `export`, so a key the .env text seems to lack can still be built in —
# and on iOS that turns App Store billing on. A real key is appl_ + letters and
# digits; the bare "appl_" of the app's own key check (in every bundle) and the
# .env.example placeholder (appl_REPLACE_…) do not match.
LC_ALL=C grep -aqE 'appl_[A-Za-z0-9]{8,}' "$B"
case $? in
  0) echo "sells: §3.6 with the In-App Purchase sentence" ;;
  1) echo "no in-app purchases: §3.6 as written" ;;
  *) echo "STOP: cannot read $B" ;;
esac
```

A `STOP` on the publishable key means the build would sign everyone out once the
legacy Supabase keys are disabled (docs/MOBILE_AUTH.md §1) — add the key to
`mobile/.env`, rsync again and rebuild. Every iPhone build up to and including
1.0.6 (6) fails it: `mobile/.env` had no publishable key before 2026-10-25.

### 1.2 For TestFlight / the App Store (EAS)

`eas build -p ios --profile production`, then `eas submit -p ios` for TestFlight
and the App Store. `preview` is not TestFlight: it is `distribution: internal`,
on iOS an ad-hoc build that installs only on devices registered with
`eas device:create`.
EAS manages certificates, provisioning profiles and the build number
(`appVersionSource: remote`). Set these as **EAS environment variables**
(Expo dashboard → project → Environment variables), not in `eas.json`:

| Variable | Value | Without it |
|---|---|---|
| `EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | Supabase publishable key, `sb_publishable_…` (preferred over the anon key when both are set, `src/utils/supabase-key.ts`) | Sign-in works on the anon key until the legacy keys are disabled, then signs everyone out (docs/MOBILE_AUTH.md §1) |
| `EXPO_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon key (legacy JWT; fallback) | With neither key, sign-in does not work |
| `EXPO_PUBLIC_REVENUECAT_IOS_KEY` | RevenueCat **public** App Store key, `appl_…` | No paid plans anywhere (no Plan/Upgrade row, no paywall, no prices) and no daily check limit — the build has no in-app purchases; no crash |
| `EXPO_PUBLIC_SENTRY_DSN` | optional | No crash reports |

`EXPO_PUBLIC_REVIEW_EMAILS` (the App Review sign-in account, §3.6) and
`EXPO_PUBLIC_CAPTCHA_URL` are not secrets and live in `eas.json` itself.

`EXPO_PUBLIC_DISTRIBUTION` does not matter on iOS: every iOS build is the App
Store build (`distributionFor()` in `src/utils/freemium.ts`). That is
deliberate — an EAS profile shared with Android may carry
`EXPO_PUBLIC_DISTRIBUTION=play`, and an iOS build that fell back to `site`
would link to the web checkout (App Review 3.1.1). `appstore` is accepted as a
value for clarity. A secret `sk_…` key or the Play `goog_…` key is refused on
iOS (`readStoreBillingConfig`).

---

## 2. What is in the binary

| | Value |
|---|---|
| Bundle id | `ai.cleanway.app` |
| Targets | `Cleanway` (app), `CleanwayCheckLink` (share extension, `ai.cleanway.app.share-extension`), `CleanwaySmsFilter` (scam-text filter, `ai.cleanway.app.sms-filter`, §5), `CleanwaySafariExtension` (Safari Web Extension, `ai.cleanway.app.safari-extension`, iOS 16.4+, §2.5) |
| App group | `group.ai.cleanway.app` (app + share extension + Safari extension; the share extension hands the shared link/text to the app through it, the Safari extension the time it last ran on a web page) |
| Devices | iPhone only (`supportsTablet: false`, see §2.3); iOS 16.4+ (Expo SDK 56+ minimum) |
| Entitlements | App group; Network Extensions = `["dns-settings"]` (DNS protection, §4 — added by `plugins/withIosAppStore.js`). No push (`aps-environment` is stripped by the same plugin), no VPN value |
| Usage strings | Camera only (QR scanner). Microphone and Face ID strings are switched off in `app.json`. The camera prompt is in the phone's language: `app.json` `locales` → `<lang>.lproj/InfoPlist.strings` for all 10 app languages, generated by `scripts/build-i18n.py` from `packages/i18n-strings` (`mobile.ios_info_plist`) into `mobile/i18n/ios/`. The share-sheet name of `CleanwayCheckLink` (`iosShareExtensionName`) stays English: it lives in the extension's own Info.plist, and expo-share-intent has no option to localise it (it would take a plugin that adds InfoPlist.strings to that target, checked on a real build) |
| Encryption | `ITSAppUsesNonExemptEncryption = false` — no export-compliance question on upload. The app does ship its own standard cryptography (TweetNaCl, "Семья" end-to-end), so `false` is right **only while the app is not on the App Store in France**: France was removed from Pricing and Availability on 2026-10-24 (174 territories remain), and App Store Connect then requires no encryption documentation — its API refuses a declaration "unless either containsProprietaryCryptography is True or containsThirdPartyCryptography and availableOnFrenchStore are both True". Re-adding France needs the ANSSI declaration first ([docs/STORE_DECISIONS_2026-10.md](STORE_DECISIONS_2026-10.md) §1.9) |
| Privacy manifest | `ios.privacyManifests` in `app.json` → `PrivacyInfo.xcprivacy` (UserDefaults: `CA92.1` own defaults, `1C8F.1` the app group); pods ship their own (RN core, Expo modules, RevenueCat, Sentry); the Safari extension has its own (UserDefaults `1C8F.1`, nothing collected) |
| Launch screen | `SplashScreen.storyboard` from the `expo-splash-screen` plugin entry in `app.json` (dark `#0f172a` + logo) |
| App icon | `assets/icon.png`, 1024², alpha removed at prebuild (App Store rejects transparent icons) |
| Payments | RevenueCat SDK (StoreKit). No other purchase path in the iOS app |

### 2.1 What the iPhone app does today

- **Check anything**: paste a link, type a site, scan a QR code → verdict. Same
  server check as Android.
- **Share → Cleanway** from any app (Safari, Messages, Mail, WhatsApp…): a link
  goes to the link check; text with a link is checked by its site name (the
  on-device message analyzer is Android-only, so the text itself never leaves
  the phone and is not analysed on iOS). Verified on the simulator for a Safari
  URL and for selected text. iOS lists the extension under the app's name,
  "Cleanway". A page Safari could not load is shared as a `data:` URL, not its
  address — the app then says "No link found"; copying the address works.
- History, Score, account (email code sign-in, devices, delete account),
  paywall, Family hub, weekly report, 10 languages.

### 2.2 What is hidden on iPhone (Android-only)

The "Every app" VPN shield and its pause sheet, Private DNS conflict card,
keep-protection-on card (battery / phone maker / Always-on), link checking
(default link handler) on home and in Settings, the call stop screen and "I'm
being called", the on-device SMS analyzer card, the APK update banner, Android
permission prompts. The rules live in `src/utils/platform-features.ts` and are
pinned by `mobile/scripts/test-platform-gating.mjs` (CI). Instead the home
screen shows **Protection on iPhone**: the Safari extension ("Set up" / "On"
→ §2.5), scam-text filter ("Set up" → §5) and DNS protection ("Set up" → §4),
and the hero says "Check before you tap"
instead of "Let's set up your protection — 0 shields active". The onboarding's
third slide is iPhone-specific. The paywall lists only what the iPhone build
can do (unlimited checks, devices).

### 2.3 iPad: off, on purpose

Every screen is a single portrait phone column; on an iPad with
`supportsTablet: true` Apple would require all four orientations (or
`UIRequiresFullScreen`), iPad screenshots (13"), and review on iPad. With
`supportsTablet: false` the iPhone app still installs on iPads (scaled), and
none of that is needed. Revisit when the layouts get a tablet pass.

### 2.4 Hooks for the next steps

- **Home card**: each layer reports `"coming" | "setup" | "on"` through
  `iosProtectionLayers({ dns: …, sms_filter: …, safari: … })` in
  `app/(tabs)/index.tsx`; `IosProtectionCard` takes an `onSetUp(id)` callback.
  Nothing else on home needs to change.
- **DNS protection**: built — §4.
- **Scam-text filter**: built — §5. The layer is "setup" (never "on": Apple
  gives the app no "is it enabled" API) and its row opens the setup steps.
- **Safari Web Extension**: built — §2.5.
- `mobile/native/ios/PacketTunnelProvider.swift` is the parked VPN experiment;
  it is not in any target.

### 2.5 The Safari Web Extension (in the app)

The same extension as Chrome / Firefox / the Mac's Safari, inside the iPhone
app. Nothing is duplicated: `packages/extension-core/` → `bash
scripts/build-extensions.sh` → `extension-safari/` → **copied at prebuild** by
`mobile/plugins/withSafariExtension.js` into
`ios/CleanwaySafariExtension/Resources/` (EAS runs prebuild on every build;
locally re-run prebuild after changing the extension). A missing tree fails
the prebuild.

| | |
|---|---|
| Target | `CleanwaySafariExtension`, app extension, point `com.apple.Safari.web-extension`, embedded in the app |
| Bundle id | `ai.cleanway.app.safari-extension` (EAS: `extra.eas.build.experimental.ios.appExtensions`, set by the plugin) |
| iOS | 16.4+ — the background is an ES-module service worker, which Safari supports from 16.4 (release notes: "Added support for modules in background service workers"). Since Expo SDK 56 the app is 16.4+ too. iPhone only, like the app |
| Entitlements | App group `group.ai.cleanway.app` only |
| Native half | `SafariWebExtensionHandler.swift` (generated by the plugin): answers `{type: "seen"}` by storing the time in the app group. Nothing about the page is sent or stored |
| Why our own plugin | One fixed target needs no new dependency (`@bacons/apple-targets` would add one plus a `targets/` convention); the other plugins here are ours too; it uses the same `xcode` project API Expo and expo-share-intent use |

**What differs on iPhone** (`packages/extension-core/src/utils/platform.js`
decides — `runtime.getPlatformInfo().os` is `ios`, else the user agent; tests
in `scripts/test-extension-core.mjs` group 6):

- **Background**: MV3 service worker, never persistent on iOS (Safari stops it
  after ~30 s idle and may kill it harder on device — iOS 17.4–17.6 had a bug
  that killed extension workers for good). Nothing depends on it staying
  alive: state is in `storage.local`, the in-memory verdict cache is just a
  cache, and the content scripts carry the offline scorer, so a page is still
  judged when the worker is gone.
- **Webmail scanner**: never on iOS. Settings removes the switch, the welcome
  page removes "Scan my inbox", and the background refuses to register the
  scanner even if the flag were set (`webmail-scanner.js`
  `webmailScannerBlockedHere`). docs/MOBILE_AUTO_PROTECTION.md.
- **Family Hub alerts**: Safari (Mac and iPhone) has no `notifications`, so the
  1-minute poll is not armed there — it would wake the worker every minute and
  take alerts off the server without showing them.
- **Context menu / keyboard command / toolbar badge**: not on iOS; already
  feature-checked (the background loads without them).
- **Popup**: opens as a sheet the width of the screen (`html.cw-ios`).
- **Storage**: `storage.local` only (settings, stats, tokens — kilobytes);
  history in IndexedDB, pruned to 30 days. No `unlimitedStorage`.
- **Permissions UI** (iOS 26, seen on the simulator): Settings → Apps →
  Safari → Extensions → "Cleanway — …" (the manifest's localized name) has
  the **Allow Extension** switch, "In Private Browsing", a "Settings" link (the
  options page) and **Permissions**: one row per host the manifest names
  (api.cleanway.ai, cleanway.ai) plus **Other Websites**, each Ask / Deny /
  Allow — older iOS calls the last one "All Websites". Safari asks per site
  until Other Websites is Allow. Its note "can read … passwords, phone numbers
  or credit cards" appears for every extension that runs on pages. The manifest's `notifications` and
  `contextMenus` are ignored by Safari on iOS (a console warning, no prompt).
  `nativeMessaging` (Safari tree only) shows no prompt.
- **Block page**: the content-script overlay (`content/block-page.js`) works
  unchanged; "Go back" uses history, else closes the tab.
- **Sign-in**: the popup's sign-in opens `cleanway.ai/<locale>/extension/connect`
  in a new Safari tab; `content/connect-relay.js` hands the session to the
  background as on desktop. It needs website access for cleanway.ai — granted
  by "Other Websites → Allow" (or cleanway.ai → Allow), otherwise Safari asks
  on that page.

**Status in the app** (`src/hooks/useSafariExtension.ts`,
`modules/cleanway-safari`, `safariLayerState()` in
`src/utils/platform-features.ts`):

- iOS 26.2+ answers "switched on?" (`SFSafariExtensionManager
  .getStateOfExtension`) and can open the extension's Settings page
  (`SFSafariSettings.openExtensionsSettings`). Older iOS has no API at all.
  Both calls answer once with a timeout (3 s / 5 s), so a call iOS never
  completes cannot leave the card waiting; it then falls back to the "seen"
  time. On the iOS 26.2 simulator the state followed the switch (off → "Turned
  off", on → "allow it on other websites"); `openExtensionsSettings` opened
  the Settings app at its top level rather than the extension's page —
  re-check both on a device.
- Website access has no API anywhere, so the extension tells the app: when a
  content script on a real page reaches the background (or the person opens
  cleanway.ai, which the extension never checks but reports from), the
  background sends `{type: "seen"}` through Safari's native messaging, at most
  every 6 h (`background/safari-native.js`); the handler stores the time.
- Card: switched off → "Set up" + "Turned off in Safari's settings"; on but
  never seen → "Set up" + "allow it on other websites"; seen in the last 14 days
  → **On**; older iOS and never seen → "Set up". "Set up" opens the steps
  (Settings → Apps → Safari → Extensions → Cleanway → Allow Extension; Other
  Websites → Allow), "Open Safari settings" (iOS 26.2+) and "Test it in
  Safari" (opens `cleanway.ai` in Safari via `x-safari-https://`; the card
  says On when the person comes back). The status is re-read whenever the app
  returns to the foreground.

**Verified on the iOS 26.2 simulator** (Xcode 26.3, 2026-10-09): see the PR
description for what was checked. Not verifiable in the simulator: the
service-worker life cycle on a real device — re-check on a device via
TestFlight before release.

### 2.6 Safari on the Mac (not in this app)

The Mac's Safari needs its own macOS app (a Safari extension cannot ship in an
iPhone-only app). The same `extension-safari/` tree, wrapped by Apple's
converter — docs/STORES.md §5:

```bash
bash scripts/build-store-artifacts.sh          # stages dist/store-artifacts/cleanway-<v>-safari/
xcrun safari-web-extension-converter dist/store-artifacts/cleanway-<v>-safari/ \
  --project-location /tmp/cleanway-mac --app-name Cleanway \
  --bundle-identifier ai.cleanway.safari --macos-only --swift
```

The converted project's handler ignores `{type: "seen"}` replies it does not
know; the extension treats a missing answer as "no app around" and tries
again later, so nothing breaks. A universal (Mac + iPhone) Xcode project from
the converter is not used: the iPhone side is this Expo target.

---

## 3. App Store Connect — founder checklist

### 3.1 Account: Individual is enough

| | Individual (today) | Organization |
|---|---|---|
| Ship the app, share extension, IAP subscriptions | Yes | Yes |
| DNS settings (`NEDNSSettingsManager`), SMS filter, Safari extension | Yes | Yes |
| A real VPN (`NEPacketTunnelProvider`) | **No** (App Review 5.4) | Yes |
| Seller name on the App Store | Your legal name | The company |
| Needs | Apple ID + $99/yr | D-U-N-S number, legal entity, $99/yr |

Decision 2026-10-10: the founder's company publishes. The whole account
(Team ID `29LQWL23VQ`, all apps) converts to an Organization through Apple
Developer support — steps and request text in
`docs/runbooks/company-accounts.md`. Paid Apps agreement, banking, tax and the
subscriptions wait for the conversion.

### 3.2 Identifiers (developer.apple.com → Certificates, IDs & Profiles)

EAS creates these on the first `eas build` if you let it log in; to do it by hand:
1. App ID `ai.cleanway.app` with capabilities **App Groups** → `group.ai.cleanway.app`
   and **Network Extensions** (DNS protection, §4; EAS turns it on from the
   entitlement when it manages the profile).
2. App ID `ai.cleanway.app.share-extension` with the same App Group.
2a. App ID `ai.cleanway.app.sms-filter` (the scam-text filter) with the same
   App Group. No other capability: a message filter needs no entitlement, and
   it has no network URL (§5).
2b. App ID `ai.cleanway.app.safari-extension` with the same App Group (the
   Safari extension; EAS creates it from `extra.eas…appExtensions`).
3. Do **not** enable Push Notifications (the app uses none on iOS).

### 3.3 The app record

1. Done 2026-10-09: App Store Connect record "Cleanway: Scam Protection"
   (plain "Cleanway" is taken on the App Store; the home-screen name stays
   "Cleanway"), bundle id `ai.cleanway.app`, SKU `cleanway-ios`, primary
   language English (U.S.), Apple ID `6821030874` — in `mobile/eas.json` →
   `submit.production.ios.ascAppId`. App Group `group.ai.cleanway.app` is
   registered and assigned to all four App IDs.
2. Category: Utilities (or Productivity). Age rating questionnaire: no
   objectionable content → 4+.
3. Privacy Policy URL `https://cleanway.ai/privacy-policy`; Terms (EULA)
   `https://cleanway.ai/terms` — App Store requires both for subscriptions
   (the paywall links them too). Support URL `https://cleanway.ai`.
4. Account deletion: in the app (Settings → Delete account, and Account →
   Delete account). Mention it in review notes.
5. **Pricing and Availability → Countries or Regions: every territory except
   France. Russia stays on the list.** Decision 2026-11-04: worldwide launch
   that does not wait for Russia; founder's clarification 2026-11-11: the app
   stays available in Russia, paid plans are simply not expected to sell there
   (App Store payments mostly do not work in Russia). France is off since
   2026-10-24 (encryption declaration, §2 table). Check the list before every
   submission (174 territories were on on 2026-10-24). The subscriptions
   (§3.4) follow the app's availability, so no separate country setting is
   needed for them.

### 3.4 In-app purchases (Subscriptions)

The server already knows these ids (`api/services/store_products.py`):

| Group | Product id | Period | Grants |
|---|---|---|---|
| `Cleanway` | `cleanway.devices.monthly` | 1 month | Personal plan (3 devices) |
| `Cleanway` | `cleanway.devices.yearly` | 1 year | Personal plan |
| `Cleanway devices` (separate group) | `cleanway.extra_device.monthly` / `.yearly` | — | +1 device (not sold in the app yet) |

**Prices (founder decision 2026-11-04: US$1.99 a month in every country).**
Apple no longer has numbered "price tiers"; it has price points. For each
subscription: App Store Connect → the app → Subscriptions → group `Cleanway` →
the product → Subscription Prices → Add Subscription Price → base country
**United States**, price **USD 1.99** → Next: Apple fills every other storefront
with its equalized local price for the same point (keep them, do not edit
countries by hand — "the same price everywhere" is exactly Apple's
equalization) → Confirm.

| Product | Base price (United States) | Note |
|---|---|---|
| `cleanway.devices.monthly` | USD 1.99 | the founder's price |
| `cleanway.devices.yearly` | USD 19.99 | approved by the founder 2026-11-11 (≈ 2 months free), already created in App Store Connect; the paywall shows only what the `default` offering has |
| `cleanway.extra_device.*` | — | not sold in the app yet: no need to create before it is |

Introductory offer (free trial): do **not** add one unless the founder says so —
the app already gives 7 days with everything unlocked, then 5 free manual checks
a month (server settings), and a store trial on top would double it. The app never types a
price: it shows StoreKit's own string (RevenueCat `priceString`), so a price change
here needs no new build. Apple's price changes for existing subscribers follow
Apple's rules (notice, consent for an increase) — irrelevant before the first sale.

Then in RevenueCat (runbook §3, §9): add the App Store app, upload the
In-App Purchase key (`.p8`), set App Store Server Notifications V2 to
RevenueCat's URL, attach both plan products to the `unlimited` entitlement and
to the `default` offering (monthly + annual packages). Copy the **public**
`appl_…` key into `EXPO_PUBLIC_REVENUECAT_IOS_KEY`. Fill the **Paid Apps
agreement**, banking and tax in App Store Connect first — products stay
"Missing Metadata" without it. Each subscription needs a review screenshot of
the paywall.

What the app already does for review — **in a build made with the `appl_…`
key only**; without it the app has no paywall, no prices and no "Restore
purchases" at all (`PAID_PLANS_OFFERED`, §3.6): prices only from StoreKit,
"Restore purchases" on the paywall and the account screen, "Manage subscription" opens
Apple's subscriptions page, small print under the button (billed to Apple ID,
auto-renews unless cancelled 24 h before the period ends, cancel in Settings),
Terms + Privacy links, no link to the web checkout anywhere in the iOS build,
and for App Store subscribers the account screen explains that only Apple can
cancel the subscription and that deleting the account does not.

**No account needed to buy or restore** (#344; the founder answered "Б" on
2026-11-11 — `docs/STORE_DECISIONS_2026-10.md` §3).
App Review 5.1.1(v) rejects an app that asks for an account before an in-app
purchase its main function does not need. So, signed out, the purchase and
"Restore purchases" run under RevenueCat's anonymous id. The phone keeps its
own App Store plan from RevenueCat (`storePlanActive`,
`mobile/src/utils/store-billing.ts`). It counts that plan signed in too, so
the iPhone that paid stays unlimited even when the account's 3 device seats
are taken (3.1.2(a)). After the purchase the paywall offers sign-in as
optional, to use the plan in the Android app and the browser extension, and a
"Have a Cleanway account? Sign in" link stays under Restore so someone paying
elsewhere does not buy twice. On sign-in `Purchases.logIn` merges the
anonymous buyer into the account. When it does not (the account already has
an anonymous alias of its own — nearly every account, the review account
included), the app calls `Purchases.syncPurchasesForResult()`, a restore
without an Apple ID prompt, so the plan follows the account; if even that
fails, the phone keeps the plan it paid for and suggests "Restore purchases".
The app then asks the server to re-read the account (`/me/entitlement/refresh`,
retried until it answers — the server needs `REVENUECAT_SECRET_API_KEY`).
Signed out, a purchase or restore on an iPhone where someone signed in before
first asks whether to continue without signing in (it would move the
subscription off that account), and signing out says the plan stays in the
account. Family Sharing stays off for these subscriptions. Android is
unchanged (sign in first). Details and edge cases: runbook §9 and §9.1.

Sandbox testing: App Store Connect → Users and Access → Sandbox testers; sign
in on the device under Settings → App Store → Sandbox Account. The simulator
can use a StoreKit configuration file, but RevenueCat needs real sandbox
receipts for the server webhook — test on a device via TestFlight. The
TestFlight checklist for buying without an account (buy signed out; reinstall
and restore signed out; sign in and see the plan on Android and in the
extension; the same with an account that does not merge, such as the review
account; sign out and restore; a full device list; offline right after
sign-in) is in `docs/runbooks/revenuecat.md` §9.1.

### 3.5 App Privacy ("nutrition labels")

Answer from the real egress (same facts as `docs/RUSTORE_SUBMISSION.md` §3):

| Apple data type | Collected | Linked to the user | Tracking | Purpose |
|---|---|---|---|---|
| Contact Info → Email Address | Yes, only when the person signs in | Yes | No | App Functionality |
| Identifiers → User ID (account id) | Yes, when signed in | Yes | No | App Functionality |
| Identifiers → Device ID (random device id of the account's device list; daily-rotating install number for rate limits) | Yes | Device id: Yes · install number: No | No | App Functionality |
| Browsing History (site names the person checks — never full URLs, no account token on the check; with DNS protection on, every name the iPhone looks up goes to the DNS gateway, §4.3) | Yes | No | No | App Functionality |
| Purchases → Purchase History (App Store subscription via RevenueCat) | Yes, when subscribing | Yes | No | App Functionality |
| Diagnostics → Crash Data (Sentry, only when a DSN is set) | Yes | No | No | App Functionality |

Not collected: location, contacts, photos, messages (shared message text stays
on the phone), audio, health, financial info, advertising data. No tracking,
no ad SDKs, no ATT prompt. Re-check before submitting if the Family hub or the
weekly report send anything new.

**The sign-in captcha is now inside the app.** Since 1.0.6 (build 5) the
on-demand "I'm not a robot" page (`https://cleanway.ai/auth/captcha`, Cloudflare
Turnstile) opens in an in-app sheet (`ASWebAuthenticationSession`, ephemeral —
`mobile/modules/cleanway-safari`), not in Safari. Apple: "Data collected via
web traffic must be declared, unless you are enabling the user to navigate the
open web" — this is our own page, so "it opens in the browser" no longer
excuses it. Today it changes nothing: Supabase captcha is off, so the app never
opens the page and Cloudflare gets nothing from the app. **Before switching
captcha on** (docs/MOBILE_AUTH.md, captcha order step 4), decide the entry for
what Turnstile sees — the IP address and browser signals, to tell a person from
a bot. Apple says to declare an IP address by how it is used (coarse location,
device ID, diagnostics…); the purpose is App Functionality ("prevent fraud,
implement security measures"), not linked to the user, no tracking. The
cautious answer is to add it (e.g. Other Data, Not linked, App Functionality)
rather than to rely on Cloudflare not keeping it.

### 3.6 Review notes (paste into "Notes")

**Which text for which build.** For **1.1.0 (iOS build 7) and later**, paste
the block below as it is: its last paragraph, the one that starts "VPN
(2.1):", is the one for build 7+. Pasted, the block is 3,808 characters of the
4,000 App Review allows (3,824 with the In-App Purchase sentence swapped in,
below; counted with each paragraph's lines joined, a blank line between
paragraphs and no backticks); count again after any edit. The Notes that went
with **1.0.6 (6)** on 2026-11-02 differed only in that paragraph; it is kept
as history after the reply, marked "do not paste". Before pasting for build 7,
repeat on its archive the whole search of docs/EXPO_UPGRADE_PLAN.md §10.4 —
every file of the app, the UTF-16 strings of `main.jsbundle` and the
EXConstants config — and attach the output to the 1.1.0 PR (#327). Done on the
build 7 archive on 2026-11-03, after #392, with the expected output below
(the #327 checklist); repeat on any rebuilt archive. With `$M` the mirror of
§1.1:

```bash
A="$M/Cleanway.xcarchive/Products/Applications/Cleanway.app"
# Every file in the app — its executable, Frameworks/, PlugIns/*.appex and
# their resources — for the word as it is written (VPN, Vpn, vpn; ASCII).
LC_ALL=C grep -rcaE 'VPN|Vpn|vpn' "$A" | grep -v ':0$'   # no output
# The bundle's UTF-16 strings: only the Settings path ("General → VPN &
# Device Management → DNS" and its translations: 2 keys × 10 locales).
python3 -c 'import sys; print(open(sys.argv[1],"rb").read().count("VPN".encode("utf-16-le")))' "$A/main.jsbundle"   # 20
LC_ALL=C grep -aci vpn "$A/EXConstants.bundle/app.config"  # 0: no BIND_VPN_SERVICE in the app's config
# A case-insensitive search (grep -rcai vpn) also finds byte noise, none of it
# a word (build 7, 2026-11-03): main.jsbundle 2 ("…IUvpNINCwL…", a sample AWS
# request id in @sentry/conventions, and "vPn" inside bytecode), Cleanway 1
# (code-signature bytes; they change when the app is re-signed), hermesvm 2
# and ReactNativeDependencies 2 (C++ mangled names: "…IFvPN6hermes…",
# "…EEvPNSt3__1…"). Anything else: find out what matches and record it here
# before pasting.
# Build 8 (2026-11-11, ios-1.1.0-8-archive-checks.txt): the three searches
# above as expected (no output, 20, 0); case-insensitive: main.jsbundle 1
# ("…IUvpNINCw…"), Cleanway 0, hermesvm 2, ReactNativeDependencies 2.
# Build 9 (2026-11-12, ios-1.1.0-9-archive-checks.txt): the same as build 8.
```

> Cleanway checks links and text messages for scams. No account is needed:
> paste a link or a message on the home screen, or share one to Cleanway from
> Safari or Messages. A message is checked on the device and never sent; only
> the site names of its links go to our server. Sign-in is optional and is by
> a one-time code sent to email. To review it, use the account in Sign-In
> Information: Settings → Sign in → type review@cleanway.ai — for this address
> only, a Password field appears instead of the emailed code; enter the
> password and tap Sign in. Account deletion: Settings → Delete account.
> This version has no in-app purchases: no paywall, no prices and nothing
> to buy in the app. The app
> contains no VPN. All three "Protection on iPhone" items (Safari extension,
> scam-text filter, DNS protection) work in this version; each needs a switch
> the user turns on in Settings, which the app explains step by step.
>
> DNS protection (home → Protection on iPhone → DNS protection → Set up) uses
> the public DNS Settings API (NEDNSSettingsManager with
> NEDNSOverHTTPSSettings, Network Extensions entitlement value
> `dns-settings`). It is not a VPN: there is no tunnel, no NEVPNManager and no
> Network Extension provider target. The app saves an encrypted DNS-over-HTTPS setting
> pointing at our resolver, https://dns.cleanway.ai/dns-query, which answers
> NXDOMAIN for known scam and phishing sites and forwards every other name to
> Cloudflare's DNS. Nothing changes until the user selects "Cleanway" in
> Settings → General → VPN & Device Management → DNS. Before the user adds
> it, the app explains that site names are sent to our DNS server (the
> matching happens on our server) and that our server keeps no log of them;
> our host's standard request logs can include the IP address and requested
> URL — privacy policy, section 11. The user can remove it in the app, or
> choose "Automatic" on the same Settings page, at any time.
>
> The scam-text filter is an SMS filter extension. On iOS 26, enable it in
> Settings → Apps → Messages: under Unknown Senders turn on Screen Unknown
> Senders, then tap Text Message Filter → Cleanway (Text Message Filter is
> greyed out until Screen Unknown Senders is on). On iOS 18: Settings → Apps
> → Messages → Unknown & Spam → SMS Filtering → Cleanway. It works
> offline — it has no network URL and never sends a message anywhere — and
> moves only texts it judges a scam to Junk.
>
> The Safari Web Extension warns about scam sites: Settings → Apps → Safari →
> Extensions → Cleanway → Allow Extension, then Other Websites → Allow; open
> any site in Safari (or the home screen's "Set up" → "Test it in Safari").
> It sends the names of the sites it checks to api.cleanway.ai; it has no
> purchases or upsell of its own.
>
> VPN (2.1): no VPN, no tunnel, no NEVPNManager/NETunnelProviderManager, no
> Network Extension provider target. NetworkExtension.framework is used only
> for the DNS Settings API (entitlement "dns-settings"), which iOS lists under
> VPN & Device Management; that Settings path is the only "VPN" in the app's
> text. The app's DNS module is "CleanwayDns" (save, read, remove the
> setting). Since 1.1.0 the native module, the Android-only text that names
> VPN and the BIND_VPN_SERVICE permission of our Android app's VPN-based
> filter are not in the iOS build.
> With DNS protection on, our server gets DNS queries (name, record type) and
> the request's IP. It logs no names or IPs. It keeps aggregate counters, an
> in-memory answer cache keyed by the question only, and an hourly rate-limit
> count under a keyed hash of the IP. Unblocked, uncached names go to
> Cloudflare from our server. Railway hosts us (EU West); its edge nearest the
> user ends HTTPS and keeps request logs that can include the IP and URL (a
> GET query's URL holds the name). iOS 26+ may fall back to the network's DNS.
> No sale, ads or profiling.

**"The app contains VPN functionality" (2.1, 2026-10-30).** App Review's
automated analysis flagged 1.0.4 (3) and asked what user information the
"VPN" collects, why, and who else gets it. Likely triggers: the
`dns-settings` Network Extensions entitlement with NetworkExtension.framework
linked, the `CleanwayVpn` module name (`modules/cleanway-vpn`, startVpn/stopVpn
are no-ops on iOS) and the Android-only VPN strings in `i18n/en.json`, which
the iOS bundle carries but never shows. The reply below went on 2026-11-02
(founder's «да»), the VPN paragraph above was added to Notes first because the
reply says so, and the submission moved to 1.0.6 (6). Every statement was
checked against the code (`api/routers/doh.py`, `api/services/doh_*.py`,
`api/services/logger.py`, `modules/cleanway-vpn/ios/CleanwayVpnModule.swift`).
Re-check it before reusing: GET vs POST from iOS and what Railway's request
logs keep were not verified (the Railway session had expired); renaming the
module or dropping the Android strings from the iOS bundle changes the second
paragraph; a change to the DoH cache, rate limiter, upstreams or logging
changes "2." and "3.". (Below: the reply as recorded when it went, the Notes
paragraph that went with it, then what changed for 1.1.0.)

> Hello,
>
> Cleanway has no VPN features: no tunnel, no NEVPNManager or
> NETunnelProviderManager, and no Network Extension provider target (packet
> tunnel, app proxy, DNS proxy or content filter). Its extensions are a share
> extension, an SMS filter and a Safari Web Extension.
>
> The app uses only the DNS Settings API (NEDNSSettingsManager,
> NEDNSOverHTTPSSettings, entitlement value "dns-settings"). The analysis most
> likely matched that entitlement and framework and our native module
> "CleanwayVpn", shared with our Android app. On iOS its startVpn/stopVpn do
> nothing, and Android-only VPN text in the shared code is never shown. iOS
> also lists DNS settings under VPN & Device Management.
>
> When the user taps "Add to iPhone", the app saves one encrypted DNS setting
> for https://dns.cleanway.ai/dns-query. It stays off until the user selects
> "Cleanway" in Settings > General > VPN & Device Management > DNS, and can be
> removed in the app or there at any time.
>
> 1. What is collected
> The app itself receives no DNS data. While the setting is on, iOS sends our
> server the device's DNS queries: standard DNS messages with the name looked
> up (e.g. example.com) and record type. Never a page link or content, other
> traffic, or an account or device identifier. Our server sees each request's
> IP address.
>
> 2. Purposes
> To answer NXDOMAIN for known scam and phishing sites and resolve all other
> names. The IP address is used only to reply and to rate-limit abuse. No ads,
> profiling or sale.
> Our server writes no log of names or IP addresses. It keeps aggregate
> counters; recent answers in memory, keyed by the question, never by who
> asked (served for at most the TTL, max 1 hour, +6 hours if the upstream
> fails; dropped when replaced, evicted or on restart); and an hourly
> rate-limit count under a keyed hash of the IP, never with a name.
>
> 3. Third parties and storage
> - Cloudflare's public DNS resolver gets names that are neither blocked nor
>   cached, from our server's IP, not the user's, under Cloudflare's resolver
>   privacy policy.
> - Railway hosts our server (EU West, Amsterdam) and the database the filter
>   checks names against (no IP). HTTPS ends at Railway's edge nearest the
>   user, possibly outside the EU. Railway's standard request logs can include
>   the IP and requested URL, which for an HTTP GET query contains the encoded
>   name; Railway's retention applies.
> Our server shares queries with no one else. On iOS 26+, if it does not
> answer, iOS may use the network's own DNS.
>
> We have added this to App Review Information.

**History — the Notes "VPN (2.1)" paragraph as pasted for 1.0.6 (6) on
2026-11-02, before the reply went** (the narrative's "the VPN paragraph
above"; do not paste it for build 7 — that build has no `CleanwayVpn` and no
startVpn/stopVpn):

> VPN (2.1): no VPN, no tunnel, no NEVPNManager/NETunnelProviderManager, no
> Network Extension provider target. Only the DNS Settings API (entitlement
> "dns-settings"), which iOS lists under VPN & Device Management. The native
> module "CleanwayVpn" is shared with Android; on iOS startVpn/stopVpn do
> nothing and Android-only VPN text is never shown. With DNS protection on,
> our server gets DNS queries (name, record type) and the request's IP. It
> logs no names or IPs. It keeps aggregate counters, an in-memory answer cache
> keyed by the question only, and an hourly rate-limit count under a keyed
> hash of the IP. Unblocked, uncached names go to Cloudflare from our server.
> Railway hosts us (EU West); its edge nearest the user ends HTTPS and keeps
> request logs that can include the IP and URL (a GET query's URL holds the
> name). iOS 26+ may fall back to the network's DNS. No sale, ads or
> profiling.

**1.1.0 (build 7 and later): what changed for the "VPN" question.** After
the reply went, four PRs took out of the iPhone build the parts of the
Android shield that name VPN: its native module, its four VPN strings,
`BIND_VPN_SERVICE` and the `vpn-…` icon names (in `main` on SDK 54, in 1.1.0
with the SDK 58 merge; docs/EXPO_UPGRADE_PLAN.md §10.4). The rest of the
shield still ships in the iPhone bundle, without the word: its shared JS
(`modules/cleanway-vpn/index.ts`, `useNetworkShield`, `KeepAliveCard` and
others) under neutral names, and its other on-screen text (#387 below). The
reply's second paragraph ("native module CleanwayVpn … startVpn/stopVpn")
describes 1.0.6 (6) and earlier; the Notes paragraph for build 7+ above and
the reply below say what 1.1.0 carries.

- #388: the iPhone's DNS protection is its own iOS-only module, `CleanwayDns`
  (`modules/cleanway-dns`); `CleanwayVpn` (`modules/cleanway-vpn`) is
  Android-only (`mobile/scripts/test-ios-native-modules.mjs`). The shared
  JS's names no longer say VPN: `startShield`/`stopShield`/`isShieldRunning`
  and the rest are neutral, and the Kotlin names live only in
  `modules/cleanway-vpn/src/native.android.ts`, which the iOS bundle does not
  include (`mobile/scripts/test-no-vpn-names.mjs`; its allowlist still names
  `mobile.ios.dns.note_vpn`, which #387 renamed to `note_other_dns` without
  the word, so nothing uses that exception).
- #387: the four Android-only strings (the VpnService disclosure, the
  "permission taken back" notice, the two Always-on VPN rows) live in
  `mobile/i18n/android/`, which only `src/i18n/resources.android.ts` imports,
  and the landing and email strings are no longer in the mobile JSON. In the
  strings the iPhone carries, "VPN" is left only in
  `mobile.ios.dns.step_on_body` and `mobile.ios.dns.error_remove`: Apple's
  Settings path, in all 10 languages (`mobile/scripts/test-ios-strings-no-vpn.mjs`).
  The rest of the Android shield's text stays in `i18n/{locale}.json`, which
  `src/i18n/resources.ts` imports on the iPhone too, in all 10 languages: 51
  `mobile.shield.*` keys ("Every app", the Private DNS and pause states, "How
  the shield works"), 42 `mobile.keep_alive.*` (battery and keep-protection
  rows) and 29 `mobile.android_native.*` (the foreground notification and
  block alerts). None of them says VPN.
- #386: `BIND_VPN_SERVICE` is declared in
  `modules/cleanway-vpn/android/src/main/AndroidManifest.xml` instead of
  `app.json`, so `expo-constants` no longer copies it into the iPhone app's
  config (`mobile/scripts/check-android-permissions.mjs`).
- #389: icons are imported per family, so the bundle carries no `vpn-key` or
  `vpn-lock` names (`mobile/scripts/check-icon-imports.mjs`).

What stays, because DNS protection needs it: NetworkExtension.framework and
the `dns-settings` entitlement (`plugins/withIosAppStore.js`; only
`CleanwayDnsModule.swift` imports NetworkExtension). The automated analysis
can flag 1.1.0 for them again, so the Notes keep the VPN paragraph. Gone
since #392: the SMS filter's `message_model.json` (copied from
`modules/cleanway-vpn/android/src/main/assets` into
`PlugIns/CleanwaySmsFilter.appex` and `CleanwayMessageEngineAssets.bundle`)
named 8 files under `mobile/modules/cleanway-vpn/` in its `data_sha256`; it
now names them from the module's `src/` (`ml/sms/data.py` `provenance_key`),
and `mobile/scripts/test-ios-sms-filter.mjs` keeps the shared text assets
free of "vpn". Checked on the build 7 archive (SDK 58, 2026-11-03): no
VPN/Vpn/vpn in any file of the app, UTF-16 "VPN" only in the Settings path,
none in the EXConstants config. Repeat the searches at the top of §3.6 on any
rebuilt archive before pasting the build 7+ paragraph or sending the reply
below.

If App Review asks about the "VPN" again for 1.1.0, reply with the text below.
Re-check it first, as for the 1.0.6 reply: GET vs POST from iOS and what
Railway's request logs keep are still unverified, and a change to the DoH
cache, rate limiter, upstreams or logging changes its "While it is on"
paragraph. It is shorter than the 1.0.6 reply and carries the same data
facts; send the longer one (with its second paragraph replaced by this
reply's second) if they ask the three questions point by point again.

> Hello,
>
> Cleanway has no VPN features: no tunnel, no NEVPNManager or
> NETunnelProviderManager, and no Network Extension provider target (packet
> tunnel, app proxy, DNS proxy or content filter). Its extensions are a share
> extension, an SMS filter and a Safari Web Extension.
>
> The app links NetworkExtension.framework only for the DNS Settings API
> (NEDNSSettingsManager, NEDNSOverHTTPSSettings, entitlement value
> "dns-settings"), which iOS lists under VPN & Device Management. That
> Settings path, which the app names where it explains the DNS setting, is
> the only "VPN" in the app's text. In version 1.1.0 the DNS setting has its
> own iOS module, "CleanwayDns", and the native module, the Android-only text
> that names VPN and the BIND_VPN_SERVICE permission of our Android app's
> VPN-based filter are not in the iOS build.
>
> The app saves one encrypted DNS setting for
> https://dns.cleanway.ai/dns-query. It stays off until the user selects
> "Cleanway" in Settings > General > VPN & Device Management > DNS, and can be
> removed in the app or there at any time.
>
> While it is on, iOS sends our server the device's DNS queries (the name
> looked up and the record type; never a page link or content, other traffic,
> or an account or device identifier), and our server sees each request's IP
> address. They are used only to answer NXDOMAIN for known scam and phishing
> sites, to resolve all other names and to rate-limit abuse. Our server writes
> no log of names or IP addresses; it keeps aggregate counters, recent
> answers in memory keyed by the question only, and an hourly rate-limit
> count under a keyed hash of the IP. Names neither blocked nor cached go to
> Cloudflare's public DNS resolver from our server's IP, not the user's.
> Railway hosts our server (EU West, Amsterdam); HTTPS ends at its edge
> nearest the user, and its standard request logs can include the IP and the
> requested URL, which for a GET query contains the name. On iOS 26+, if our
> server does not answer, iOS may use the network's own DNS. No ads,
> profiling or sale.
>
> The same is in App Review Information.

**Purchases: which sentence.** The Notes block at the top of §3.6 is for a
build made **without** `EXPO_PUBLIC_REVENUECAT_IOS_KEY` — every iPhone build
up to 1.1.0 (7) (1.0.6 builds 5 and 6 checked on 2026-10-25: no `appl_` key in their
bundles; check a new one with §1.1). **1.1.0 (8)** (2026-11-11) is made with
the key — its check prints "sells" — so its Notes take the In-App Purchase
sentence below, and its subscriptions must be attached to the version. `PAID_PLANS_OFFERED` is false there: the paywall sends anyone who
reaches it home (`app/paywall.tsx`), Settings has no Plan row, Account shows
the plan as "Free" with no Upgrade, and "Restore purchases" appears only when
App Store billing is on (`storeBillingOn()`, `app/account.tsx`). Attach **no**
in-app purchase or subscription to such a version in App Store Connect (the
version page's "In-App Purchases and Subscriptions" section stays empty). Only
for a build made with the public `appl_…` key (§1.2, §3.4) and with its
subscriptions attached to the version, replace the sentence "This version has
no in-app purchases: …" with the sentence for that build:

- built from `feat/iap-without-account` (buying without an account, §3.4 —
  after the founder's "Б"; `docs/STORE_DECISIONS_2026-10.md` §3.7):

  > Subscriptions are sold only through In-App Purchase and can be bought
  > and restored without an account. Signing in (a one-time code by email)
  > is optional: it lets the same subscription work in the Cleanway Android
  > app and browser extension and manage up to 3 devices. A subscription
  > bought without an account moves to the account when you sign in, the
  > demo account in Sign-In Information included. "Restore purchases" is on
  > the paywall and on the Account screen. On an iPhone where an account was
  > used before, buying or restoring while signed out first asks whether to
  > continue without signing in, because the subscription would then leave
  > that account.

- built before it (the paywall still asks to sign in first — answer "А" or
  "В"):

  > Subscriptions are sold only through In-App Purchase; "Restore purchases"
  > is on the paywall and in Account.

Sign-In Information (App Review Information → **Sign-in required**): user
name `review@cleanway.ai`, password from the macOS Keychain — create the
account and rotate the password with `python3 scripts/create_review_account.py`
(`docs/runbooks/app-review-account.md`). Email-code sign-in fails review when
the reviewer cannot receive the code, so the build carries
`EXPO_PUBLIC_REVIEW_EMAILS=review@cleanway.ai` (`mobile/eas.json`, preview and
production): for that exact address the sign-in screen asks for a password
instead; every other address keeps the code. Only builds made with the
variable have the password field (the first one after 2026-10-23) — for an
older binary say instead that sign-in is optional. If the reviewer deleted the
account while testing deletion, it is on hold for 30 days: sign-in works, but
every API call answers 410 and the app shows "Account on hold" — a new
password alone does not bring it back. Before the next submission re-run the
script as usual: after the new password it signs in as the review account and
taps "Restore my account" for it (POST /api/v1/user/account/restore). If that
step fails (`restore error`), sign in as the review account in the app and tap
"Restore my account" yourself. Past 30 days the purge removes the account and
the next run creates it anew (runbook: "Если проверяющий удалил аккаунт").

### 3.7 Screenshots and listing

iPhone 6.9" (1320×2868 or 1290×2796) is the only required size with
`supportsTablet: false`. Never show the Settings "VPN & Device Management"
page or the word "VPN" in screenshots or the description; call the feature
"DNS protection" or "encrypted DNS", never a VPN (5.4 misfile risk). The
setup sheet names that Settings page in-app only, because it is Apple's own
label. Say "filters scam texts (SMS) from unknown senders"; never "blocks all
scam texts" or anything about iMessage — iOS shows the filter only SMS/MMS
from numbers not in the contacts, and iMessage is invisible to any app.

---

## 4. DNS protection (NEDNSSettingsManager)

Built on `feat/ios-dns-settings` (2026-10-09). An Individual account cannot
filter DNS on the phone (a local tunnel is a VPN — App Review 5.4), so the
iPhone uses iOS's system-wide **encrypted DNS settings**, pointed at the
existing DoH gateway.

### 4.1 What is in the code

| Piece | Where |
|---|---|
| Native: save / read / remove the configuration, change notice | `mobile/modules/cleanway-dns/ios/CleanwayDnsModule.swift` — its own iOS-only module `CleanwayDns` (`CleanwayDnsSettings`; JS names `dnsSettingsStatus`, `installDnsSettings`, `removeDnsSettings`, event `onDnsSettingsChanged`). Android's shield module (`modules/cleanway-vpn`) has no iOS half |
| JS bridge + report parser | `modules/cleanway-dns/index.ts` (`isIosDnsSupported`, `iosDnsStatus`, `installIosDns`, `removeIosDns`, `addIosDnsChangedListener`; the native module is optional and asked for on iOS only), `modules/cleanway-dns/src/IosDnsSettings.ts` |
| State machine (pure) | `src/utils/ios-dns.ts` — phases `unavailable → checking → add → turn_on → on`, the sheet model, the error wording |
| Live hook | `src/hooks/useIosDnsProtection.ts` — reads iOS on mount, on every foreground (back from Settings) and on `NEDNSSettingsConfigurationDidChange` |
| UI | home card row "DNS protection" (`IosProtectionCard`: "Set up" / check mark — both open the sheet) → `src/components/shield/IosDnsSetupSheet.tsx`; home privacy line and hero follow it |
| Entitlement | `com.apple.developer.networking.networkextension = ["dns-settings"]`, added by `plugins/withIosAppStore.js` (VPN values stripped) — no `app.json` change |
| Tests (CI) | `mobile/scripts/test-ios-dns.mjs`, `mobile/scripts/test-platform-gating.mjs`, `mobile/scripts/test-ios-native-modules.mjs` |

The configuration: `NEDNSOverHTTPSSettings(servers: [])`, `serverURL =
https://dns.cleanway.ai/dns-query`, `localizedDescription = "Cleanway"`, no
on-demand rules, and on iOS 26+ `allowFailover = true`.

### 4.2 Decisions, with sources

- **Entitlement and account.** `dns-settings` is a value of the Network
  Extensions entitlement: "The APIs you use to create and manage a
  system-wide DNS configuration"
  ([Apple: Network Extensions Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)).
  The Network Extensions capability is ticked for **ADP** (Apple Developer
  Program — Individual and Organization memberships alike) and ADEP; only the
  free "Apple Developer" tier lacks it
  ([Supported capabilities (iOS)](https://developer.apple.com/help/account/reference/supported-capabilities-ios),
  checked 2026-10-09). The Organization-only rule is App Review 5.4, about
  apps "offering VPN services" that "must utilize the NEVPNManager API"
  ([App Review Guidelines 5.4](https://developer.apple.com/app-store/review/guidelines/#vpn-apps));
  this feature uses neither. No extension target: "since we're configuring a
  protocol that's supported by the system, we don't need to implement an
  extension point" ([WWDC20 "Enable encrypted DNS"](https://developer.apple.com/videos/play/wwdc2020/10047/)).
- **The person turns it on, not the app.** `isEnabled` is read-only;
  "configurations are disabled until the user enables the configuration in
  the Settings app"
  ([isEnabled](https://developer.apple.com/documentation/networkextension/nednssettingsmanager/isenabled)).
  On iOS 26.2 the page is Settings → General → **VPN & Device Management** →
  DNS. There is no public deep link to it: the sheet's "Open Settings" uses
  `Linking.openSettings()` (Cleanway's own page) and step 2 says where to go
  from there. No `App-Prefs:` URLs (private API, review risk).
- **No server IP addresses.** For DoH, "if no ServerAddresses are provided,
  the system uses the hostname or address in the URL to determine the server
  addresses"
  ([DNSSettings payload, ServerURL](https://developer.apple.com/documentation/devicemanagement/dnssettings/dnssettings-data.dictionary)
  — the settings NEDNSOverHTTPSSettings carries). `dns.cleanway.ai` is a
  CNAME to Railway's edge (`ics2mtji.up.railway.app` → 69.46.46.49 on
  2026-10-09, and it answers RFC 8484 GETs); pinned Railway addresses would
  break every lookup the day Railway changes them.
- **No on-demand rules.** Without rules the setting applies on every
  network. Captive-network login (hotel / café Wi-Fi) "is automatically
  granted an exception" (WWDC20). A "disconnect on cellular/Wi-Fi" rule would
  only switch protection off where it matters. Forum reports of portals that
  still fail behind encrypted DNS are why the sheet says "If sites stop
  opening, choose Automatic…".
- **Failover on iOS 26+.** `NEDNSSettings.allowFailover` — "failover to the
  default system resolver is permitted on resolution failure", iOS 26.0+ — is
  set, matching the gateway's own fail-open policy: a gateway outage must not
  take every iPhone offline. Guarded by `#if compiler(>=6.2)` and
  `#available(iOS 26.0, *)`, so an older Xcode (an older EAS image) still
  builds. Below iOS 26 an outage fails lookups until the person picks
  "Automatic".
- **Errors.** Every native call resolves with a report (`installed`,
  `current`, `enabled`, `error`, `message`), never a rejection. The
  `NEDNSSettingsManagerError` codes map to `invalid` / `disabled` / `stale` /
  `cannot_remove`; anything else (e.g. a build without the entitlement) is
  `failed`, with the raw `domain code: description` kept for logs only. The
  sheet words the error for the call that failed (read / add / remove).

### 4.3 Privacy — what the copy says, and why it is true

On iPhone the matching happens **on our server**, unlike Android: while DNS
protection is on, every name any app looks up goes over HTTPS to the gateway
(`api/routers/doh.py`). The sheet says so before its "Add" button
(`mobile.ios.dns.privacy_body`), the home privacy line switches to
`mobile.home.privacy_ios_dns` while it is on, and the public policy has a
paragraph in §11 (10 locales).

The copy matches the gateway as hardened in PR #124 (on `main` since
2026-10-09): blocked names get NXDOMAIN, others go to Cloudflare
(`cloudflare-dns.com`, then `1.1.1.1`); **no per-query log line at all**,
only aggregate counters (`/health/doh`); an in-memory answer cache keyed by
the question only (TTL capped at 1 h, up to 6 h stale fallback, never on
disk / Redis / logs); the per-IP rate limit in process memory under a keyed
hash, not the raw IP. Any change to that — another upstream operator via
`DOH_UPSTREAMS`, a log line, a persisted cache — must update the sheet
copy, policy §11 in all 10 locales and `docs/PRIVACY.md` → "The iPhone app"
in the same PR. Still open: whether iOS's resolver sends GET or POST (with
GET the question is in the URL, which Railway's own request log can record
with the IP) — see §4.4.

### 4.4 Simulator vs. device

Simulator run (iPhone 17, iOS 26.2, Xcode 26.3, Release build, 2026-10-09):
prebuild writes `dns-settings` (and no push) into `Cleanway.entitlements` and
the binary's simulated entitlements; the module links and loads; the home
card shows "DNS protection — Set up" and the hero "Automatic protection for
iPhone — see below"; the sheet renders the privacy block first, both steps,
the status and the notes. **The simulator has no NetworkExtension
configuration daemon**: every `loadFromPreferences` fails with
`NEConfigurationErrorDomain 11 "IPC failed"` (lost connection to
`nehelper`), so on the simulator the sheet shows "Couldn't read your
iPhone's DNS settings" on open and "Your iPhone didn't save the setting"
after "Add to iPhone" — the error paths, verified; the card stays "Set up",
never "On". Saving, Settings → DNS → Cleanway, `isEnabled`, the change
notice and removal can only be tested on a device. What only a device
(TestFlight) can show — check before submitting:

1. "Cleanway" under Settings → General → VPN & Device Management → DNS on a
   real phone; selecting it flips the sheet to "On" when the app comes back.
2. A listed site fails to open in Safari **and** in an in-app browser
   (WhatsApp / Instagram); unlisted sites keep working.
3. Captive Wi-Fi login; iOS 26 failover when the gateway is unreachable
   (block `dns.cleanway.ai` on a router); on iOS < 26, what the person sees.
4. Another VPN app connected; iCloud Private Relay on.
5. Whether iOS's resolver sends GET or POST to `/dns-query` — the privacy
   paragraph in `docs/PRIVACY.md` depends on it.
6. "Remove from iPhone" removes the Settings entry; adding again works, and
   whether a re-save keeps the person's on/off choice.

### 4.5 Not built (on purpose)

- **Canary proof of "on".** Android's "on" is proven by a canary query
  through the tunnel. On iOS the app cannot see the resolver's answer, and
  `list-canary.cleanway.ai` is NXDOMAIN everywhere, so it cannot tell our
  resolver from any other. A proof needs a public wildcard name that the
  gateway alone blocks (e.g. `*.ios-canary.cleanway.ai` with a public A
  record, always on the published list): a random label that fails while a
  control name resolves = lookups reach Cleanway. That is an ops + blocklist
  change; until then "On" means "iOS reports it enabled", and the sheet says a
  connected VPN may take DNS over.
- **Pause.** Off is the person's, in Settings ("Automatic"), or "Remove from
  iPhone" in the sheet. A timed pause would be a disconnect-all on-demand
  rule — never `removeFromPreferences`, which makes the Settings trek repeat.
- **Block notifications.** iOS gives the app no per-query signal; per-block
  alerts would need per-device query attribution on the server.

---

## 5. Scam-text filter (SMS)

### 5.1 What it is

`CleanwaySmsFilter` is an `ILMessageFilterExtension` (Message Filter
Extension) embedded in the app. iOS hands it each SMS/MMS **from a number
that is not in the contacts** — never iMessage, never a known sender — and it
answers with an `ILMessageFilterAction`:

| Engine verdict | Action | Why |
|---|---|---|
| `dangerous` | `.junk` | Messages → Filters → Junk: no notification, links not tappable. No sub-action: in the iOS 26.2 SDK sub-actions exist only for `.transaction` and `.promotion`, which would file a scam as a bill or an offer. |
| `caution` | `.none` | A caution is a *partial* combination (a brand plus a foreign link, a model score without an ingredient…). Junk hides a message with no way to say why; a real bank or delivery text there costs more than a borderline scam left in the inbox. Revisit with real-device data. |
| `no_signals` | `.none` | Shown as usual. |

**Offline only.** The extension never calls `deferQueryRequestToNetwork`,
its Info.plist has no `ILMessageFilterExtensionNetworkURL`, and the engine
opens no connection — so iOS has nowhere to send a message: its text never
leaves the phone, not even to us. `mobile/scripts/check-ios-parity-fixture.mjs`
(CI) fails if any of that appears. Server-assisted filtering is banned
(docs/MOBILE_AUTO_PROTECTION.md). The sender (`ILMessageFilterQueryRequest.sender`)
is passed to the engine, where it can only add suspicion (a bank writing
from a personal number, a "Госуслуги" text from another sender id).

The filter **holds no blocklist** (Android's message check also checks link
hosts against the synced DNS list; here every host is "not on the list"), so
`link_blocklisted` never fires on iPhone. Everything else is the Android
engine, verdict for verdict (§5.3).

### 5.2 Where things are

| | |
|---|---|
| `mobile/targets/sms-filter/Sources/CleanwayMessageEngine/` | The engine: a Swift port of `MessageAnalyzer/MessageSignals/MessageGeneric/MessageText/MessageLinks/MessageRules/MessageModel/RemoteConfig.kt`. Works on UTF-16 code units with the JVM's character classes, Java's lowercase, IDNA 2003 (`IDN.swift`: nameprep + punycode, as `java.net.IDN`) and java.util.regex patterns run through ICU with Java's ASCII `\d`/`\s` — Swift's own `String` compares by grapheme and canonical equivalence and would part from Kotlin on exactly the inputs a scammer controls. The model's feature set is the Kotlin open-addressing set bit for bit, so its weights are summed in the same order. |
| `mobile/targets/sms-filter/Extension/MessageFilterExtension.swift` | The extension's entry point (verdict → action). |
| `mobile/targets/sms-filter/Package.swift`, `Tests/` | The engine as a Swift package: parity, budget and kill-switch tests (`swift test`). |
| `mobile/plugins/withSmsFilter.js` | Expo plugin: copies the engine, the entry point and **the Android assets themselves** (`message_rules.json`, `root_zone_tlds.txt`, `message_model.json/.bin` from `modules/cleanway-vpn/android/src/main/assets`) into `ios/CleanwaySmsFilter/`, writes Info.plist / entitlements (app group only) / an empty privacy manifest, adds the target and its embed phase, and declares it in `extra.eas.build.experimental.ios.appExtensions` for EAS signing. A hand-written plugin rather than `@bacons/apple-targets`: one target, four copied files, the same `xcode` API expo-share-intent already uses, no new build dependency. |
| `mobile/modules/cleanway-sms-filter/` | App side (iOS-only Expo module): `isInstalled()` (the build carries the extension) and `setRemoteConfig(json)` → `remote_config.json` in the app group. |

One vocabulary and one model for both platforms: never edit a copy under
`ios/` — it is regenerated on every prebuild.

### 5.3 Parity with Android

`MessageIosParityTest.kt` (Android module tests) makes the Kotlin engine
write `Tests/CleanwayMessageEngineTests/Fixtures/kotlin_parity.json`: every
message of `MessageCorpus*.kt`, the held-out set, the four blind sets, the
model's parity texts, sender variants and Unicode edge cases (zero-width
characters, mixed scripts, IDN/punycode hosts, `ß`/`ﬁ`/`İ`, Greek, Arabic
digits, emoji, fullwidth dots, transliteration, a 14 000-character text) —
each under three server configs: model on, model switched off, raised
thresholds. `KotlinParityTests.swift` replays it and requires the same
verdict, the same reasons in the same order, the same links, phones,
organisations and legit shape, and the same model probability (≤ 1e-9).

Result (2026-10-09): **2,426 messages × 3 configs = 7,278 analyses, 0
mismatches**; model probabilities equal to within 1.7e-17. Run once more over
the model's training texts (`ml/sms/data/train_{a,b,c}.tsv`, a local-only
fixture via `CLEANWAY_IOS_PARITY_EXTRA`): 4,297 messages × 3 = 12,891
analyses, 0 mismatches.

### 5.4 After changing the Android engine, its assets or a corpus

CI (`mobile` job) re-hashes every input the fixture records and fails until
it is regenerated; the `ios-sms-engine` job (macOS runner) runs the Swift
parity tests. Locally:

1. Regenerate the fixture with the Kotlin tests, from the JVM (CI runs none).
   `mobile/android` is prebuild output, so either run the module's unit tests
   in a prebuilt tree, or a throwaway Gradle project (Kotlin JVM plugin,
   `org.json:json`, `kotlin-test-junit`) with the module's `Message*.kt`,
   `RemoteConfig.kt`, `LinkPolicy.kt`, `BlockList.kt`, `UserAllow.kt`,
   `DnsUtil.kt` and a `DomainPolicy` stub, the test sources above and
   `src/test/resources` — JDK: Android Studio's
   (`/Applications/Android Studio.app/Contents/jbr/Contents/Home`):
   ```bash
   CLEANWAY_REPO_ROOT=$PWD CLEANWAY_WRITE_IOS_PARITY=1 \
     gradle test --tests ai.cleanway.app.MessageIosParityTest
   ```
   Without `CLEANWAY_WRITE_IOS_PARITY` the same test compares the committed
   fixture with the engine (it passes on a fresh checkout).
2. `cd mobile/targets/sms-filter && swift test -c release` — any mismatch is
   printed with both sides; port the Kotlin change to the Swift file of the
   same name. (Debug builds of the engine are ~40× slower; the parity test
   then takes minutes.)
3. `node mobile/scripts/check-ios-parity-fixture.mjs`.

### 5.5 Memory and speed

A message filter extension runs under a small, undocumented memory limit.
The engine loads nothing until the first message, keeps the 512 KB float16
weight table memory-mapped (widened per read, no 1 MB `Float` copy), and does
not even read the model while the server has it switched off.

| Measured (release build, `FilterBudgetTests`) | macOS (Intel) | iOS 26.2 simulator |
|---|---|---|
| First message (load rules + root zone + model, check) | 14 ms | 13 ms |
| Per message, average over the 2,426 corpus messages | 0.7 ms | 4.0 ms¹ |
| Worst message (14 000-character text, cut to 10 000) | 71 ms | 296 ms¹ |
| Footprint (`phys_footprint`) after loading | +0.5 MB | +0.5 MB |
| Footprint after checking all 2,426 messages | +1.0 MB | +1.0 MB |

¹ Measured while a full app build ran on the same Mac; the macOS column is the
quiet figure. The extension target is compiled with `-O` even in Debug (whole
module). The bundled extension is 1.3 MB (0.7 MB binary + the four assets).

### 5.6 The app side

- **Home → Protection on iPhone → Scam-text filter**: "Set up" whenever the
  build carries the extension (`smsFilterLayerStatus`), never "On" — Apple
  gives an app no API to learn whether the person enabled the filter, and a
  filter extension cannot write anything back (no counter, no heartbeat).
  The row's line says it works once turned on in Settings.
- **Set up** opens `SmsFilterSetupSheet`. iOS 26 steps: Settings → Apps →
  Messages → (Unknown Senders) turn on Screen Unknown Senders → Text Message
  Filter → Cleanway. On iOS 26 the Text Message Filter row stays greyed out
  ("None") until Screen Unknown Senders is on — found by an on-device test on
  iOS 26.3.1 (2026-10-14); the sheet before that named only the iOS 18 path,
  which no longer exists. A note right under the steps says what the switch
  costs: messages from numbers not in the contacts go to a separate Unknown
  Senders list (Messages → Filters → Unknown Senders), verification codes
  still notify by default. Then the older paths (iOS 18: Settings → Apps →
  Messages → Unknown & Spam → SMS Filtering; iOS 17 and earlier: Settings →
  Messages → Unknown & Spam → SMS Filtering), what goes to Junk, that the
  text never leaves the phone, and the limits (unknown senders only, no
  iMessage, region/carrier may hide the option). Apple's labels per locale:
  [support.apple.com/125068](https://support.apple.com/en-us/125068) ("View
  conversations from unknown senders in Messages", iOS 26, also in ru-ru,
  es-es, pt-br, fr-fr, de-de, it-it, id-id, ar-ae) and the iPhone User Guide
  "Block, filter, and report messages" for iOS 26/18/17 (`iph203ab0be4`;
  Messages moved under Settings → Apps in iOS 18). Apple has no Hindi
  support page, so the Hindi sheet describes the iOS 26 switches in words
  with the English label in brackets. "Open Settings" opens Cleanway's own Settings page —
  the Messages page has no public URL, and private ones are a review rejection.
- **Kill switch**: the update check (`useUpdateCheck`) now also runs on an
  iPhone build with the filter, for the server's switches only (no update
  nudge on iOS); `setSmsFilterRemoteConfig` stores them, validated like
  `RemoteConfig.parse`, as `remote_config.json` in `group.ai.cleanway.app`.
  The extension reads the file for every message; missing or malformed means
  the shipped defaults. Overrides only raise thresholds.
- **In-app "Check a text message"** (pasted or shared text) runs the same
  engine in the app: `CleanwaySmsFilter.analyzeMessage` returns Android's
  `MessageCheck.toWire()` shape. The module compiles the engine through
  per-file symlinks in `modules/cleanway-sms-filter/ios/Engine/` (CocoaPods
  does not walk into a symlinked folder) and bundles the shared Android assets
  from `EngineAssets/` as `CleanwayMessageEngineAssets.bundle` — one engine,
  never a copy; `test-ios-sms-filter.mjs` pins the links. There is no list on
  an iPhone, so `listAvailable` is false and the app asks the server about the
  link hosts (up to three, host only); the card says so. Before 2026-10-10 the
  screen answered "Checking messages isn't available on this phone".

### 5.7 What was verified, and what needs a phone

On the iOS 26.2 simulator (Xcode 26.3, 2026-10-09), Release build:

- the app builds with the extension embedded as
  `Cleanway.app/PlugIns/CleanwaySmsFilter.appex` (bundle id
  `ai.cleanway.app.sms-filter`, extension point
  `com.apple.identitylookup.message-filter`, principal class
  `CleanwaySmsFilterExtension.MessageFilterExtension`, the four shared assets
  and its privacy manifest inside, no network URL in its Info.plist);
- after install, iOS registers it as a message filter
  (`xcrun simctl spawn <device> pluginkit -m -p com.apple.identitylookup.message-filter`
  lists `ai.cleanway.app.sms-filter`);
- home shows the row as "Set up" with its ready line; "Set up" opens the
  setup sheet (steps, notes, Open Settings, Done);
- the engine's Swift tests pass on the simulator too (`xcodebuild test
  -scheme CleanwayMessageEngine` in `mobile/targets/sms-filter`): parity 0
  mismatches, the numbers in §5.5;
- the simulator's Settings → Apps → Messages page is empty (no telephony), so
  the filter list (Text Message Filter on iOS 26) cannot be shown there.
- 2026-10-10, same simulator: the in-app "Check a text message" (§5.6) runs
  the engine in the app — a parcel-fee scam text in English and in Russian
  shows "Looks like a scam" / «Похоже на мошенников» with three reasons, the
  link host checked on the server, and the iPhone note under the links.

The simulator cannot receive an SMS, so the end-to-end path — a text from an
unknown number landing in Junk — needs a real iPhone with a SIM and a
second phone: enable the filter (§5.6), send from a number not in the
contacts (1) an ordinary text, (2) a corpus scam such as «Госуслуги:
зафиксирован вход в ваш аккаунт с нового устройства. Если это были не вы,
срочно позвоните по номеру +7 916 482-15-37» → expect (1) in the inbox, (2)
under Filters → Junk without a notification. Re-check on every iOS beta
(MOBILE_AUTO_PROTECTION.md §4.5).
