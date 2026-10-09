# Cleanway for iPhone — build, targets, App Store

The iOS app is the same Expo app as Android (`mobile/`, Expo SDK 54, React
Native 0.81, legacy architecture), shipped through the App Store only. This
file covers how to build it, what is in the binary today, what comes next, and
what the founder has to set up in Apple's consoles.

Architecture and the choice of iOS mechanisms: `docs/MOBILE_AUTO_PROTECTION.md`.
Payments (server side, RevenueCat): `docs/runbooks/revenuecat.md`.

---

## 1. Build it

### 1.1 Locally (simulator)

The monorepo hoists a different `react-native` to the repo root, which breaks
`expo prebuild` / `pod install` inside the workspace. Build from a mirror
outside the repo:

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
npm install                                    # mobile/package-lock.json comes along
# The Safari extension target bundles the repo's built extension-safari/
# (plugins/withSafariExtension.js); outside the repo it must be told where.
bash "$REPO/scripts/build-extensions.sh" > /dev/null
CLEANWAY_SAFARI_EXTENSION_DIR="$REPO/extension-safari" CI=1 npx expo prebuild -p ios --no-install
cd ios && LANG=en_US.UTF-8 pod install --repo-update   # --repo-update: RevenueCat's pods are newer than a stale CDN index
xcodebuild -workspace Cleanway.xcworkspace -scheme Cleanway -configuration Debug \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone Air' \
  -derivedDataPath ../build build
```

Debug loads JS from Metro (`npx expo start` in `$M`); Release embeds the bundle.
Both configurations were built and run on the iOS 26.2 simulator with Xcode 26.3
(2026-10-09). `plugins/withXcode26Patches.js` keeps fmt / Sentry /
expo-localization compiling on Xcode 26. A full build is ~4 GB of DerivedData —
delete the mirror and `build/` afterwards.

### 1.2 For TestFlight / the App Store (EAS)

`eas build -p ios --profile production` (or `preview` for TestFlight testers).
EAS manages certificates, provisioning profiles and the build number
(`appVersionSource: remote`). Set these as **EAS environment variables**
(Expo dashboard → project → Environment variables), not in `eas.json`:

| Variable | Value | Without it |
|---|---|---|
| `EXPO_PUBLIC_SUPABASE_ANON_KEY` | Supabase anon key | Sign-in does not work |
| `EXPO_PUBLIC_REVENUECAT_IOS_KEY` | RevenueCat **public** App Store key, `appl_…` | The paywall says "Paying in the app is coming soon" — no crash |
| `EXPO_PUBLIC_SENTRY_DSN` | optional | No crash reports |

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
| Targets | `Cleanway` (app), `CleanwayCheckLink` (share extension, `ai.cleanway.app.share-extension`), `CleanwaySafariExtension` (Safari Web Extension, `ai.cleanway.app.safari-extension`, iOS 16.4+, §2.5) |
| App group | `group.ai.cleanway.app` (app + both extensions; the share extension hands the shared link/text to the app through it, the Safari extension the time it last ran on a web page) |
| Devices | iPhone only (`supportsTablet: false`, see §2.3); iOS 15.1+ |
| Entitlements | App group only. No push (`aps-environment` is stripped by `plugins/withIosAppStore.js`), no Network Extension, no VPN |
| Usage strings | Camera only (QR scanner). Microphone and Face ID strings are switched off in `app.json` |
| Encryption | `ITSAppUsesNonExemptEncryption = false` (HTTPS only) — no export-compliance question on upload |
| Privacy manifest | `ios.privacyManifests` in `app.json` → `PrivacyInfo.xcprivacy` (UserDefaults: `CA92.1` own defaults, `1C8F.1` the app group); pods ship their own (RN core, Expo modules, RevenueCat, Sentry); the Safari extension has its own (UserDefaults `1C8F.1`, nothing collected) |
| Launch screen | `SplashScreen.storyboard` from `app.json` `splash` (dark `#0f172a` + logo) |
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
screen shows **Protection on iPhone**: the Safari extension (shipped, §2.5),
scam-text filter and DNS protection ("Coming soon" until their steps land),
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
- **DNS protection** (`NEDNSSettingsManager`, encrypted DNS to the existing
  `/dns-query` gateway): status / enable functions go into
  `modules/cleanway-vpn/ios/CleanwayVpnModule.swift`; add the
  `com.apple.developer.networking.networkextension = ["dns-settings"]`
  entitlement — `withIosAppStore.js` keeps `dns-settings` and strips only VPN
  values. Never call it a VPN in the UI, listing or screenshots (5.4 misfile
  risk; Settings shows it under "VPN & Device Management").
- **Scam-text filter**: an `ILMessageFilterExtension` target (offline rules
  only — no server call, the text never leaves the phone). Apple gives the app
  no "is it enabled" API: the layer can only be "setup" with honest copy.
- **Safari Web Extension**: shipped — §2.5.
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
| iOS | 16.4+ — the background is an ES-module service worker, which Safari supports from 16.4 (release notes: "Added support for modules in background service workers"). The app stays at 15.1; on older iOS the extension just does not show up in Safari. iPhone only, like the app |
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

Recommendation (as in `MOBILE_AUTO_PROTECTION.md` §6): stay Individual; the
iOS plan uses no VPN. Switch only if a company is formed anyway — the app can
be transferred later.

### 3.2 Identifiers (developer.apple.com → Certificates, IDs & Profiles)

EAS creates these on the first `eas build` if you let it log in; to do it by hand:
1. App ID `ai.cleanway.app` with capability **App Groups** → `group.ai.cleanway.app`
   (and later **Network Extensions** for DNS settings).
2. App ID `ai.cleanway.app.share-extension` with the same App Group.
3. App ID `ai.cleanway.app.safari-extension` with the same App Group (the
   Safari extension; EAS creates it from `extra.eas…appExtensions`).
4. Do **not** enable Push Notifications (the app uses none on iOS).

### 3.3 The app record

1. App Store Connect → My Apps → **+** → iOS, name "Cleanway", bundle id
   `ai.cleanway.app`, SKU e.g. `cleanway-ios`. Put the numeric Apple ID into
   `mobile/eas.json` → `submit.production.ios.ascAppId`.
2. Category: Utilities (or Productivity). Age rating questionnaire: no
   objectionable content → 4+.
3. Privacy Policy URL `https://cleanway.ai/privacy-policy`; Terms (EULA)
   `https://cleanway.ai/terms` — App Store requires both for subscriptions
   (the paywall links them too). Support URL `https://cleanway.ai`.
4. Account deletion: in the app (Settings → Delete account, and Account →
   Delete account). Mention it in review notes.

### 3.4 In-app purchases (Subscriptions)

The server already knows these ids (`api/services/store_products.py`):

| Group | Product id | Period | Grants |
|---|---|---|---|
| `Cleanway` | `cleanway.devices.monthly` | 1 month | Personal plan (3 devices) |
| `Cleanway` | `cleanway.devices.yearly` | 1 year | Personal plan |
| `Cleanway devices` (separate group) | `cleanway.extra_device.monthly` / `.yearly` | — | +1 device (not sold in the app yet) |

Then in RevenueCat (runbook §3, §9): add the App Store app, upload the
In-App Purchase key (`.p8`), set App Store Server Notifications V2 to
RevenueCat's URL, attach both plan products to the `unlimited` entitlement and
to the `default` offering (monthly + annual packages). Copy the **public**
`appl_…` key into `EXPO_PUBLIC_REVENUECAT_IOS_KEY`. Fill the **Paid Apps
agreement**, banking and tax in App Store Connect first — products stay
"Missing Metadata" without it. Each subscription needs a review screenshot of
the paywall.

What the app already does for review: prices only from StoreKit, "Restore
purchases" on the paywall and the account screen, "Manage subscription" opens
Apple's subscriptions page, small print under the button (billed to Apple ID,
auto-renews unless cancelled 24 h before the period ends, cancel in Settings),
Terms + Privacy links, no link to the web checkout anywhere in the iOS build,
and for App Store subscribers the account screen explains that only Apple can
cancel the subscription and that deleting the account does not.

Sandbox testing: App Store Connect → Users and Access → Sandbox testers; sign
in on the device under Settings → App Store → Sandbox Account. The simulator
can use a StoreKit configuration file, but RevenueCat needs real sandbox
receipts for the server webhook — test on a device via TestFlight.

### 3.5 App Privacy ("nutrition labels")

Answer from the real egress (same facts as `docs/RUSTORE_SUBMISSION.md` §3):

| Apple data type | Collected | Linked to the user | Tracking | Purpose |
|---|---|---|---|---|
| Contact Info → Email Address | Yes, only when the person signs in | Yes | No | App Functionality |
| Identifiers → User ID (account id) | Yes, when signed in | Yes | No | App Functionality |
| Identifiers → Device ID (random device id of the account's device list; daily-rotating install number for rate limits) | Yes | Device id: Yes · install number: No | No | App Functionality |
| Browsing History (site names the person checks — never full URLs, no account token on the check) | Yes | No | No | App Functionality |
| Purchases → Purchase History (App Store subscription via RevenueCat) | Yes, when subscribing | Yes | No | App Functionality |
| Diagnostics → Crash Data (Sentry, only when a DSN is set) | Yes | No | No | App Functionality |

Not collected: location, contacts, photos, messages (shared message text stays
on the phone), audio, health, financial info, advertising data. No tracking,
no ad SDKs, no ATT prompt. Re-check before submitting if the Family hub or the
weekly report send anything new.

### 3.6 Review notes (paste into "Notes")

> Cleanway checks links for scams. No account is needed: paste a link on the
> home screen or share one to Cleanway from Safari. Sign-in (optional) is by a
> one-time code sent to email — use the demo account below. Account deletion:
> Settings → Delete account. Subscriptions are sold only through In-App
> Purchase; "Restore purchases" is on the paywall and in Account. The app
> contains no VPN. The app includes a Safari Web Extension that warns about
> scam sites: Settings → Apps → Safari → Extensions → Cleanway → Allow
> Extension, then Other Websites → Allow; open any site in Safari (or the
> home screen's "Set up" → "Test it in Safari"). It sends only site names to
> api.cleanway.ai to check them; it has no purchases or upsell of its own.
> The "Protection on iPhone" items marked "Coming soon" are not functional in
> this version and are labelled as such.

Provide a demo account the reviewer can sign in with (an email inbox you can
read the code from, or a review-only bypass on the server) — email-code
sign-in fails review if the reviewer cannot receive the code.

### 3.7 Screenshots and listing

iPhone 6.9" (1320×2868 or 1290×2796) is the only required size with
`supportsTablet: false`. Never show the Settings "VPN & Device Management"
page or the word "VPN" in screenshots or the description. Do not promise
"blocks scam texts / iMessage": the SMS filter is "coming soon", and iMessage
is invisible to any app.
