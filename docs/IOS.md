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
| Targets | `Cleanway` (app), `CleanwayCheckLink` (share extension, `ai.cleanway.app.share-extension`), `CleanwaySmsFilter` (scam-text filter, `ai.cleanway.app.sms-filter`, §5), `CleanwaySafariExtension` (Safari Web Extension, `ai.cleanway.app.safari-extension`, iOS 16.4+, §2.5) |
| App group | `group.ai.cleanway.app` (app + share extension + Safari extension; the share extension hands the shared link/text to the app through it, the Safari extension the time it last ran on a web page) |
| Devices | iPhone only (`supportsTablet: false`, see §2.3); iOS 15.1+ |
| Entitlements | App group; Network Extensions = `["dns-settings"]` (DNS protection, §4 — added by `plugins/withIosAppStore.js`). No push (`aps-environment` is stripped by the same plugin), no VPN value |
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
| Browsing History (site names the person checks — never full URLs, no account token on the check; with DNS protection on, every name the iPhone looks up goes to the DNS gateway, §4.3) | Yes | No | No | App Functionality |
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
> contains no VPN. The "Protection on iPhone" items marked "Coming soon" are
> not functional in this version and are labelled as such.
>
> DNS protection (home → Protection on iPhone → DNS protection → Set up) uses
> the public DNS Settings API (NEDNSSettingsManager with
> NEDNSOverHTTPSSettings, Network Extensions entitlement value
> `dns-settings`). It is not a VPN: there is no tunnel, no NEVPNManager and no
> network extension target. The app saves an encrypted DNS-over-HTTPS setting
> pointing at our resolver, https://dns.cleanway.ai/dns-query, which answers
> NXDOMAIN for known scam and phishing sites and forwards every other name to
> Cloudflare's DNS. Nothing changes until the user selects "Cleanway" in
> Settings → General → VPN & Device Management → DNS. Before the user adds
> it, the app explains that site names are sent to our DNS server (the
> matching happens on our server) and that we keep no record of who looked up
> what — privacy policy, section 11. The user can remove it in the app, or
> choose "Automatic" on the same Settings page, at any time.
>
> The scam-text filter is an SMS filter extension: enable it in Settings →
> Apps → Messages → Unknown & Spam → SMS Filtering → Cleanway. It works
> offline — it has no network URL and never sends a message anywhere — and
> moves only texts it judges a scam to Junk.
>
> The Safari Web Extension warns about scam sites: Settings → Apps → Safari →
> Extensions → Cleanway → Allow Extension, then Other Websites → Allow; open
> any site in Safari (or the home screen's "Set up" → "Test it in Safari").
> It sends only site names to api.cleanway.ai to check them; it has no
> purchases or upsell of its own.

Provide a demo account the reviewer can sign in with (an email inbox you can
read the code from, or a review-only bypass on the server) — email-code
sign-in fails review if the reviewer cannot receive the code.

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
| Native: save / read / remove the configuration, change notice | `mobile/modules/cleanway-vpn/ios/CleanwayVpnModule.swift` (`CleanwayDnsSettings`; JS names `dnsSettingsStatus`, `installDnsSettings`, `removeDnsSettings`, event `onDnsSettingsChanged`) |
| JS bridge + report parser | `modules/cleanway-vpn/index.ts` (`isIosDnsSupported`, `iosDnsStatus`, `installIosDns`, `removeIosDns`, `addIosDnsChangedListener`), `modules/cleanway-vpn/src/IosDnsSettings.ts` |
| State machine (pure) | `src/utils/ios-dns.ts` — phases `unavailable → checking → add → turn_on → on`, the sheet model, the error wording |
| Live hook | `src/hooks/useIosDnsProtection.ts` — reads iOS on mount, on every foreground (back from Settings) and on `NEDNSSettingsConfigurationDidChange` |
| UI | home card row "DNS protection" (`IosProtectionCard`: "Set up" / check mark — both open the sheet) → `src/components/shield/IosDnsSetupSheet.tsx`; home privacy line and hero follow it |
| Entitlement | `com.apple.developer.networking.networkextension = ["dns-settings"]`, added by `plugins/withIosAppStore.js` (VPN values stripped) — no `app.json` change |
| Tests (CI) | `mobile/scripts/test-ios-dns.mjs`, `mobile/scripts/test-platform-gating.mjs` |

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
- **Set up** opens `SmsFilterSetupSheet`: Settings → Apps → Messages →
  Unknown & Spam → SMS Filtering → Cleanway (iOS 17 and earlier: Settings →
  Messages → Unknown & Spam), what goes to Junk, that the text never leaves
  the phone, and the limits (unknown senders only, no iMessage, region/carrier
  may hide the option). "Open Settings" opens Cleanway's own Settings page —
  the Messages page has no public URL, and private ones are a review rejection.
- **Kill switch**: the update check (`useUpdateCheck`) now also runs on an
  iPhone build with the filter, for the server's switches only (no update
  nudge on iOS); `setSmsFilterRemoteConfig` stores them, validated like
  `RemoteConfig.parse`, as `remote_config.json` in `group.ai.cleanway.app`.
  The extension reads the file for every message; missing or malformed means
  the shipped defaults. Overrides only raise thresholds.

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
  the SMS Filtering list cannot be shown there.

The simulator cannot receive an SMS, so the end-to-end path — a text from an
unknown number landing in Junk — needs a real iPhone with a SIM and a
second phone: enable the filter (§5.6), send from a number not in the
contacts (1) an ordinary text, (2) a corpus scam such as «Госуслуги:
зафиксирован вход в ваш аккаунт с нового устройства. Если это были не вы,
срочно позвоните по номеру +7 916 482-15-37» → expect (1) in the inbox, (2)
under Filters → Junk without a notification. Re-check on every iOS beta
(MOBILE_AUTO_PROTECTION.md §4.5).
