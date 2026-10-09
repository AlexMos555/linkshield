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
CI=1 npx expo prebuild -p ios --no-install
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
| Targets | `Cleanway` (app), `CleanwayCheckLink` (share extension, `ai.cleanway.app.share-extension`) |
| App group | `group.ai.cleanway.app` (app + share extension; the extension hands the shared link/text to the app through it) |
| Devices | iPhone only (`supportsTablet: false`, see §2.3); iOS 15.1+ |
| Entitlements | App group; Network Extensions = `["dns-settings"]` (DNS protection, §4 — added by `plugins/withIosAppStore.js`). No push (`aps-environment` is stripped by the same plugin), no VPN value |
| Usage strings | Camera only (QR scanner). Microphone and Face ID strings are switched off in `app.json` |
| Encryption | `ITSAppUsesNonExemptEncryption = false` (HTTPS only) — no export-compliance question on upload |
| Privacy manifest | `ios.privacyManifests` in `app.json` → `PrivacyInfo.xcprivacy`; pods ship their own (RN core, Expo modules, RevenueCat, Sentry) |
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
screen shows **Protection on iPhone**: Safari extension and scam-text filter
("Coming soon" until their targets ship) and DNS protection ("Set up" → §4),
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
- **Scam-text filter**: an `ILMessageFilterExtension` target (offline rules
  only — no server call, the text never leaves the phone). Apple gives the app
  no "is it enabled" API: the layer can only be "setup" with honest copy.
- **Safari Web Extension**: a separate target, reusing `extension-safari/`.
- `mobile/native/ios/PacketTunnelProvider.swift` is the parked VPN experiment;
  it is not in any target.

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
3. Do **not** enable Push Notifications (the app uses none on iOS).

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

Provide a demo account the reviewer can sign in with (an email inbox you can
read the code from, or a review-only bypass on the server) — email-code
sign-in fails review if the reviewer cannot receive the code.

### 3.7 Screenshots and listing

iPhone 6.9" (1320×2868 or 1290×2796) is the only required size with
`supportsTablet: false`. Never show the Settings "VPN & Device Management"
page or the word "VPN" in screenshots or the description; call the feature
"DNS protection" or "encrypted DNS", never a VPN (5.4 misfile risk). The
setup sheet names that Settings page in-app only, because it is Apple's own
label. Do not promise
"blocks scam texts / iMessage": the SMS filter is "coming soon", and iMessage
is invisible to any app.

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
paragraph in §11 (10 locales). The exact server behaviour and the open
questions (GET vs POST and Railway's request log; the gateway-hardening
branch) are in `docs/PRIVACY.md` → "The iPhone app". Re-read all three texts
when `feat/doh-gateway-hardening` lands.

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
