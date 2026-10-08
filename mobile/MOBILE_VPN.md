# Android DNS-VPN — build & verify

Cleanway's **system-wide, on-tap protection** on Android: a local DNS-filtering
VPN that sees the DNS lookup for **every** link opened in **any** app (Chrome, other
browsers, and the in-app browsers of WhatsApp / Telegram / Mail) and blocks known
phishing domains from a list **synced to the phone** (`GET /api/v1/blocklist/dns`,
ETag/304, every ~6h, also through Doze via `BlocklistAlarm`). Names are matched on the
phone; **no lookup is sent to Cleanway** — what the list does not block goes to the
network's own resolver, then 1.1.1.1 / 9.9.9.9, then Cloudflare DoH. This is the
"protect the moment a link is opened" layer — the only mechanism that reaches
messenger in-app webviews.

> **Status (2026-10).** Everything below the "What changed" heading is the record of the
> original `mobile-android-vpn` branch (2026-07). Since then the module has been
> compiled, emulator-verified (2026-08-18 scenario matrix in
> `docs/MOBILE_AUTO_PROTECTION.md`) and shipped in the Tele2 builds. The per-lookup
> `/public/check` design described there was replaced by the on-device list on
> 2026-08-18. The real-device OEM sweep is still owed — see "Keeping protection on"
> below.

> *(Historical, 2026-07:)* ✅ **TS-verified + prebuild-clean · ⚠️ Kotlin not compiled, not device-tested.**
> Authored on a Mac **without the Android SDK/gradle/Java**, so the Kotlin can't be
> compiled here. What WAS verified: `npx tsc --noEmit` is clean (0 new errors — the JS
> API + the wired home toggle typecheck), `npx expo prebuild -p android` runs without
> config error, and the `FOREGROUND_SERVICE_SPECIAL_USE` permission merges. The Kotlin
> compile, the module's manifest merge (the `<service>` declaration), autolinking, and
> device behaviour happen at `expo run:android` (gradle) — **your machine**. On a
> branch, not `main`, for exactly this reason.

## What changed
- **`modules/cleanway-vpn/`** — a local Expo module (scaffolded with
  `create-expo-module --local`, so the gradle/podspec/autolinking boilerplate is
  correct-by-construction):
  - `android/.../CleanwayVpnModule.kt` — the JS↔native bridge: `startVpn()` (requests
    VpnService consent once, then starts the foreground service), `stopVpn()`,
    `isRunning()`, and forwards the service's `ACTION_DOMAIN_BLOCKED` broadcasts to JS
    as an `onDomainBlocked` event.
  - `android/.../ai/cleanway/app/CleanwayVpnService.kt` — the existing hardened DNS
    service, **moved here** so it actually compiles, plus a needed fix: it had **no
    `startForeground()`** (a VPN must be a foreground service or Android kills it /
    crashes `startForegroundService`). Added a low-priority ongoing notification +
    `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` + an `isRunning` flag for the UI.
  - `android/src/main/AndroidManifest.xml` — declares the `<service>` (BIND_VPN_SERVICE,
    `foregroundServiceType=specialUse`, `PROPERTY_SPECIAL_USE_FGS_SUBTYPE=vpn`).
  - `ios/CleanwayVpnModule.swift` — **no-op stub** (iOS NE VPN is a separate track,
    gated on an Organization Apple account; keeps the JS API uniform).
  - `index.ts` — `startVpn/stopVpn/isVpnRunning` + a `useVpn()` React hook.
- **`app.json`** — added `FOREGROUND_SERVICE_SPECIAL_USE` (BIND_VPN_SERVICE /
  FOREGROUND_SERVICE / POST_NOTIFICATIONS were already there).
- **`app/(tabs)/index.tsx`** — the home **shield toggle** (which was local state only)
  now drives the real VPN via `useVpn()`. iOS taps show a "coming soon" alert.
  *(Since replaced by the Shield Checklist home: `useNetworkShield`, canary-proven
  state, no toggle.)*

## Build & test (Android Studio / SDK required; Node 20)

```bash
cd mobile
nvm use 20
# de-hoist the monorepo (installs @expo/cli + schema-utils into the mobile tree):
rm -rf node_modules && npm install
npx expo prebuild -p android --clean
npx expo run:android            # needs ANDROID_HOME + a device/emulator
```

## On-device verification checklist
- [ ] `expo run:android` compiles the Kotlin (module + service) with no errors.
- [ ] Generated `android/app/src/main/AndroidManifest.xml` contains
      `<service android:name="ai.cleanway.app.CleanwayVpnService" ... foregroundServiceType="specialUse">`
      (merged from the module manifest by gradle).
- [ ] Tapping the home shield → the system **VPN consent dialog** appears; accept it.
- [ ] The persistent "Cleanway protection is on" notification shows.
- [ ] Open a known-phishing link from **WhatsApp** (in-app browser) → it fails to
      resolve (blocked), and the shield subtitle updates to "Blocked <domain>".
- [ ] Open a normal site → resolves fine (fail-open). Toggle off → tunnel tears down.
- [ ] Airplane-mode / background the app for a while → protection survives (FGS).
- [ ] "Keep protection on" list (below the shield card): battery → dialog → back →
      ticked; phone-maker step opens the OEM screen (or App info); Always-on ticks
      only when set in Settings → VPN.
- [ ] `adb shell am kill ai.cleanway.app` while ON, app closed → within ~15 min
      `CleanwayWatchdog: rearmed trigger=watchdog` (force the job now:
      `adb shell cmd jobscheduler run -f ai.cleanway.app 31252`).
- [ ] `adb shell am force-stop ai.cleanway.app` → stays off (Android's rule) until the
      app is opened → `rearmed trigger=app_open`, green without a tap.
- [ ] Another VPN app takes over → ours never takes the slot back by itself.

## Known risks (couldn't compile-check here)
1. **Uncompiled Kotlin** — the bridge + service edits follow the Expo Modules API and
   Android FGS docs, but a typo/API-shape mismatch would only surface at gradle build.
   Read the compiler output; the surfaces most likely to need a tweak: the
   `OnActivityResult`/consent flow, and `startForeground(..., type)` on older APIs.
2. **Notification icon** — *(resolved)* notifications use the dedicated monochrome
   `cleanway_ic_notification` drawable (`BlockNotifier.SMALL_ICON`).
3. **Play Store** — before publishing: complete the **VpnService Declaration** form +
   a ≤90s demo video + a prominent in-app disclosure (it's the permitted "device
   security" category, low approval risk, but the form is mandatory).
4. **DNS edge cases** — the service routes only DNS through the tunnel; strict
   Private DNS (DoT) is detected and explained (`PrivateDnsGuard`); IPv6 DNS still to
   check on a real device.
5. **Battery / OEM kills** — see "Keeping protection on" below.

## Keeping protection on (2026-10)

What keeps the shield running after the app is closed, and what is not yet verified on
hardware, is in `docs/MOBILE_AUTO_PROTECTION.md` → "Keeping the shield alive". In
short: a battery-exemption step (`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, Play "safety
app" justification there), per-OEM steps and settings buttons (Samsung, Xiaomi/Redmi/
POCO, Huawei/Honor, OPPO/realme/OnePlus, vivo/iQOO), a `ShieldWatchdog` JobScheduler
job plus boot / update / time-zone / language triggers and an app-open re-arm — all
through one rule set (`KeepAlivePolicy.decideRearm`, JVM-tested) that never starts the
shield without the person's earlier "on", never after Android took the tunnel away, and
never without the VPN permission. A force-stop still keeps it off until the app is
opened: that is Android's rule.

## iOS
iOS system-wide VPN (`PacketTunnelProvider.swift`, already written) is the next track —
it needs `@bacons/apple-targets` to add the NE target AND an **Organization** Apple
Developer account (App Review 5.4). The iOS module here is a deliberate no-op until
then. See `memory/project_mobile_protection_state.md`.

## Adversarial review fixes (2026-07-12)
A multi-agent review against the installed Expo SDK 52 APIs (node_modules) caught 7
bugs in the uncompiled Kotlin/TS BEFORE any device build — fixed on this branch:
- **compile-break**: `DnsUtil.kt` (used by the service, same-package, no import) was
  left in `mobile/native/android/` — outside the module's Gradle source set → the
  library wouldn't compile (`unresolved reference: DnsUtil`). Moved DnsUtil.kt into the
  module main source + DnsUtilTest.kt into the module test source (+ kotlin-test dep).
- **runtime**: `stopVpn()` returned `ComponentName` (from startService) → expo-modules
  tried to convert it → the JS promise REJECTED, leaving the toggle stuck "Protected".
  Now returns `Unit` (resolves void).
- **runtime**: `useVpn().start` read `isVpnRunning()` synchronously right after
  `startVpn()` resolved, but the native flag isn't set yet → toggle didn't flip on.
  Now trusts the resolved boolean (`setRunning(ok)`).
- **runtime**: no re-sync if the VPN is torn down externally (Settings revoke / OS kill)
  → added an AppState "active" re-sync in `useVpn`.
- **polish**: `startVpn` re-entry could stack a 2nd consent dialog + leak the 1st
  promise → added a re-entry guard + reject the pending promise on module destroy.
Re-validated: `tsc --noEmit` clean (0 new errors), `expo prebuild -p android` clean.
Kotlin compile + device test still on your machine.
