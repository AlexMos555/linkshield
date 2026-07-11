# Android DNS-VPN — build & verify (branch `mobile-android-vpn`)

Wires Cleanway's **system-wide, on-tap protection** on Android: a local DNS-filtering
VPN that inspects the DNS query for **every** link opened in **any** app (Safari,
Chrome, and the in-app browsers of WhatsApp / Telegram / Mail) and blocks known
phishing domains via `api.cleanway.ai/api/v1/public/check`. This is the "protect the
moment a link is opened" layer — the only mechanism that reaches messenger in-app
webviews.

The hardened DNS service (`CleanwayVpnService.kt`) already existed but was **never
wired** into a buildable app. This branch adds the missing integration.

> ✅ **TS-verified + prebuild-clean · ⚠️ Kotlin not compiled, not device-tested.**
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

## Known risks (couldn't compile-check here)
1. **Uncompiled Kotlin** — the bridge + service edits follow the Expo Modules API and
   Android FGS docs, but a typo/API-shape mismatch would only surface at gradle build.
   Read the compiler output; the surfaces most likely to need a tweak: the
   `OnActivityResult`/consent flow, and `startForeground(..., type)` on older APIs.
2. **Notification icon** — uses `applicationInfo.icon` as the small icon; Android wants
   a monochrome drawable. Swap for a dedicated `ic_stat_shield` if it looks wrong.
3. **Play Store** — before publishing: complete the **VpnService Declaration** form +
   a ≤90s demo video + a prominent in-app disclosure (it's the permitted "device
   security" category, low approval risk, but the form is mandatory).
4. **Battery/DNS edge cases** — the service routes only DNS (port 53) through the
   tunnel; validate that IPv6 DNS and private-DNS (DoT) settings don't bypass it on
   your test device.

## iOS
iOS system-wide VPN (`PacketTunnelProvider.swift`, already written) is the next track —
it needs `@bacons/apple-targets` to add the NE target AND an **Organization** Apple
Developer account (App Review 5.4). The iOS module here is a deliberate no-op until
then. See `memory/project_mobile_protection_state.md`.
