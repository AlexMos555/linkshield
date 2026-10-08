# RuStore + Google Play — Android Submission Runbook (Cleanway)

Code-grounded, copy-paste-ready. The data-collection answers below come from the
**actual mobile egress** (the app contacts only `api.cleanway.ai` + `cleanway.ai`,
plus Sentry for crash logs and Supabase for the optional account — verified,
no third-party ad/analytics SDKs; the DNS shield forwards ordinary lookups to the
network's own resolver, see §4). A declaration that doesn't match the code is a
rejection (and, on Play, a takedown) trigger.

**The RuStore listing for 1.0.4 (Russian, ready to paste) is §7.** The Google
Play drafts (EN + RU) are in `docs/STORES.md` → "Google Play (Android app)".
`mobile/STORE_LISTING.md` keeps the shared metadata and the history of removed
claims.

RuStore is the **primary** channel for the Tele2 RF launch.

> **Google Play: the target-API blocker is fixed in code (2026-10-08), not yet
> shipped.** Since **31 Aug 2026** Play requires new apps and updates to target
> **API 36** (Android 16) — [Target API level requirements](https://developer.android.com/google/play/requirements/target-sdk)
> (an extension to 1 Nov 2026 can be requested). The app is now on **Expo SDK 54
> / React Native 0.81**, and the build from §2 produces an APK/AAB with
> `targetSdkVersion 36` (compileSdk 36) whose 64-bit native libraries are all
> 16 KB-aligned (Play's [16 KB page-size requirement](https://developer.android.com/guide/practices/page-sizes)
> for apps targeting Android 15+). What is still open before a Play upload: a
> release-signed build retested on a real phone (VPN shield, boot restart, link
> guard, share, notifications — §2 "What is and isn't verified") and the Play
> TODOs in `docs/STORES.md` §6.0. Every APK built before this change (Expo SDK 52,
> up to and including the first 1.0.4 builds) targets API 34 — do not upload those to Play.
>
> **RuStore is unaffected**: its floor is targetSdk **28**, it requires 64-bit
> native libs (our APK ships `arm64-v8a` ✓) and a signed artifact (✓). Our build
> clears every RuStore requirement today.

RuStore accepts a physical-person (физлицо) developer account — no company
required. The developer console signs in with **VK ID** (Госуслуги / Яндекс /
номер телефона are the ways *into* VK ID, not separate logins).

---

## 0. Who does what

| | Task |
|---|---|
| **[F] Founder only** | Keep the keystore backup safe (§1). Create the RuStore developer account (VK ID, физлицо). Wire transactional SMTP for sign-in mail before submitting (§5). Confirm `support@cleanway.ai` receives mail. Upload the artifact + paste the answers below. Close the TODOs in §7.0 before submitting 1.0.4. |
| **[C] Claude — done** | Release-signing + ABI plugins, explicit `versionCode`, honest listing, this runbook, the `/android` funnel page, the in-app update check, **the keystore and the signed APK itself** (§1–2). |

The keystore is **permanent identity material**: lose it and every user must
uninstall/reinstall forever.

---

## 1. Release keystore — ALREADY GENERATED (2026-08-31) and IN USE

`cleanway-release.jks` (RSA 4096, `CN=Cleanway, OU=Mobile, O=Cleanway,
L=Moscow, C=RU`, valid to 2054) and its `keystore.properties` exist in two
places, both outside git: the **founder's backup** (the `.jks`, the properties
file and a zipped copy, kept together with the downloaded v1.0.0 APK) and a
**working copy next to the generated `android/` folder of the build sandbox**
(§2). The password lives only in `keystore.properties` and the password manager
— never in this repo.

> **Do not regenerate it.** The v1.0.0 APK (versionCode 100) signed with this key
> has already been built and downloaded; a new key would make every phone that
> installed it refuse the update ("App not installed"). The only remaining job is
> to keep the backup safe: password manager **+ one offline copy**.

For the record, it was created with:

```bash
keytool -genkeypair -v \
  -keystore cleanway-release.jks \
  -alias cleanway \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -storetype PKCS12
```

- `cleanway-release.jks` never enters git.
- The build reads the key through a credentials file next to it. `storeFile` is
  **relative to the `android/` directory**, so the `.jks` sits inside `android/`
  and is referenced by name:

```properties
# mobile/android/keystore.properties  — never commit this or the .jks.
storeFile=cleanway-release.jks
storePassword=<store password — from the password manager>
keyAlias=cleanway
keyPassword=<key password — from the password manager>
```

> **Before you create these files, confirm git will ignore them.** `*.jks`,
> `keystore.properties`, and `/mobile/android/` + `/mobile/ios/` are in
> `.gitignore` (added 2026-08-25 — earlier they were NOT, which would have let a
> `git add -A` commit the permanent key). Verify on your machine:
> ```bash
> git check-ignore mobile/android/keystore.properties mobile/android/app/cleanway-release.jks
> # both paths must print — if either is silent, STOP and fix .gitignore first.
> ```
> Committing the release key or its passwords is unrecoverable: you'd have to
> rotate the key, and every already-installed user would need to uninstall/reinstall.

**Where the file must physically sit:** next to the generated `android/` tree of
whatever you build from. Since §2 builds from the mirror sandbox, that is the
sandbox's `cwmobile/android/keystore.properties` (with the `.jks` in the same
folder) — the copy that produced v1.0.0 is already there. The mirror is outside
git entirely, so the key can never be committed from there; the founder's backup
is the master copy and the mirror copy is disposable.

**How the wiring works** (`mobile/plugins/withReleaseSigning.js`): `android/` is
the *managed* workflow and is regenerated by every `expo prebuild`, so the plugin
re-injects the `release` signingConfig each time. If `keystore.properties` is
absent it **falls back to debug signing** (today's sideload behaviour) — so a
build without the key still works; the key only *upgrades* the build.

Verify after a prebuild:

```bash
cd mobile && npx expo prebuild -p android --clean
grep -n "cleanwayKeystoreProps" android/app/build.gradle   # loader + release selector present
```

---

## 2. Build the release artifact

Set the version for this release in `mobile/app.json` first: bump
`expo.android.versionCode` (integer, +1 every build) and `expo.version`
(e.g. `"1.0.4"` / `104`). Keep them in step with the update-check server
(`mobile_latest_version_*` env in Railway) so the in-app "update available"
prompt is truthful. **As of 2026-10-08 `mobile/app.json` on `main` still says
`1.0.3` / `103`** — see §7.0.

**Current release: 1.0.4 (versionCode 104).** `mobile/app.json` already says so.
Change the server **only after** the signed APK is attached to the GitHub
release `v1.0.4` — announcing a version nobody can download sends every phone
to a 404. Then, in Railway (API service → Variables), set:

```
MOBILE_LATEST_VERSION_NAME=1.0.4
MOBILE_LATEST_VERSION_CODE=104
MOBILE_APK_URL=https://github.com/AlexMos555/linkshield/releases/download/v1.0.4/cleanway-1.0.4-104-arm.apk
```

(the URL must be the exact asset name you uploaded; the app opens only
`https://` URLs). Optionally `MOBILE_RELEASE_NOTES=<one line>`. Leave
`MOBILE_MIN_SUPPORTED_VERSION_*` empty/0 — 1.0.4 is not a security floor. In
Vercel, point `NEXT_PUBLIC_APK_URL` at the same asset URL and redeploy without
the build cache (see docs/GO_LIVE_CHECKLIST.md). Check:
`curl -s https://api.cleanway.ai/api/v1/mobile/version` shows `1.0.4` (the
answer is cached up to 15 minutes).

**SMS text model kill switch (1.0.4+).** The same answer carries
`remote_config`, driven by Railway env — no APK needed:

| Env var | Default | Effect on phones |
|---|---|---|
| `SMS_TEXT_MODEL_ENABLED` | `true` | `false` stops the on-device SMS text model; the message rules and link checks keep working. |
| `SMS_TEXT_MODEL_CAUTION_THRESHOLD_OVERRIDE` | unset | A number in (0, 1). Used only if **higher** than the threshold in the APK — the model can be made quieter, never louder. |
| `SMS_TEXT_MODEL_DANGER_THRESHOLD_OVERRIDE` | unset | Same, for the "dangerous" threshold. |

A phone picks a change up at its next app start (at most hourly) or within
about a day while the app stays open, plus up to 15 minutes of HTTP cache. It
keeps the last answer it got: an API outage, or an answer without the block,
never flips a switch; a phone that never got one runs the model. A junk value
in an override is ignored (logged), it does not stop the API from booting.
Turning the model back on = unset `SMS_TEXT_MODEL_ENABLED` (or `true`).

> ⚠️ **Build from a mirror outside the monorepo, NOT from the repo checkout.**
> npm workspaces hoist the app's packages to the repo root next to landing's
> React (19.2 at the root, while the app pins **19.1.0** for Expo SDK 54), and
> root-hoisted Expo/RN packages then resolve the wrong copies. A standalone copy
> of `mobile/` with its own `node_modules` has exactly one `react-native@0.81.5`
> and one `react@19.1.0`. (On SDK 52 the same hoisting put `react-native@0.86`
> at the root and Metro died in `VirtualView.js`.) Fixing the hoisting is a
> nice-to-have, not a launch blocker; the mirror is the proven path.
>
> **Toolchain (Expo SDK 54 / RN 0.81, verified 2026-10-08):** Node ≥ 20.19.4
> (22 is fine), JDK 17+ (Android Studio's bundled JBR 21 works), the Android SDK
> with platform **android-36** and build-tools **36.0.0**. Gradle 8.14.3, AGP
> 8.11, Kotlin 2.1.20 and **NDK 27.1.12297006** come with the generated project;
> Gradle downloads the NDK on the first build (≈2.5 GB, slow). The first full
> build took ~22 min on the 6-core Intel Mac, later ones ~2 min.
> `mobile/package-lock.json` is the lock of the verified mirror (its
> `@cleanway/*` entries point at `vendor/`).

```bash
# 1) Toolchain. (The older sandbox toolchain — $HOME/Library/Caches/cleanway-dev
#    node22/ and bin/sync.sh — is no longer on the build Mac; this works:)
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

# 2) The mirror: a copy of mobile/ outside the repo with the two workspace
#    packages vendored. Its node_modules/ survives between runs; everything
#    else is overwritten from the repo.
REPO="$HOME/Desktop/linkshield"            # your checkout
M="$HOME/Library/Caches/cleanway-dev/cwmobile"
mkdir -p "$M/vendor"
rsync -a --delete \
  --exclude '/node_modules' --exclude '/android' --exclude '/ios' \
  --exclude '/dist' --exclude '/.expo' --exclude '/vendor' \
  --exclude '/package.json' --exclude '/package-lock.json' \
  "$REPO/mobile/" "$M/"
rsync -a --delete --exclude node_modules "$REPO/packages/api-client/" "$M/vendor/api-client/"
rsync -a --delete --exclude node_modules "$REPO/packages/api-types/" "$M/vendor/api-types/"
node -e '
const fs = require("fs"); const [repo, m] = process.argv.slice(1);
const p = JSON.parse(fs.readFileSync(repo + "/mobile/package.json", "utf8"));
p.dependencies["@cleanway/api-client"] = "file:./vendor/api-client";
p.dependencies["@cleanway/api-types"] = "file:./vendor/api-types";
fs.writeFileSync(m + "/package.json", JSON.stringify(p, null, 2) + "\n");' "$REPO" "$M"
cp "$REPO/mobile/package-lock.json" "$M/package-lock.json"

cd "$M"
npm install
npx expo install --check   # "Dependencies are up to date" (reanimated is excluded on purpose)

# 3) Regenerate android/ so the config plugins and the new versionCode are
#    applied. CI=1 keeps prebuild non-interactive (the mirror is not a git repo).
CI=1 npx expo prebuild -p android --clean
grep -n "cleanwayKeystoreProps" android/app/build.gradle   # release-signing wiring present

# 4) Put the keystore where the plugin expects it (see §1) BEFORE building:
#    $M/android/keystore.properties + the .jks alongside it. `prebuild --clean`
#    deletes android/, so copy them back after every prebuild. Without them the
#    build still succeeds but is signed with the DEBUG key (big warning in the log).

# 5) The starter blocklist (1.0.2+): download + verify it into the module's
#    assets, AFTER the rsync (its --delete removes the gitignored file). Without
#    it the release build refuses to start (plugins/withSeedGuard.js; skip only
#    on purpose with -PcleanwayNoSeed).
bash scripts/fetch-seed-blocklist.sh
grep -n "cleanway-seed-guard" android/app/build.gradle

cd android

# A) Direct-download APK for the Tele2 funnel. Do NOT pass
#    -PreactNativeArchitectures: it does NOT slim the APK (it only feeds
#    splits.abi.include, and splits are off by default). Slimming is handled by
#    plugins/withAbiFilters.js, which drops the emulator-only x86/x86_64.
#    Result: 56 MB with armeabi-v7a + arm64-v8a, i.e. every real phone.
./gradlew assembleRelease
#    → android/app/build/outputs/apk/release/app-release.apk
#    (arm64-only, ~20 MB smaller but excludes old 32-bit phones:
#     CLEANWAY_ABIS=arm64-v8a npx expo prebuild -p android --clean, then rebuild.)

# B) App Bundle for the stores (35 MB). NOTE: withAbiFilters applies to every
#    RELEASE variant, so the AAB is ARM-only too (armeabi-v7a + arm64-v8a), not
#    universal. Fine for phones; it does exclude x86 Chromebooks/tablets.
#    Widen with CLEANWAY_ABIS + a fresh `expo prebuild --clean` if you need them.
./gradlew bundleRelease
#    → android/app/build/outputs/bundle/release/app-release.aab

# The seed is inside (≈2.8 MB):
unzip -l app/build/outputs/apk/release/app-release.apk | grep dns-blocklist-v2.seed.bin
```

Confirm the **target API, the signer and 16 KB alignment** before uploading:

```bash
BT="$ANDROID_HOME/build-tools/36.0.0"
APK=app/build/outputs/apk/release/app-release.apk

# targetSdkVersion:'36' (Play's floor since 31 Aug 2026), compileSdkVersion='36'.
"$BT/aapt2" dump badging "$APK" | grep -E "targetSdkVersion|compileSdkVersion"

# Should show CN=Cleanway…, NOT "CN=Android Debug".
"$BT/apksigner" verify --print-certs "$APK" | grep -i "Signer #1 certificate DN"

# 16 KB, part 1: uncompressed .so files are 16 KB-aligned inside the zip.
"$BT/zipalign" -c -P 16 -v 4 "$APK" | tail -1        # → "Verification successful"

# 16 KB, part 2: every 64-bit library's ELF LOAD segments are aligned to
# 0x4000 (16 KB). 32-bit armeabi-v7a libraries stay at 0x1000 — Play's rule is
# for 64-bit devices only.
RE="$ANDROID_HOME/ndk/27.1.12297006/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf"
rm -rf /tmp/cw-so && unzip -q "$APK" 'lib/arm64-v8a/*' -d /tmp/cw-so
for so in /tmp/cw-so/lib/arm64-v8a/*.so; do
  echo "$(basename "$so") $("$RE" -lW "$so" | awk '/LOAD/{print $NF}' | sort -u | tr '\n' ' ')"
done | grep -E "0x(1000|2000) " || echo "all arm64-v8a libraries are 16 KB-aligned"
```

Then sanity-check on the real device: install the APK, confirm it opens, turn on
the shield, then **bump versionCode, rebuild, reinstall over it** — it must update
in place (no "App not installed"). That proves B2 is fixed end-to-end.

> **What is and isn't verified (2026-10-08, Expo SDK 54 build).** Built in a
> mirror exactly as above, without the release key (so debug-signed, as
> expected): `assembleRelease` and `bundleRelease` both succeed. `aapt2` reports
> `targetSdkVersion 36`, `compileSdkVersion 36`, `versionCode 104`; the
> permission list is identical to SDK 52's 1.0.3 APK (table in §3). 16 KB:
> `zipalign -c -P 16` passes; all 21 `arm64-v8a` libraries in the APK and in the
> AAB have 16 KB LOAD alignment (the SDK 52 APK had 18 of 23 at 4 KB — React
> Native 0.76's own `libreactnative`/`libhermes`/`libfbjni` among them, which
> is why a targetSdk flag on SDK 52 could not pass Play), and the AAB's
> BundleConfig asks for `PAGE_ALIGNMENT_16K`. The merged manifest keeps the
> VpnService (`foregroundServiceType="specialUse"` + the `vpn` subtype
> property), BootReceiver in `:boot`, ShieldWatchdog, the alarm receiver, the
> link-guard activity and the `text/*` share filter unchanged;
> `enableOnBackInvokedCallback="false"` is new (below), and the unused
> `ai.cleanway.app://` deep-link scheme is gone (Expo SDK 53 stopped adding the
> package name as a scheme; nothing links to it — `cleanway://` is the scheme).
>
> **On an Android 16 emulator** (API 36.1, x86_64, a release build with x86_64
> added to the ABI filter), every native path was exercised: onboarding → tabs;
> the shield's explainer → Android's VPN consent → tunnel up (`tun0`, foreground
> service type `specialUse`), seed loaded (469,685 names), blocklist sync and
> its alarm, ordinary DNS still resolving, the list canary not resolving; the
> notification-permission prompt; the battery-optimisation explainer → Android's
> dialog → app on the idle allow-list; "Link checking" → the browser-role
> dialog → Cleanway holds `ROLE_BROWSER`, and a tapped link goes through
> `LinkGuardActivity` to Chrome; a shared SMS text → the SMS check screen with
> the on-device verdict; a link check against the API; system back; and a
> **reboot**: BootReceiver restarted the shield by itself (FGS start allowed,
> watchdog job and refresh alarm re-armed). Installing the new build over the
> previous one (same key, same versionCode) kept its data. Both navigation modes
> (gesture and 3-button) were checked for insets.
>
> The native module's Kotlin unit tests: 328 of 330 pass. The two that fail are
> wall-clock budgets in `MessageAnalyzerTest` (≈9.6 ms per 1,000-character
> message against a 5 ms limit, and the pathological-input case) — they fail
> the same way on `main`'s SDK 52 build on this Mac (9.8 ms), so they are a
> machine-speed / budget question, not an effect of the upgrade.
>
> Still **unverified**: the release-signed build on the founder's Samsung —
> install over the installed 1.0.x (same key, higher versionCode), the shield on
> mobile data, One UI's battery manager, the blocked-site notification on a real
> blocked site, the QR scanner (camera) and the after-call screen. No release
> key was used and nothing was installed on the phone during the upgrade.

### Android 15/16 behaviour (targetSdk 34 → 36) and what the app does about it

- **Edge-to-edge is mandatory** (Android 15 enforces it at targetSdk 35; Android
  16 removes the opt-out). The app now draws under the status and navigation
  bars. Stack headers pad for the status bar; `app/_layout.tsx` pads every stack
  screen by the navigation-bar inset, and the tab bar's height includes it
  (`app/(tabs)/_layout.tsx` — the fixed 84 px bar was covered by Android's
  3-button navigation). `plugins/withDarkSystemBars.js` puts the activity in
  night mode before React Native sets up edge-to-edge, so the transparent
  navigation bar and its contrast scrim are dark even when the phone uses the
  light system theme (before, they came out as a white strip). Native dialogs
  (Alert) are dark as a side effect, matching the app.
- **Predictive back**: at targetSdk 36 Android stops calling `onBackPressed`
  unless the app opts out. React Native still relies on it, so
  `android.predictiveBackGestureEnabled` is pinned to `false` in `app.json`
  (Expo SDK 54's default) → `enableOnBackInvokedCallback="false"`. The system
  back button/gesture navigates the JS stack as before.
- **Large screens** (≥ 600 dp): Android 16 ignores `screenOrientation`, so on
  tablets/foldables the portrait-only app can rotate and fill the screen. Phones
  are unaffected.
- **Foreground service**: the shield is `specialUse` with subtype `vpn`. Android
  15's ban on starting some FGS types from `BOOT_COMPLETED` (dataSync, camera,
  media, phoneCall, microphone…) does not cover `specialUse`, so BootReceiver's
  restart path is unchanged (verified on the emulator, above).
- **Local network permission** (Android 16 opt-in, enforced in a later release):
  DNS on port 53 to the network's own resolver is exempt, which is what the
  shield forwards to. Re-check when Google turns enforcement on.
- **16 KB pages**: covered by React Native ≥ 0.77 and NDK r27/r28 builds; see
  the checks above. Play blocks non-compliant updates of apps targeting
  Android 15+ from 1 Feb 2027.
- **Architecture**: the app stays on React Native's legacy architecture
  (`newArchEnabled: false`, as on SDK 52; reanimated stays on 3.19 because 4.x
  needs the New Architecture). Expo SDK 54 is the last SDK that allows this —
  moving to SDK 55+ means switching to the New Architecture first.

---

## 3. Data-collection declaration (RuStore + Play "Data safety")

Answer from the real egress — do not embellish. Source of truth for every row:
`docs/PRIVACY.md` → "The Android app".

**Does the app collect or transmit user data?** → **Yes** (a site name is sent
for the safety check).

| Data type | Collected? | Sent off device? | Purpose | Shared w/ 3rd parties? |
|---|---|---|---|---|
| **Site names (hosts) of links the person checks** — typed, pasted, scanned from a QR code, shared, opened through the link guard, or found in a shared message (max 3 per message). Not full URLs, not page content | Yes, transient | Yes → `api.cleanway.ai` (`GET /api/v1/public/check/{host}`, no account token) | App functionality — the scam check | The server checks the bare host with threat-intelligence services (Google Safe Browsing and others listed in `docs/PRIVACY.md`) and Cloudflare's family resolver; no user identity goes with it |
| **Message (SMS) text** the person shares or pastes | Processed on the phone only | **No** — the text never leaves the phone and is never stored | Scam check of the message | No |
| **Email address** | Only if the person signs in (optional) | Yes → our backend (Supabase) | Account, linked-devices list | No |
| **Device list of the account** (a random device ID, platform, a name) | Only when signed in | Yes → our backend | Showing / unlinking the person's devices | No |
| **Random install number** (`X-Cleanway-Install`, a UUID made on the phone, replaced every 24 h) | Yes | Yes → `api.cleanway.ai` | Rate limiting per phone instead of per carrier IP | No |
| **Crash logs & diagnostics** | Yes | Yes → Sentry | Stability / bug-fixing | Processor only (Sentry) |
| **Approximate info from the request** (server sees the connection IP like any web request; raw in expiring rate-limit keys ≤ 1 h, hashed in the audit log) | Minimal | Inherent to any request | Abuse/rate control | No |
| **DNS lookups of sites that are NOT blocked** | Not collected by us | Go to the network's own DNS (operator / Wi-Fi), fallback Cloudflare `1.1.1.1` / Quad9 `9.9.9.9` — as they would without Cleanway | Normal name resolution | Those resolvers see the name, as without Cleanway; Cleanway's server does not |
| Precise location, contacts, photos, call logs, phone numbers, full browsing history | **No** | No | — | — |

Cross-cutting answers:
- **Encrypted in transit?** Yes (TLS/HTTPS everywhere; the DNS fallback to
  Cloudflare over HTTPS is encrypted, plain DNS to the operator is not — same as
  without the app).
- **Can users request deletion?** Yes — in the app (Settings → Удалить аккаунт,
  or the Account screen), on cleanway.ai/account, and by email; GDPR
  export/delete endpoints exist server-side.
- **Data used for ads / sold?** No. No ad SDKs, no data sale.
- **Leaked-password check** (`mobile/app/breach.tsx`; registered as a screen
  but not linked from any menu in 1.0.4): sends only the first 5 characters of a
  SHA-1 hash (k-anonymity), never the password itself.

### Manifest permissions (what RuStore's automated scan shows — answer from this table)

The "photos: No" answer above and the `CAMERA` permission are **not** a
contradiction: the camera is opened only when the user taps "Сканировать QR",
frames are decoded live for a QR code and never saved, previewed elsewhere, or
uploaded. Moderators do ask when a declared permission is missing from the
justification, so every `uses-permission` in the APK is listed here.

| Permission | Status | Why it is there |
|---|---|---|
| `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE` | **Used** | The on-device DNS shield (§4). |
| `RECEIVE_BOOT_COMPLETED` | **Used** | Re-starts the shield after a reboot (the home screen says so). |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | **Used — new in 1.0.4** | The "Чтобы защита не выключалась" checklist asks Android once, after explaining why, to stop battery optimisation from killing the shield. The person can decline. Justification text in §4. |
| `POST_NOTIFICATIONS`, `VIBRATE` | **Used** | The persistent "shield on" notification, blocked-site alerts, and the after-call reminder. |
| `CAMERA` | **Used** | QR-code scanning only (`scanner.tsx`); runtime-requested on first use; no photo/video capture. |
| `INTERNET`, `ACCESS_NETWORK_STATE`, `WAKE_LOCK` | **Used** | Host checks against `api.cleanway.ai`, blocklist refresh, offline detection. |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | Library | Declared by `expo-secure-store` for keystore-backed storage; the app never prompts for biometrics. |
| `com.google.android.c2dm.permission.RECEIVE`, launcher badge permissions (`com.sec…`, `com.huawei…`, `com.htc…`, `READ_APP_BADGE`, …) | Library | Declared by `expo-notifications` for push/badges. No Firebase project is configured in the app, so no push token is ever created. |
| `RECORD_AUDIO`, `SYSTEM_ALERT_WINDOW`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` | **Removed** (since versionCode 101) | Library/template defaults the app does not use. |
| `READ_PHONE_STATE`, `READ_CALL_LOG`, `ANSWER_PHONE_CALLS`, `CALL_PHONE`; any SMS permission | **Never requested** | Blocked in `app.json` and pinned by `mobile/scripts/check-android-permissions.mjs` (CI). The call screen knows *that* a call is going on from the phone's audio mode only (`CallState.kt`); it cannot see numbers or hear calls. |

The "removed" rows are blocked in `mobile/app.json`
(`expo.android.blockedPermissions` + `expo-camera` → `recordAudioAndroid: false`),
which makes `expo prebuild` write `tools:node="remove"` entries so library
manifests cannot re-add them. Only v1.0.0 (versionCode 100) still declared them.
Before uploading 1.0.4, run `aapt dump permissions` on the new APK and confirm the
list matches this table (and that `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is there).

---

## 4. Permission justifications — VpnService, battery, camera (BOTH stores will ask)

Paste the first block verbatim into the "why does your app use VpnService / the
VPN API" field. It matches the store copy and `docs/PRIVACY.md`.

> Cleanway uses Android's VpnService **locally, on the device, to filter DNS and
> block known phishing/scam domains before they load**. The tunnel routes only
> DNS lookups to the app; page contents, messages and calls never pass through
> it. A name on the on-device blocklist is answered "not found"; every other
> lookup is forwarded to the DNS server of the network the phone is on (the
> mobile operator's or the Wi-Fi router's), and only if that fails to Cloudflare
> (1.1.1.1) or Quad9 (9.9.9.9) — the same lookups the phone makes without
> Cleanway. It is **not** an anonymity or proxy VPN: it does **not** route the
> user's traffic to our servers or any proxy, and does **not** hide or change
> the user's IP address. The blocklist is stored on the device and matched
> on-device. This is the core protection feature and is disclosed to the user
> via the standard Android VPN consent dialog before it starts.

Google Play specifics:
- In the app's **Advanced/VpnService declaration**, select the "core
  functionality (device security / parental control)" use, not "app that
  connects to a VPN gateway".
- Foreground-service type is `specialUse` (declared in the manifest, with the
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` = `vpn` property); provide the same
  justification if Play asks about `FOREGROUND_SERVICE_SPECIAL_USE`. Play Console
  asks every app targeting Android 14+ to declare its foreground-service types
  under **App content → Foreground service permissions** — tick *Special use*;
  the paste-ready justification and video note are in `docs/STORES.md` §6.6.
  It is the only FGS type the app declares (`LinkCheckService` is a plain
  short-lived service, not a foreground one).

**Battery optimisation** (paste if asked about
`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`; source: `docs/MOBILE_AUTO_PROTECTION.md`):

> Cleanway is a safety app: its core function is an always-on local DNS filter
> (VpnService) that blocks known scam and phishing sites in every app. Battery
> optimisation and OEM battery managers stop it in the background without telling
> the user, which leaves them unprotected. The app asks once, after explaining
> why, from its "Keep protection on" checklist; the person can decline and the
> app keeps working.

**Camera** (paste if asked about `android.permission.CAMERA`):

> Cleanway uses the camera for one purpose: scanning a QR code so the link
> inside it can be checked before it is opened. The permission is requested at
> runtime only when the user opens the scanner. Frames are decoded on the device
> and discarded; no photo or video is captured, stored, or uploaded, and the app
> does not access the photo gallery. Audio recording is not used (the
> `RECORD_AUDIO` permission is removed from builds after versionCode 100).

---

## 5. Store assets & review notes

Everything RuStore asks for is in the repo — upload from these paths:

| Asset | Path | Spec |
|---|---|---|
| App icon | `mobile/assets/store/icon-512.png` | 512 × 512 PNG, opaque (downscaled from `mobile/assets/icon.png`; do not upload the 1024 source). |
| Phone screenshots (≥ 3 required) | `mobile/assets/store/screenshots/01.png` … `04.png` | 1080 × 2400 PNG, RU locale, unedited frames of the **signed v1.0.0 APK** on an Android 15 emulator, captured 2026-09-13. `screenshots/README.md` says what each shows. `05.png` (Settings) shows "Улучшить тариф" and "Отчёт за неделю" — do not upload it. |

Captions and the recommended new 1.0.4 screenshots are in §7.6.

**Sign-in is tested by moderators — fix SMTP before submitting.** RuStore
reviewers open every entry point, including "Войти". The app's only sign-in is an
email one-time code sent by Supabase, whose built-in mailer is capped at 2
emails/hour and is not meant for production. Connect a transactional SMTP
provider (e.g. Resend) in the Supabase Auth settings *before* upload, then verify
a code actually arrives on a fresh address. In the review notes also give the
reviewer a test address they can receive on (or state explicitly that login is
optional and every protection feature works without it — both are true).

- **Review note** (paste): "The VPN permission is used only for a local on-device
  DNS phishing filter — no remote VPN gateway, no IP masking, no traffic proxying;
  lookups that are not blocked go to the network's own DNS as usual. See the
  VpnService justification. The camera is used only to scan QR codes. The app has
  no SMS, phone-state or call-log permissions: a message is checked only when the
  user shares or pastes it, and the call warning knows only that a call is in
  progress (from the audio mode). Core protection is free; no login is required —
  sign-in (email code) is optional and shows the account's linked devices."

---

## 6. Launch-blocker status (see docs/TELE2_LAUNCH_PLAN.md)

- ✅ B1 signing wiring · ✅ B2 versionCode · ✅ B4 blocklist no-429 · ✅ B5 honest
  listing + support page · ✅ `/android` funnel page · ✅ in-app update check
- ✅ Release keystore generated + backed up, signed v1.0.0 APK (versionCode 100)
  built and downloaded (§1–2) · ✅ store icon + screenshots in repo (§5) ·
  ✅ unused Android permissions blocked in `app.json` (versionCode 101+)
- ⏳ **Founder:** RuStore account (VK ID), transactional SMTP for sign-in mail
  (§5), host the signed APK + set `NEXT_PUBLIC_APK_URL`, confirm the support
  mailbox, install-and-update test on a real phone (§2), the 1.0.4 TODOs in §7.0.

---

## 7. Листинг RuStore — версия 1.0.4 (вставлять как есть)

Copy below is the paste-ready text. Notes, TODOs and character counts are
outside the text blocks — never paste them. Every claim was checked against
the code on 2026-10-08 (`main` @ `9aff8ee`); the evidence is listed in §7.7.

### 7.0 TODO for the founder before submitting 1.0.4

- [ ] **Bump the version.** `mobile/app.json` on `main` is still `1.0.3` /
      versionCode `103`. Set `1.0.4` / `104` and the update-check env in Railway.
- [ ] **SMS model switch** (`docs/ACCOUNTS_BILLING_PLAN.md` §7 item 6: "выключатель
      модели SMS" before 1.0.4) is not in `main` yet. The copy below says
      "проверка СМС стала точнее" — true with the on-device text model (#99) and
      the new rules (#81–#96). If the model is switched off in the build, the
      sentence still holds for the rules alone; if you change more, re-read §7.5.
- [ ] **Automatic SMS check is NOT in this copy.** It lives only on
      `feat/sms-auto-rustore`, which is not merged into `main` (no SMS receiver in
      `mobile/`, and `check-android-permissions.mjs` forbids SMS permissions). If
      you decide to ship it in the RuStore build, the copy, §3 and §4 must all
      change (new permission, new data row) — ask for a rewrite, do not edit one
      line.
- [ ] **Pricing line.** The Russian build hides paid plans
      (`mobile/src/config/market.ts`: `PAID_PLANS_HIDDEN_LANGUAGES = {"ru"}`), the
      daily free-check limit and the 7-day trial are not in the app, and RuStore
      in-app payments are not wired. So the copy says only "Основная защита —
      бесплатно." When paid is live in the build, replace the "СКОЛЬКО СТОИТ"
      block with (numbers from `docs/ACCOUNTS_BILLING_PLAN.md` §5 — confirm them):
      "Блокировка опасных сайтов по списку — бесплатно и без ограничений. 3
      подробные проверки в день — бесплатно, первые 7 дней — без ограничений.
      Подписка по желанию: 99 ₽ в месяц за 3 устройства (телефон, планшет или
      браузер с расширением), каждое следующее — 29 ₽ в месяц."
- [ ] **Old upgrade screen on non-Russian phones.** Paid plans are hidden only
      when the app language is Russian. A RuStore user whose phone is in English
      (or any other language) sees Settings → Plan → `mobile/app/upgrade.tsx`:
      "$4.99 / $9.99", "10 checks/day" and a link to pay on cleanway.ai. Those
      prices contradict the new ones and the link is an outside payment.
      Hide it for every language in the RuStore build (one line in
      `mobile/src/config/market.ts`) before submitting.
- [ ] **Screenshots** are from v1.0.0. The home screen in 1.0.4 has the "Мне
      звонят" button and the "Чтобы защита не выключалась" card. Recapture
      `01`–`04` on the signed 1.0.4 APK and add the three new frames in §7.6.
- [ ] **RuStore field limits** for the app name and keywords/tags: confirm in the
      console (the counts below are given so you can trim if needed).
- [ ] **Keep-alive on real phones.** The "щит сам пробует включиться снова"
      line in "Что нового" describes `ShieldWatchdog` (#105), which has not been
      verified on Samsung/Xiaomi hardware (`docs/MOBILE_AUTO_PROTECTION.md`).
      Test it once before submitting; if it does not work, delete that clause.

### 7.1 Название

```text
Cleanway: защита от мошенников
```

30 characters. "защита от мошенников" is the phrase people type; "фишинг"
is a word the audience mostly does not use.

### 7.2 Краткое описание (лимит RuStore — 80 символов)

```text
Защита от мошенников: блокирует опасные сайты, проверяет СМС и ссылки
```

69 characters (counted with Python `len()`).

### 7.3 Полное описание (лимит — 4000 символов)

<!-- count: rustore_full max=4000 -->
```text
Cleanway — защита от мошенников в телефоне. Не даёт открыть известные мошеннические сайты и помогает проверить подозрительное СМС или ссылку, прежде чем вы по ней перейдёте. Включили один раз — защита работает сама, даже когда приложение закрыто. Можно поставить себе и родителям.

ОТ ЧЕГО ЗАЩИЩАЕТ
• Сайты мошенников. Cleanway блокирует известные мошеннические и фишинговые сайты во всех приложениях и браузерах. Такая страница просто не откроется, а Cleanway сообщит об этом уведомлением.
• Подозрительные СМС. Пришло сообщение про «посылку», «блокировку карты» или «выигрыш»? Перешлите его в Cleanway кнопкой «Поделиться» или вставьте текст. Приложение скажет, похоже ли это на мошенников, и объяснит почему — простыми словами.
• Опасные ссылки и QR-коды. Вставьте ссылку или наведите камеру на QR-код — Cleanway проверит сайт, прежде чем вы его откроете.
• Обман по телефону. Если во время звонка или сразу после него вы пытаетесь отключить защиту или открыть заблокированный сайт, Cleanway покажет предупреждение: так действуют мошенники. Кнопка «Мне звонят» подскажет, что делать, если звонят «из банка» или «из полиции», и поможет одним нажатием позвонить близкому. Cleanway не слушает разговоры, не видит номера и не блокирует звонки.

ПРОСТО ДЛЯ ВСЕХ
• Понятные предупреждения на русском, без технических слов.
• Подсказки на главном экране: что настроить в телефоне, чтобы экономия батареи не выключала защиту.
• Если защита была включена, после перезагрузки телефона она включится сама.
• Аккаунт не нужен. Войти по email можно по желанию — тогда в одном месте видны все ваши устройства, и лишнее можно отвязать.

КАК ЭТО УСТРОЕНО — ЧЕСТНО
• Список известных мошеннических сайтов хранится на телефоне, и сверка идёт там же. Для этого Cleanway использует встроенный в Android механизм VPN. Это не VPN для анонимности: ваш IP-адрес не меняется, а страницы, сообщения и звонки через Cleanway не проходят.
• Остальные сайты телефон находит как обычно — через вашего оператора или Wi-Fi, а если они не отвечают — через общедоступные сервисы Cloudflare или Quad9.
• На Android одновременно может работать только один VPN. Если у вас уже включён другой VPN, придётся выбрать: он или защита Cleanway.
• Текст СМС проверяется на телефоне и никуда не отправляется. На наш сервер могут уйти только имена сайтов из ссылок в сообщении — не больше трёх.
• Когда вы проверяете ссылку, на сервер Cleanway уходит только имя сайта (например, example.ru), без остальной части адреса. Сервер сверяет его в том числе с внешними базами опасных сайтов, например Google Safe Browsing.
• Мы не показываем рекламу и не продаём данные.

ЧЕГО CLEANWAY НЕ ОБЕЩАЕТ
Новые мошеннические сайты и сообщения появляются каждый день, и ни одна программа не ловит их все. Если сомневаетесь — не переходите по ссылке, никому не называйте коды из СМС и перезвоните в банк по номеру на обратной стороне карты.

СКОЛЬКО СТОИТ
Основная защита — бесплатно.

Вопросы и помощь: support@cleanway.ai
Политика конфиденциальности: cleanway.ai/privacy-policy
```

Character count: see §7.7 (re-run the snippet there after any edit).

### 7.4 Ключевые слова

```text
защита от мошенников, мошенники, антимошенник, проверка ссылок, проверка СМС, мошеннические СМС, фишинг, защита от фишинга, опасные сайты, блокировка сайтов, телефонные мошенники, защита для пожилых, безопасность телефона, проверка QR-кода
```

Every keyword maps to a feature in the build (no "антивирус", no "VPN" as a
selling word — the app is neither an antivirus nor a privacy VPN).

### 7.5 Что нового в версии 1.0.4

<!-- count: rustore_whatsnew max=500 -->
```text
• «Мне звонят»: если во время звонка вы пытаетесь отключить защиту или открыть заблокированный сайт, Cleanway предупредит: так действуют мошенники.
• Проверка СМС стала точнее: больше схем мошенников, ссылки без «http://». Текст по-прежнему не покидает телефон.
• Подсказки «Чтобы защита не выключалась»; щит сам пробует включиться снова, если телефон его остановил.
• Аккаунт: вход сохраняется, видны ваши устройства, лишнее можно отвязать.
• Понятнее сообщения при входе по email.
```

Source (all merged to `main` after the 1.0.3 commit `6aec2ed`): #69 call
stop screen + after-call reminder; #81, #86, #91, #92, #96, #99 SMS rules,
links without `http://`, on-device text model; #105 keep-alive checklist,
battery exemption, `ShieldWatchdog`; #108 stay signed in, Account screen,
unlink, delete; #72 sign-in error texts. The 500 limit above is our own
target (RuStore allows more); short notes get read.

### 7.6 Подписи к скриншотам

Existing frames (v1.0.0 — recapture on 1.0.4, see §7.0):

| File | Screen | Caption |
|---|---|---|
| `01.png` | Щит включён | `Включили один раз — защита работает сама` |
| `02.png` | Опасная ссылка | `Опасный сайт — и простое объяснение почему` |
| `03.png` | История | `Сайты мошенников блокируются во всех приложениях` |
| `04.png` | Оценка | `Советы, как обезопасить себя` |

New frames to capture on 1.0.4 (TODO):

| File | Screen | Caption |
|---|---|---|
| `05.png` | Проверка СМС с вердиктом «Опасно» | `Проверьте СМС — текст не уходит с телефона` |
| `06.png` | Экран во время звонка | `Звонят «из банка»? Cleanway подскажет` |
| `07.png` | «Чтобы защита не выключалась» | `Подскажет, как не дать телефону выключить защиту` |

Order for upload: `01`, `05`, `02`, `06`, `03`, `07`, `04` — the first three
frames carry the three main promises (sites, SMS, calls).

### 7.7 Evidence and character counts

Counts (Python `len()`, 2026-10-08): название 30 · краткое описание 69/80 ·
полное описание and "Что нового" — run:

```bash
python3 - <<'EOF'
import re, pathlib
t = pathlib.Path("docs/RUSTORE_SUBMISSION.md").read_text(encoding="utf-8")
for name, mx, body in re.findall(r"<!-- count: (\S+) max=(\d+) -->\n```text\n(.*?)\n```", t, re.S):
    print(name, len(body), "/", mx, "OK" if len(body) <= int(mx) else "TOO LONG")
EOF
```

What each claim rests on:

| Claim in the copy | Code |
|---|---|
| Blocklist on the phone; DNS-only tunnel; not-found answer for listed names | `mobile/modules/cleanway-vpn/android/src/main/java/ai/cleanway/app/CleanwayVpnService.kt:255` (`addRoute(VPN_GATEWAY_IP, 32)`), `:444` (NXDOMAIN) |
| Other lookups: network DNS first, then Cloudflare / Quad9 | `CleanwayVpnService.kt:5-6`, `:519-525` |
| Link check sends the host only | `packages/api-client/src/index.ts:555` (`/api/v1/public/check/{host}`), `mobile/src/utils/host.ts:25` |
| SMS text stays on the phone; max 3 hosts | `docs/PRIVACY.md` "Message check (SMS)"; `mobile/src/utils/message-verdict.ts:23` |
| No SMS / phone permissions; call awareness from audio mode | `mobile/scripts/check-android-permissions.mjs:36-40`; `CallState.kt:21-22` |
| Call warning + after-call reminder | `mobile/src/utils/call-guard.ts:1-20`; `CallGuard.kt` (`noteEvent` from `CleanwayVpnService.kt:737`, `MessageCheck.kt:49`, `LinkCheckService.kt:132`) |
| Battery checklist | `mobile/src/components/shield/KeepAliveCard.tsx`; module manifest line 31 |
| Account: devices, unlink, delete | `mobile/app/account.tsx`; `mobile/app/(tabs)/settings.tsx:321-332` |
| Paid plans hidden in Russian | `mobile/src/config/market.ts:10` |
