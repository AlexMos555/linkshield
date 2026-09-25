# RuStore + Google Play — Android Submission Runbook (Cleanway)

Code-grounded, copy-paste-ready. The data-collection answers below come from the
**actual mobile egress** (the app contacts only `api.cleanway.ai` + `cleanway.ai`,
plus Sentry for crash logs and Supabase for optional account/family — verified,
no third-party ad/analytics SDKs). A declaration that doesn't match the code is a
rejection (and, on Play, a takedown) trigger. Listing copy is in
`mobile/STORE_LISTING.md` (RU authoritative).

RuStore is the **primary** channel for the Tele2 RF launch.

> **Two APKs, one app (decided 2026-09-25).** The same code, package
> (`ai.cleanway.app`), version and release key build two APKs:
>
> | APK | Build | Where it goes | SMS |
> |---|---|---|---|
> | **Direct** `app-release.apk` | `./gradlew assembleRelease` | cleanway.ai/android + the GitHub release. Never RuStore. | **None** — no SMS permission, no SMS receiver, ever. |
> | **RuStore** `app-rustore.apk` | `./gradlew assembleRustore` | **RuStore only.** | `RECEIVE_SMS` + a receiver, off until the person turns on "SMS-сообщения". |
>
> ⛔ **Never upload `app-rustore.apk` to the website or a GitHub release.** Google
> Play Protect's enhanced fraud protection hard-blocks (no "install anyway")
> any browser- or messenger-downloaded APK that declares `RECEIVE_SMS`, and
> Android 15+ puts it behind "restricted settings". Store installs are not
> affected. Both APKs share the signature, so either installs over the other:
> the direct APK installed over the RuStore one silently removes the SMS
> check, which is why the RuStore build's in-app update banner never points
> at the website APK (`planUpdate` in `mobile/src/lib/update-check.ts`).

> ⚠️ **Google Play is BLOCKED right now — do not waste time submitting there.**
> Verified 2026-08-31: the built APK targets **API 34**, but from **31 Aug 2026**
> Google Play requires new apps and updates to target **API 36** (Android 16);
> anything at 35 or lower is rejected. Raising it is not a flag flip — Expo SDK 52
> / RN 0.76 is built around targetSdk 34, so reaching 36 means an Expo SDK upgrade
> plus on-device retesting of the VPN shield. Treat Play as a post-launch project.
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
| **[F] Founder only** | Keep the keystore backup safe (§1). Create the RuStore developer account (VK ID, физлицо). Wire transactional SMTP for sign-in mail before submitting (§5). Confirm `support@cleanway.ai` receives mail. Upload the artifact + paste the answers below. |
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
(e.g. `"1.0.0"`). Keep them in step with the update-check server
(`mobile_latest_version_*` env in Railway) so the in-app "update available"
prompt is truthful.

> ⚠️ **Build from the mirror sandbox, NOT from the monorepo.** Two things in the
> repo checkout break the Metro bundle (verified 2026-08-25):
> 1. **Node version.** Expo SDK 52 needs Node ≤22; the machine's default `node`
>    is 25. The sandbox ships its own Node 22 at `~/Library/Caches/cleanway-dev/node22/bin`.
> 2. **Hoisted React Native.** npm workspaces hoist a much newer
>    `react-native@0.86.2` to the monorepo root, while the app pins **0.76.9**
>    (SDK 52). Root-hoisted `expo`, `expo-asset`, `expo-constants`,
>    `expo-file-system` and `expo-linking` then resolve the WRONG RN, and Metro
>    dies with a `SyntaxError` in RN's `VirtualView.js`. The mirror has a clean
>    `react-native@0.76.9`, which is why builds succeed there.
>
> Verified in the mirror on 2026-08-25: the JS bundles cleanly —
> `entry-*.hbc, 4.98 MB` — including the OTP sign-in, update check and link-guard
> code. Fixing the monorepo hoisting is a nice-to-have cleanup, **not** a launch
> blocker; the mirror path is the proven one.

```bash
CACHE="$HOME/Library/Caches/cleanway-dev"
REPO="$HOME/Desktop/LinkShield/LinkShield"   # the monorepo checkout (for the APK guard)

# 0) Push the current repo state into the build mirror (keeps vendored
#    workspace packages; excludes android/ios/node_modules by design).
bash "$CACHE/bin/sync.sh"

# 1) Use the sandbox toolchain: Node 22 + JDK 17 + the Android SDK.
export JAVA_HOME=/opt/homebrew/opt/openjdk@17
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$CACHE/node22/bin:$JAVA_HOME/bin:$PATH"

cd "$CACHE/cwmobile"
# 2) Regenerate android/ so the release-signing plugin and the new versionCode
#    are actually applied (sync.sh deliberately does not copy android/).
npx expo prebuild -p android --clean
# Sanity: the signing wiring must be present in the generated gradle.
grep -n "cleanwayKeystoreProps" android/app/build.gradle

# 3) Put the keystore where the plugin expects it (see §1) BEFORE building:
#    $CACHE/cwmobile/android/keystore.properties + the .jks alongside it.

cd android

# A) Direct-download APK for the Tele2 funnel (cleanway.ai + GitHub). Do NOT pass
#    -PreactNativeArchitectures: measured 2026-08-31, it does NOT slim the APK
#    (it only feeds splits.abi.include, and splits are off by default — the
#    build still came out 92 MB with all four ABIs). Slimming is handled by
#    plugins/withAbiFilters.js, which drops the emulator-only x86/x86_64.
#    Result: 55 MB with armeabi-v7a + arm64-v8a, i.e. every real phone.
./gradlew assembleRelease
#    → android/app/build/outputs/apk/release/app-release.apk
#    (arm64-only, ~20 MB smaller but excludes old 32-bit phones:
#     CLEANWAY_ABIS=arm64-v8a npx expo prebuild -p android --clean, then rebuild.)

# A2) Prove it declares no SMS access before it goes anywhere (exit 0 = PASS):
node "$REPO/mobile/scripts/check-apk-permissions.mjs" app/build/outputs/apk/release/app-release.apk direct

# R) The RuStore APK — the one that checks incoming SMS. RuStore ONLY.
#    Same code, version and key as A; its manifest adds RECEIVE_SMS and the
#    SMS receiver (mobile/plugins/withRustoreVariant.js, build type "rustore").
./gradlew assembleRustore
#    → android/app/build/outputs/apk/rustore/app-rustore.apk
node "$REPO/mobile/scripts/check-apk-permissions.mjs" app/build/outputs/apk/rustore/app-rustore.apk rustore
#    One-shot (sync, mirror check, build, guard, signer check), in the sandbox:
#    bash "$CACHE/bin/build-rustore.sh" > "$CACHE/rustore.log" 2>&1   # then look for "### EXIT=0"

# B) App Bundle for the stores. NOTE: withAbiFilters applies to every RELEASE
#    variant, so the AAB is ARM-only too (armeabi-v7a + arm64-v8a), not
#    universal — verified by building it. That is fine for this market (no
#    retail x86 Android phones) but it does exclude x86 Chromebooks/tablets.
#    Widen with CLEANWAY_ABIS + a fresh `expo prebuild --clean` if you need them.
./gradlew bundleRelease
#    → android/app/build/outputs/bundle/release/app-release.aab
```

Confirm it is **release-signed, not debug**:

```bash
# Should show CN=Cleanway…, NOT "CN=Android Debug".
$ANDROID_HOME/build-tools/34.0.0/apksigner verify --print-certs \
  app/build/outputs/apk/release/app-release.apk | grep -i "Signer #1 certificate DN"
```

Then sanity-check on the real device: install the APK, confirm it opens, turn on
the shield, then **bump versionCode, rebuild, reinstall over it** — it must update
in place (no "App not installed"). That proves B2 is fixed end-to-end.

> **What is and isn't verified (2026-08-31).** The full release build IS done:
> a signed 55 MB APK exists and `apksigner` reports *Verifies*, v2 scheme,
> `CN=Cleanway` — not the debug key. Both config plugins have committed tests
> (`mobile/plugins/__tests__/plugins.test.js`, 15 assertions, run in CI) covering
> correct anchors, idempotency across prebuilds, the debug-signing fallback, and
> that ABI filtering never touches debug builds.
>
> Still **unverified**: that the APK installs on a real phone and updates over
> itself (bump versionCode, rebuild, reinstall). No device has been attached —
> this is the one check that needs the founder's Samsung.

---

## 3. Data-collection declaration (RuStore + Play "Data safety")

Answer from the real egress — do not embellish.

**Does the app collect or transmit user data?** → **Yes** (a domain name is sent
for the safety check).

| Data type | Collected? | Sent off device? | Purpose | Shared w/ 3rd parties? |
|---|---|---|---|---|
| **Domain names of checked/visited sites** (not full URLs, not page content) | Yes, transient | Yes → `api.cleanway.ai` | App functionality — the phishing safety check | No |
| **Email address** | Only if the user makes an account / joins Family | Yes → our backend (Supabase) | Account & Family sharing | No |
| **Crash logs & diagnostics** | Yes | Yes → Sentry | Stability / bug-fixing | Processor only (Sentry) |
| **Approximate info from the request** (server sees the connection IP like any web request; stored only as a truncated 64-bit hash) | Minimal | Inherent to any request | Abuse/rate control | No |
| **SMS** (RuStore APK only, when the person turns on "SMS-сообщения") | **Processed on the device only, not collected**: each incoming SMS is checked in memory and dropped. For one that looks like a scam the phone keeps time, sender, verdict, reason codes and link hosts — on the phone, never sent | **No** — nothing about an SMS leaves the phone, not even a link's domain | App functionality — warning about scam SMS | No |
| Precise location, contacts, photos, call logs, full browsing history | **No** | No | — | — |

Cross-cutting answers:
- **Encrypted in transit?** Yes (TLS/HTTPS everywhere).
- **Can users request deletion?** Yes — in-app, and by email; GDPR export/delete
  endpoints exist server-side.
- **Data used for ads / sold?** No. No ad SDKs, no data sale.
- **Breach/password check** (if surfaced): uses k-anonymity — only a short hash
  prefix leaves the device, never the email/password itself.

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
| `POST_NOTIFICATIONS`, `VIBRATE` | **Used** | The persistent "shield on" notification and blocked-site alerts. |
| `CAMERA` | **Used** | QR-code scanning only (`scanner.tsx`); runtime-requested on first use; no photo/video capture. |
| `RECEIVE_SMS` | **Used — RuStore APK only** | The automatic SMS check (§4). Runtime-requested only when the person turns on "SMS-сообщения", after an in-app explanation. Not `READ_SMS`: the inbox is never read. Absent from the direct APK. |
| `INTERNET`, `ACCESS_NETWORK_STATE`, `WAKE_LOCK` | **Used** | Domain checks against `api.cleanway.ai`, blocklist refresh, offline detection. |
| `USE_BIOMETRIC`, `USE_FINGERPRINT` | Library | Declared by `expo-secure-store` for keystore-backed storage; the app never prompts for biometrics. |
| `com.google.android.c2dm.permission.RECEIVE`, launcher badge permissions (`com.sec…`, `com.huawei…`, `com.htc…`, `READ_APP_BADGE`, …) | Library | Declared by `expo-notifications` for push/badges. No Firebase project is configured in the app, so no push token is ever created. |
| `RECORD_AUDIO` | **Removed from the next build** | Came from the `expo-camera` plugin default (`recordAudioAndroid: true`); the app records no audio or video. |
| `SYSTEM_ALERT_WINDOW` | **Removed from the next build** | Expo's bare template adds it for the development red-box overlay; unused in release. |
| `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE` | **Removed from the next build** | Expo template + `expo-file-system` manifest defaults; the app has no file picker, export, or gallery access. |

The four "removed" rows are blocked in `mobile/app.json`
(`expo.android.blockedPermissions` + `expo-camera` → `recordAudioAndroid: false`),
which makes `expo prebuild` write `tools:node="remove"` entries so library
manifests cannot re-add them. **v1.0.0 (versionCode 100) still declares them** —
the change ships with the next build (versionCode 101). If you submit the
versionCode 100 artifact, answer any moderator question with the rows above; if
you rebuild first, re-run `aapt dump permissions` on the new APK and confirm the
four names are gone before uploading.

---

## 4. Permission justifications — VpnService and Camera (BOTH stores will ask)

Paste the first block verbatim into the "why does your app use VpnService / the
VPN API" field. It is the same honest framing as the store copy and the landing
page. The second block answers the camera question.

> Cleanway uses Android's VpnService **locally, on the device, to filter DNS and
> block known phishing/scam domains before they load**. It establishes a local
> loopback tunnel to inspect DNS lookups only. It is **not** an anonymity or
> proxy VPN: it does **not** route the user's traffic to any remote server, does
> **not** hide or change the user's IP address, and transmits no browsing data as
> a consequence of the tunnel. The blocklist is stored on the device and matched
> on-device. This is the core protection feature and is disclosed to the user via
> the standard Android VPN consent dialog before it starts.

Google Play specifics:
- In the app's **Advanced/VpnService declaration**, select the "core
  functionality (device security / parental control)" use, not "app that
  connects to a VPN gateway".
- Foreground-service type is `specialUse` (declared in the manifest); provide the
  same justification if Play asks about `FOREGROUND_SERVICE_SPECIAL_USE`.

**Camera** (paste if asked about `android.permission.CAMERA`):

> Cleanway uses the camera for one purpose: scanning a QR code so the link
> inside it can be checked before it is opened. The permission is requested at
> runtime only when the user opens the scanner. Frames are decoded on the device
> and discarded; no photo or video is captured, stored, or uploaded, and the app
> does not access the photo gallery. Audio recording is not used (the
> `RECORD_AUDIO` permission is removed from builds after versionCode 100).

**SMS — `RECEIVE_SMS`** (RuStore APK only; paste into RuStore's field for
sensitive permissions, it is written for the moderator in Russian):

> Разрешение RECEIVE_SMS нужно для одной функции — автоматической проверки
> входящих SMS на мошенничество («SMS-сообщения» на главном экране). Она
> выключена, пока пользователь сам её не включит: перед системным запросом
> приложение объясняет, что SMS проверяются прямо на телефоне, текст никуда не
> отправляется и не сохраняется. Каждое входящее SMS проверяется на устройстве
> по встроенным правилам (просьба назвать код, «безопасный счёт», звонок на
> неофициальный номер и т. п.) и по списку мошеннических сайтов, хранящемуся на
> телефоне. Если сообщение похоже на мошенническое, приложение показывает
> уведомление-предупреждение. Текст SMS не передаётся ни на наш сервер, ни
> третьим лицам, не записывается в память устройства и не попадает в журналы и
> отчёты об ошибках; для подозрительного SMS в истории на телефоне остаются
> только время, отправитель, причины и названия сайтов из ссылок. Мы не
> запрашиваем READ_SMS (не читаем папку «Входящие»), не отправляем SMS и не
> становимся приложением для SMS по умолчанию. Выключить проверку можно в любой
> момент — на главном экране или в «Настройки → SMS-сообщения».

---

## 5. Store assets & review notes

Everything RuStore asks for is in the repo — upload from these paths:

| Asset | Path | Spec |
|---|---|---|
| App icon | `mobile/assets/store/icon-512.png` | 512 × 512 PNG, opaque (downscaled from `mobile/assets/icon.png`; do not upload the 1024 source). |
| Phone screenshots (≥ 3 required) | `mobile/assets/store/screenshots/01.png` … `04.png` (+ optional `05.png`) | 1080 × 2400 PNG, RU locale, unedited frames of the **signed v1.0.0 APK** on an Android 15 emulator, captured 2026-09-13. `screenshots/README.md` says what each shows and why `05` (Settings) is optional. |

Screenshot set: (1) home with the shield ON, (2) a live phishing domain with the
red "Опасно" verdict and plain-Russian reasons, (3) history with domains marked
"Остановлен щитом", (4) the on-device score screen. Still missing and worth
adding when convenient: a blocked-site **notification** in Russian (the shade
capture did not work on the emulator).

**Sign-in is tested by moderators — fix SMTP before submitting.** RuStore
reviewers open every entry point, including "Войти". The app's only sign-in is an
email one-time code sent by Supabase, whose built-in mailer is capped at 2
emails/hour and is not meant for production. Connect a transactional SMTP
provider (e.g. Resend) in the Supabase Auth settings *before* upload, then verify
a code actually arrives on a fresh address. In the review notes also give the
reviewer a test address they can receive on (or state explicitly that login is
optional and every protection feature works without it — both are true).

- **Review note** (paste): "The VPN permission is used only for a local on-device
  DNS phishing filter — no remote VPN gateway, no IP masking, no traffic proxying.
  See the VpnService justification. The camera is used only to scan QR codes.
  RECEIVE_SMS is used only by the optional on-device scam-SMS check, which is off
  until the user turns it on (Home → «SMS-сообщения» → «Включить»); SMS text never
  leaves the device. To try it, send the test phone an SMS such as «Ваша карта
  заблокирована. Срочно позвоните 8 999 123-45-67 и назовите код из SMS» — a
  warning notification appears within seconds. Core protection is free; no login
  required to use it — sign-in (email code) is optional and only syncs settings /
  enables Family alerts."

---

## 6. Launch-blocker status (see docs/TELE2_LAUNCH_PLAN.md)

- ✅ B1 signing wiring · ✅ B2 versionCode · ✅ B4 blocklist no-429 · ✅ B5 honest
  listing + support page · ✅ `/android` funnel page · ✅ in-app update check
- ✅ Release keystore generated + backed up, signed v1.0.0 APK (versionCode 100)
  built and downloaded (§1–2) · ✅ store icon + screenshots in repo (§5) ·
  ✅ unused Android permissions blocked in `app.json` — lands with versionCode 101
- ⏳ **Founder:** RuStore account (VK ID), transactional SMTP for sign-in mail
  (§5), host the signed APK + set `NEXT_PUBLIC_APK_URL`, confirm the support
  mailbox, install-and-update test on a real phone (§2).
- ⏳ **Founder, SMS check (RuStore APK):** upload `app-rustore.apk` (never the
  direct one) with a bumped versionCode; paste the RECEIVE_SMS justification
  (§4) and the review note (§5). When the listing is live, set
  `STORES.rustore` to `{ available: true, url: "<listing URL>" }` in
  `mobile/src/config/stores.ts`: that turns on the "в версии Cleanway из
  RuStore" line in the website APK and the RuStore update banner in the RuStore
  build. Raise the server's `min_supported` version only once the RuStore
  release is live too. Still unverified on a real phone: whether a RuStore
  install on Android 15+ is under "restricted settings" (the app handles both).
