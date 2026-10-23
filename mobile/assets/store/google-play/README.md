# Google Play graphics — Cleanway Android

Paste order and the listing text: `docs/STORE_SUBMISSION_KIT.md` §1.2–1.3.
The first Play upload is **1.0.6 (versionCode 107)**,
`cleanway-1.0.6-107-play.aab` (`docs/RUSTORE_SUBMISSION.md` §2, build C). The
frames below are from the unpublished 1.0.4 (104) build: before uploading,
compare the five screens on the 1.0.6 Play build and recapture any that differ.
Sizes and "no alpha" are checked by `scripts/check_store_submission_kit.py`.

## Phone screenshots — `en/` (en-US) and `ru/` (ru-RU)

Unedited `screencap` frames of Cleanway 1.0.4 (104) on the Android 16 (API 36.1)
emulator, display set to 1080 × 1920 (9:16 — Play refuses a long side more than
twice the short one, so the 1080 × 2400 RuStore frames cannot be reused),
captured 2026-10-13. Only change after capture: the alpha channel was dropped
(Play wants 24-bit PNG); pixels are untouched. The status bar is Android's demo
mode (9:41, full battery); the shield icon next to the clock is Cleanway's own
"Protection is on" notification. Verdicts are live answers from the production
backend; the example scam site and message use no real brand.

| File | Screen | Shows |
|---|---|---|
| `01-home.png` | Shield (home), protection on | "You're protected", "I'm being called", the "Every app" shield with its honest limit |
| `02-message-scam.png` | Message check | A shared parcel-fee text → "Looks like a scam", with the reasons, incl. the server's verdict on its link |
| `03-link-dangerous.png` | Link check | `account-verify-login-secure.netlify.app` → Dangerous 65/100 and why |
| `04-call-guard.png` | "I'm being called" | What to do when "the bank" calls; "Cleanway does not identify numbers, block calls or listen" |
| `05-history.png` | History | The checks above in the history list |

Not shown on purpose: Settings (the site/RuStore build has an "Upgrade" row
that the Play paywall replaces) and anything with a price.

## Feature graphic — `en/feature-graphic.png`, `ru/feature-graphic.png`

1024 × 500, opaque, the app icon + wordmark + one line from the listing, in the
app colours (`mobile/src/utils/theme.ts`). Made by `store-assets/render-graphics.mjs`.

## Recapture

Install the Play build's check APK (`cleanway-<version>-<code>-play-check.apk`,
built next to the AAB in `docs/RUSTORE_SUBMISSION.md` §2 C) on an emulator, then:

```bash
adb -s emulator-5554 shell wm size 1080x1920
adb -s emulator-5554 shell cmd locale set-app-locales ai.cleanway.app --locales ru-RU   # "" for English
adb -s emulator-5554 shell settings put global sysui_demo_allowed 1
adb -s emulator-5554 shell am broadcast -a com.android.systemui.demo -e command clock -e hhmm 0941
# message check:  am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT '<text>' -n ai.cleanway.app/.MainActivity
# link check:     am start -a android.intent.action.VIEW -d 'cleanway://result?domain=<host>' ai.cleanway.app
# call guard:     am start -a android.intent.action.VIEW -d 'cleanway://call-guard' ai.cleanway.app
adb -s emulator-5554 exec-out screencap -p > 0N-name.png
```

Then drop the alpha channel without touching pixels (any tool that writes RGB
PNG) and run `python3 scripts/check_store_submission_kit.py`.
