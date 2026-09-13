# Store screenshots — Cleanway Android v1.0.0 (versionCode 100)

Phone screenshots for the RuStore listing (RuStore requires at least 3).
All five are **unedited `screencap` frames of the signed v1.0.0 release APK**
(`cleanway-1.0.0-100-arm.apk`, SHA-256 `3be3be39…9808`) running on the
`cleanway-test` Android 15 arm64 emulator in the `ru-RU` locale, captured
2026-09-13. Resolution 1080 × 2400 (9:20), PNG, opaque. No mock data: the
verdict and the history rows are real results from the production backend and
the on-device blocklist.

| File | Screen | What it shows |
|---|---|---|
| `01.png` | Щит (home), shield **ON** | "Вы под защитой", network shield enabled, blocklist of 431 493 known scam sites, link-guard enabled. |
| `02.png` | Результат (link check) | A live phishing domain (Roblox typosquat from the public OpenPhish feed) scored 55/100 → **Опасно**, with plain-Russian reasons and the "only the site name is sent" footer. |
| `03.png` | История | Recent checks: the dangerous verdict above plus rows marked **Остановлен щитом** — a malicious domain the DNS shield blocked in Chrome. |
| `04.png` | Оценка | On-device habit score with the honest "this is not how protected you are" caveat and "nothing is sent anywhere" footer. |
| `05.png` | Настройки | Account / explanation-style settings. **Optional** — it shows the "Улучшить тариф" and "Отчёт за неделю" rows, which the v1 listing copy deliberately omits (no store IAP wired). Upload only once paid delivery works on-store. |

Recommended upload order for RuStore: `01`, `02`, `03`, `04`.

## Regenerating

Install the release APK on a phone/emulator set to Russian, drive the screen
you need, then:

```bash
adb exec-out screencap -p > 0N.png
```

Keep the frames unedited (no device frames, no added text) so they stay a
faithful record of what the shipped build looks like.
