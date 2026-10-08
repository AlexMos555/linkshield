# Store Listing — Cleanway (Android)

> **Honesty contract.** Every claim in the store copy is grounded in what the
> code does. Verified egress: the app contacts `api.cleanway.ai` and
> `cleanway.ai`, plus Sentry for crash logs and Supabase for the optional
> account. Link checks send **only the site name (host)**, which the server may
> check with outside sources such as Google Safe Browsing. Message text is
> checked **on the phone** and never sent. The shield uses Android's VpnService
> **locally**: blocked names are answered on the phone; every other DNS lookup
> goes to the network's own resolver (operator / Wi-Fi), falling back to
> Cloudflare or Quad9 — so "no traffic leaves the phone" is **not** a claim we
> make. It is not an anonymity/proxy VPN, and on Android only one VPN runs at a
> time. No hardcoded recall/AUC; any measured number must name its set, its
> date and its caveat (see `docs/EVALUATION_2026-10.md`). Full detail:
> `docs/PRIVACY.md` → "The Android app".

---

## Where the copy lives

The paste-ready text moved out of this file so each store has exactly one
source (this file used to hold a v1.0.0 draft that had drifted from the build):

| Store | Language | Where |
|---|---|---|
| **RuStore** (primary, Tele2 launch) | RU | `docs/RUSTORE_SUBMISSION.md` §7 — name, short and full description, "Что нового" 1.0.4, keywords, screenshot captions, founder TODOs |
| **Google Play** (blocked: targetSdk 36 required) | EN + RU | `docs/STORES.md` §6 — title, short and full description, Data safety answers |
| Data-collection / permissions answers | — | `docs/RUSTORE_SUBMISSION.md` §3–4 |

The Russian full description is the same text in both stores on purpose; if you
edit one, edit the other.

---

## Metadata (both stores)

| Field | Value |
|---|---|
| Name | RU: `Cleanway: защита от мошенников` · EN: `Cleanway: Scam Protection` |
| Category | Tools / Security (RuStore: Инструменты / Безопасность) |
| Content rating | Everyone / 0+ |
| Privacy policy | https://cleanway.ai/privacy-policy |
| Support | https://cleanway.ai/support · support@cleanway.ai |
| Website | https://cleanway.ai |
| Account deletion (web) | https://cleanway.ai/account |
| Price | Free. No in-app purchases are wired in any store yet (see the TODOs in the two docs above before adding prices). |

### Assets (in repo)

| Asset | Path | Spec |
|---|---|---|
| Store icon | `mobile/assets/store/icon-512.png` | 512 × 512 PNG, opaque — downscaled from `mobile/assets/icon.png` (1024 × 1024, not for direct upload). |
| Phone screenshots | `mobile/assets/store/screenshots/01.png` … `05.png` | 1080 × 2400 PNG, RU locale, unedited frames of the signed **v1.0.0** APK. `screenshots/README.md` names each screen. Upload `01`–`04`; never `05` (it shows "Улучшить тариф" and "Отчёт за неделю"). For 1.0.4, recapture and add the message-check, call-warning and "Чтобы защита не выключалась" frames (`docs/RUSTORE_SUBMISSION.md` §7.6). |

---

## Removed claims (and why) — do not bring them back

From the original draft:
- ❌ "YOUR DATA STAYS ON YOUR DEVICE / even if breached your data is safe" —
  false: site names are sent to the server for checks.
- ❌ "93.5% recall / AUC 0.95" hardcoded — numbers move; only a dated, sized,
  caveated measurement may be quoted.
- ❌ "VPN Protection" as a feature name — reframed as an on-device DNS filter
  with an explicit "not an anonymity VPN" statement (RF-critical + honest).
- ❌ Breach Check headline, Privacy Audit, Weekly Report, Security Score, and
  the $4.99/$9.99 tiers — not verified working on mobile, and no store IAP.

From the v1.0.0 copy that was here until 2026-10-08:
- ❌ Short description "Проверка ссылок на устройстве" / "Link checking that
  runs on your device" — false: a checked link's host goes to
  `GET /api/v1/public/check/{host}` (`packages/api-client/src/index.ts:555`).
- ❌ "Никакой ваш трафик не уходит на наши или чужие серверы" / "None of your
  traffic is sent to our servers or anyone else's" — DNS lookups for sites that
  are not blocked go to the operator's / Wi-Fi resolver, then Cloudflare or
  Quad9 (`mobile/modules/cleanway-vpn/android/src/main/java/ai/cleanway/app/CleanwayVpnService.kt:5-6`, `:519-525`).
  Now: "not an anonymity VPN, IP does not change, pages/messages/calls do not
  pass through Cleanway, other lookups go to your network's DNS as usual".
- ❌ "работает даже без интернета" / "works even offline" — dropped: with no
  connection nothing loads anyway, so it promised nothing real.
- ❌ "routes no traffic to a remote server" (honesty note) — same reason as
  above; replaced by the accurate DNS description.
- ➕ Missing until now and added to the copy: message (SMS) check by sharing or
  pasting, the call warning and "Мне звонят", the keep-protection-on checklist,
  the account / devices screen, the one-VPN-at-a-time limit, and the "no app
  catches every scam" line.
- ⚠️ Not in the copy on purpose: **automatic** checking of incoming SMS. It
  exists only on `feat/sms-auto-rustore`, which is not merged into `main`; the
  main build has no SMS permission (`mobile/scripts/check-android-permissions.mjs:36`).
