All findings ground out. Writing the plan.

---

# Cleanway → Tele2 Launch Plan

*Android-only, RU-first, direct-APK + RuStore. Grounded in the 5 audits and live-prod/file verification (2026-08-25); status refreshed 2026-09-13.*

## 1. Verdict

**Yes, we can launch to a small first cohort — but not this week, and not with the current APK.** The engine is genuinely ready: prod blocklist is live (2.6 MB, verified 200), the on-device shield blocks listed phishing and lets `sberbank.ru`/`gosuslugi.ru` resolve on a real A16, the link guard (the exact SMS-phishing defense Tele2 subscribers are sold) is shipped and enableable, RU is 100% translated, and the RF-critical honest VPN disclosure ("это не VPN для анонимности") already exists. The single thing standing between "now" and "a Tele2 subscriber installs and is protected" is **a real release keystore + a hosted, versioned APK download page** — everything else is either already working or a fast follow. **Update 2026-08-31: signing and versioning are now solved** — a real keystore exists and the shipped APK verifies as `CN=Cleanway`, 55 MB, versionCode 100. **Update 2026-09-13: hosting and prod deploy are solved too** — PR #39 merged 2026-09-01 (`e240442`, 11 checks passed + 3 skipped by path filter) and release `v1.0.0` is on GitHub (asset `cleanway-1.0.0-100-arm.apk`), so `/android`, `/support` and `/api/v1/mobile/version` are live. What remains before traffic: **(1)** `NEXT_PUBLIC_APK_URL` in Vercel + a redeploy without build cache — until then `/ru/android` says «скоро» and there is nowhere to send people; **(2)** real SMTP for Supabase — still the built-in sender at **2 messages/hour**, Resend not wired (the OTP-length mismatch, 8 sent vs 6 accepted, was fixed 2026-09-13); **(3)** MX for `cleanway.ai` — `support@`/`privacy@`/`legal@`/`business@` all bounce; **(4)** the release APK has never gone through the browser install path on a real phone. See docs/GO_LIVE_CHECKLIST.md for the live status.

---

## 2. Launch-blockers (must-fix before ANY Tele2 traffic)

Ordered by how much each unblocks.

| # | Blocker | Owner | Concrete step |
|---|---------|-------|---------------|
| **B1** | ✅ **CLEARED 2026-08-31.** Keystore generated (RSA 4096, valid to 2054) and the first release APK built and verified — `apksigner`: *Verifies*, v2 scheme, `CN=Cleanway`, 55 MB, versionCode 100. *(Original problem: the APK was signed with the world-known Android debug key, so no store would take it and it had no stable update identity.)* | **Claude ✅ built it — Founder must BACK IT UP** | `mobile/plugins/withReleaseSigning.js` re-wires the `release` signingConfig on every `expo prebuild` (managed workflow regenerates `android/`), reading `keystore.properties`, and falls back to debug signing when absent — it can only upgrade a build, never break it. 8 transform assertions. ⏳ **Founder:** keep `cleanway-release.jks` + `keystore.properties` alive in the backup (password manager + one offline copy); the working copy is the build sandbox's `android/` folder. **Regenerating is no longer free** (2026-09-13): the signed APK has been downloaded, so a new key means pulling the release and reinstalls. Never `expo prebuild --clean` in the sandbox — without `keystore.properties` the plugin falls back to debug signing and the build still succeeds. |
| **B2** | **versionCode hardcoded to 1.** Even after B1, the next build won't install over the first — "App not installed". | **Claude ✅ DONE** | ✅ Set `app.json` to `version "1.0.0"` / `versionCode 100` (first public build, headroom) — Expo prebuild writes it into `build.gradle`. This also **matches the update-check server default** (`mobile_latest_version_*` = 100 / "1.0.0"), so a fresh install does NOT see a spurious "update available" (a mismatch the 2026-08-25 audit caught while it was 0.1.0/1). Founder bumps `versionCode` + `expo.version` per release, in step with the Railway env. |
| **B3** | ⚙️ **One env var from cleared.** ✅ Claude: `/android` RU download page shipped and `install-urls.ts` android flipped to it (was `available:false → /dns`, a dead end); live in prod since the 2026-09-01 merge. ✅ Hosted 2026-09-01: GitHub Release `v1.0.0`, asset `cleanway-1.0.0-100-arm.apk` (55 MB, down from 92). ⏳ **Founder:** `NEXT_PUBLIC_APK_URL` is still unset in Vercel, so the download button shows «скоро» rather than a link. | **Founder (Vercel env)** | Set `NEXT_PUBLIC_APK_URL=https://github.com/AlexMos555/linkshield/releases/download/v1.0.0/cleanway-1.0.0-100-arm.apk` in Vercel, then **redeploy WITHOUT build cache** (`NEXT_PUBLIC_*` is inlined at build time and the page is statically prerendered per locale — a cached rebuild keeps «скоро»). No code change needed. |
| **B4** | **Blocklist has no CDN** — single Railway `ams1` origin serves every 2.6 MB first-sync (verified: `server: railway-hikari`, no `cf-ray`; response already `public, max-age=1800` + strong ETag). A synchronized SMS blast saturates one instance; compounds with the 3000/h per-IP cap that a Tele2 CGNAT gateway (thousands of phones on one IPv4) can exhaust → fresh phones sit with an empty list, unprotected up to ~1h. | **Founder (CF account/DNS) + Claude (cache rule)** | Put Cloudflare in front of `/api/v1/blocklist/dns`. **2026-09-13: still no Cloudflare, and the hostname matters** — the v1.0.0 APK hard-codes `https://api.cleanway.ai/api/v1/blocklist/dns` (`CleanwayVpnService.kt`) and does not follow redirects, so a `dl.`/`blocklist.` subdomain only helps phones on APK 1.0.1+; to cover v1.0.0 installs, front `api.cleanway.ai` itself. The existing headers make it edge-cacheable — absorbs ~99% of first-syncs. ✅ **Claude interim shipped (prod):** the blocklist GET has no blanket per-IP limit any more — only full 2.6 MB sends are metered, at a ceiling far above real traffic, and 304s/deltas are never counted — so a CGNAT gateway can't be 429'd into an empty list before the CDN lands. |
| **B5** | **Store-listing over-claims + dead support URL.** Old `mobile/STORE_LISTING.md` reintroduced retired false claims + declared support URL 404'd. | **Claude ✅ DONE + Founder (mailbox)** | ✅ Rewrote `mobile/STORE_LISTING.md` — honest, RU-authoritative: leads "защита от фишинга / DNS-фильтр on-device", domain-not-full-URL, explicit "не VPN для анонимности", numbers point to `/transparency/methodology` (no hardcoded recall/AUC), dropped the false data-residency line, breach/audit/weekly/score/paid tiers omitted until verified on-store. ✅ Support page shipped (commit 942454c). ✅ `docs/RUSTORE_SUBMISSION.md` runbook: keystore.properties setup, arm64 build recipe, Data-Safety answers (grounded in verified egress), VpnService justification text, review notes. ⏳ **Founder:** `support@cleanway.ai` still bounces on 2026-09-13 (no MX; records go in Squarespace Domains); register RuStore account. |

---

## 3. The critical path — today → "Tele2 sends the first SMS"

Interleaved. **[C]** = Claude builds, **[F]** = founder-only, **[both]**.

1. ✅ **DONE** — keystore generated and the signed APK built. **[F] Remaining: keep the key's backup alive** (password manager + one offline copy; the build sandbox's `android/` folder holds the working copy). Regenerating is no longer free — see B1.
2. ✅ **[C]** DONE — `release` signingConfig + explicit `versionCode` wired via config plugin + `app.json` (B1, B2). *(arm64-first ABI flag still pending, §4.)*
3. ✅ **[C]** DONE — signed release APK built from the sandbox: **55 MB**, `armeabi-v7a + arm64-v8a`, `CN=Cleanway`, versionCode 100. ⏳ **[F+C] still unproven (2026-09-13):** the A16 has only ever run a **debug** build over `adb` (2026-08-25). The release APK via the browser install path, Play Protect + Samsung Auto Blocker, and an update over the top (bump versionCode, reinstall) are untested.
4. ✅ **DONE 2026-09-01** — GitHub Release `v1.0.0`, asset `cleanway-1.0.0-100-arm.apk`.
5. ✅ **[C]** DONE — `/android` RU download page + Samsung "unknown sources" walkthrough, `install-urls.ts` flipped; live in prod. ⏳ **[F]** set `NEXT_PUBLIC_APK_URL` in Vercel + redeploy without build cache (B3) — the page says «скоро» until then.
6. ✅ **[C]** `landing/app/[locale]/support` route DONE, live in prod; ⏳ **[F]** mailbox — MX still empty on 2026-09-13 (B5).
7. **[F]** Create the Cloudflare account and front `api.cleanway.ai` at CF (B4 — a new `blocklist.` hostname needs APK 1.0.1, the shipped app hard-codes the api host). **[C]** add the cache rule. *(Dropped: "add CF egress CIDRs to `trusted_proxy_cidrs`" — unnecessary, `api/services/rate_limiter.py` already honours the LEFTMOST `X-Forwarded-For` once the peer is trusted, and Railway's edge stays the peer.)* ✅ **[C]** interim "no-429 on blocklist GET" patch shipped to prod.
8. ✅ **[C]** DONE — `GET /api/v1/mobile/version` + in-app update check, notification-locale bridge fix, link-guard home card (§4); all live since the merge.
9. **[both]** **Smoke test the full funnel end-to-end on the real A16 over mobile data** (still open — see step 3): tap a test SMS link → land on `/ru/android` → download `cleanway-1.0.0-100-arm.apk` → get past Samsung **Auto Blocker** (One UI 6+ blocks sideloads until switched off in Settings → Security and privacy), the unknown-sources gate and Play Protect → install → enable shield → enable link guard → confirm a listed phishing domain blocks and `gosuslugi.ru` resolves → request a login code and type the 6 digits → bump versionCode, install over the top.
10. **[F]** (Parallel track, for store channels) Register RuStore developer account (физлицо OK for a free app, ЕСИА-verified); **[C]** draft `docs/RUSTORE_SUBMISSION.md` + RU listing + data-collection declaration. Google Play secondary.
11. **[F]** External uptime+latency monitor (UptimeRobot/Better Stack), phone/push alert, for launch week (§6). Probe **`GET /health/deep`** — not HEAD (returns 405) and not `/health` (always 200, proves nothing) — plus a GET on `/api/v1/blocklist/dns`. The `dns-canary` GitHub workflow already runs every 2–6 h; its failures so far were noise (being de-noised separately), so treat it as a second opinion, not the pager.
12. **[F]** Coordinate with Tele2: agree the SMS copy (draft + rules in **§8** — phishing protection, never "VPN"), the cohort size (≤ 1–2k), and the send window. **Send the first SMS to a SMALL cohort** (see §7 cut-line).

**Direct-APK funnel is live after step 9.** Steps 10–11 gate the store channels and launch-night safety; step 12 is the go.

---

## 4. What Claude builds now (this session / next)

Ready task list, file-specific. All are Claude-ownable and launch-relevant.

- ✅ **Gradle signing + versioning** — DONE via `mobile/plugins/withReleaseSigning.js` (managed-workflow config plugin, reads git-ignored `android/keystore.properties`, debug fallback, idempotent + fail-safe) and `app.json` `versionCode`. *(Needs founder's keystore + keystore.properties to produce a store-signed build; the wiring is in place and can't break the current sideload build.)*
- ✅ **Per-ABI build** — DONE, but NOT the way this plan assumed. Measured 2026-08-31: `-PreactNativeArchitectures` does **not** slim an APK (it only feeds `splits.abi.include`, and splits are disabled by default — the first signed build was 92 MB with all four ABIs). Shipped `mobile/plugins/withAbiFilters.js` instead, which injects `ndk { abiFilters }`: it drops the emulator-only `x86`/`x86_64` and keeps **both** ARM ABIs, so no real phone is excluded. Result: **55 MB**. Store AABs still carry every ABI.
- **Android download page** — new `landing/app/[locale]/android/page.tsx` (RU-first): three paths (direct APK, RuStore, Play), illustrated Samsung "Разрешить установку / Всё равно установить" walkthrough. Flip `landing/lib/install-urls.ts` android `available:true` + CDN href.
- **Support page** — new `landing/app/[locale]/support/page.tsx` (RU): `support@cleanway.ai` + basic FAQ. Kills the 404 store field.
- ✅ **In-app update check** — DONE. `GET /api/v1/mobile/version` (new `api/routers/mobile.py`, env-driven, CGNAT-safe no per-IP limit) returns version name+code, security floor, apk_url, notes. Mobile `useUpdateCheck` compares the build's embedded version *name* (expo Constants, no new native dep, offline-safe) → `UpdateBanner` on home: dismissible nudge when newer exists, non-dismissible card (never a hard lock) below the floor. Network failure shows nothing; the last snapshot is persisted so a "must update" verdict survives offline. Pure decision logic unit-verified (13 assertions). Download falls back to the localized `/android` page when no signed APK url is set.
- **Notification locale fix** — `CleanwayVpnModule.kt` add `Function("setUiLocale")` → `LocalizedContext.set`; expose from `modules/cleanway-vpn/index.ts`; call from `i18n changeLocale()` + boot `restoreSavedLocale()`. Without it, block notifications ignore the in-app Russian pick (`cleanway_ui/locale` is never written — verified in audit).
- ✅ **Link-guard home card** — DONE. `app/(tabs)/index.tsx` now shows a link-checking ShieldCard driven by `useLinkGuard` (live `isDefaultLinkHandler()`, enable CTA → `requestLinkHandler()`, re-checks on focus). Dropped the Android `browser` "На подходе" rollout item — the shipped feature no longer advertises itself as coming soon.
- ✅ **Blocklist no-429 interim** — DONE, in prod: `api/routers/blocklist.py` GET has no blanket per-IP limit; only full sends are metered (high ceiling, 304/deltas never counted). *The "add CF CIDRs to `trusted_proxy_cidrs`" half was dropped — not needed, the limiter already takes the leftmost `X-Forwarded-For` behind a trusted peer.*
- **CF cache rule spec** + **store listing RU drafts** (`STORE_LISTING.md` rewrite, honest; RuStore + Play variants) + **`docs/RUSTORE_SUBMISSION.md`** + **mobile Data-Safety / RuStore data-collection answers** grounded in `PRIVACY.md` + the mobile egress map + **Play VpnService declaration text + ≤90s demo shot-script**.
- ✅ **Link-guard no-browser fallback** — DONE. `LinkGuardActivity.forwardToBrowser()` now always forwards with an EXPLICIT browser package; when Cleanway is the only http/https handler it routes to the in-app verdict screen (`cleanway://`, which this activity doesn't handle → cannot loop) instead of firing an unpackaged `ACTION_VIEW` that resolved straight back to itself. Launch-failure also falls back to the app screen rather than dropping the link.

---

## 5. What only the founder can do (and why)

- ~~Generate the release keystore~~ — **done 2026-08-31** (RSA 4096, valid to 2054; the first signed APK verifies as `CN=Cleanway`). The key lives in the founder's backup (password manager + offline copy) and in the build sandbox's `android/` folder. The founder's job is to **keep that backup alive** — regenerating stopped being free on 2026-09-01, when the signed APK was first downloaded (new key ⇒ pull the release, every install reinstalls).
- **Register the RuStore developer account** (ЕСИА/Gosuslugi-verified; физлицо OK for a free app) and Google Play account — requires RF identity verification Claude can't perform.
- ~~Pick + create the APK host~~ — **done 2026-09-01** (GitHub Release `v1.0.0`). Still founder-only: **`NEXT_PUBLIC_APK_URL` in Vercel + redeploy without build cache**, and the CDN account/DNS (the zone is edited in Squarespace Domains).
- ~~Set `EXPO_PUBLIC_SUPABASE_ANON_KEY`~~ — **done 2026-08-31** (wired and verified live). Sign-in still fails for a different reason — Supabase's 2 emails/hour built-in SMTP, see GO_LIVE_CHECKLIST blocker #1 — which is also founder-only (Resend key + apex-domain DNS).
- **Stand up the external uptime/latency monitor** with a phone/push channel for launch week — probe `GET /health/deep`, see §3 step 11.
- **Tele2 coordination** — SMS copy sign-off (draft + rules in §8; phishing framing, never "VPN"), cohort size, send window.
- **Record + upload the Play VpnService demo video** and fill the Play Console declaration form.
- **Set `NEXT_PUBLIC_APK_URL` in Vercel and redeploy without build cache** (the landing code itself already deploys from `main`); confirm the `support@` mailbox (MX still empty on 2026-09-13).

---

## 6. RF-specific risks (plain) + de-risking

- **The "VPN" framing under RF VPN restrictions.** Roskomnadzor targets tools that *unblock/hide* traffic. Cleanway does the opposite — it's a **local DNS filter that adds blocking**, never a tunnel to a remote server. **De-risk:** in all RU copy lead with "защита от фишинга / DNS-фильтр", reuse the existing honest disclosure ("это не VPN для анонимности, он не скрывает, куда вы заходите"), keep "VPN" out of the app title. If a RuStore reviewer raises the category, respond with the local-filter + public-resolver-forwarding evidence. This is presentational risk only, not a fatal blocker.
- **RuStore review (primary channel, currently zero prep — verified: 0 repo mentions).** **De-risk:** draft the full RU runbook + honest listing + data-collection declaration now so the founder submits a clean, consistent package; prefer the store install path for grandma (skips the unknown-sources gate entirely).
- **CGNAT rate-limits.** Thousands of Tele2 phones share one IPv4 → the 3000/h blocklist cap and 5-fresh/min `/public/check` cap are hit collectively. **De-risk:** CDN dissolves the blocklist cap (B4); the `/public/check` cap only throttles the *best-effort novel-warn bonus* — the forward-then-check design already makes a 429 harmless (link forwarded first, local 432k list still blocks known-bad in µs, 429 silently ignored — verified in `LinkGuardActivity.kt` / `checkUrlAsync`). Do **not** raise the 5/min cap blindly (it bounds the paid analyzer fan-out).
- **Play Protect + Auto Blocker friction on Samsung.** A sideloaded VPN app triggers unknown-sources gates + Play Protect warnings that read as "dangerous" to grandma — and on One UI 6+ Samsung **Auto Blocker** is on by default and refuses the install outright until the user switches it off (Settings → Security and privacy → Auto Blocker); none of this has been exercised with the release APK on the A16 yet. **Partly de-risked:** the APK is now release-signed (reputation can start accruing) and down to 55 MB, and `/android` carries the illustrated RU walkthrough. Remaining: reputation takes installs+time, so steer non-technical users to **RuStore** (a store install skips the unknown-sources gate entirely). Note Google Play is not an option today — it now requires targetSdk 36 and we ship 34. Never tell users to disable Play Protect.

---

## 7. Honest cut-line

**Minimum to launch safely to a FIRST small Tele2 cohort (direct-APK funnel):**
- ✅ B1 real keystore + B2 versionCode + slim ABI build — DONE (55 MB, release-signed, versionCode 100). Still unproven on a real device: *the release APK installs via the browser path, and updates over itself* (only a debug build over `adb` so far).
- ⚙️ B3 APK hosted (✅ GitHub Release `v1.0.0`) + `/android` RU download page live (✅) — ⏳ `NEXT_PUBLIC_APK_URL` in Vercel + redeploy without build cache still missing, so the button says «скоро»
- ✅ B4 blocklist can't 429 (interim patch is in prod; full CF can follow — fronting `api.cleanway.ai`, since v1.0.0 hard-codes that host)
- ✅ B5 support page live (kills the 404) + honest RU direct-download copy (full store listings can follow); ⏳ the mailbox behind it still bounces (no MX)
- End-to-end smoke test passed on a real device over mobile data, including Samsung Auto Blocker / Play Protect and an over-the-top update
- Basic uptime/latency monitor on `GET /health/deep` (HEAD → 405; `/health` is always 200) + blocklist path

That gets a Tele2 subscriber to install and be genuinely protected. **Keep the first cohort small** (a few hundred to low thousands, well under the 3000/h-per-CGNAT-IP edge) precisely so the un-CDN'd origin and the store-less funnel are proven under real load before scaling.

**Can follow (not launch-blocking):**
- Full Cloudflare in front of the blocklist (do it before any large blast; front `api.cleanway.ai` itself — a new hostname needs APK 1.0.1, the shipped app hard-codes the URL and does not follow redirects)
- RuStore + Google Play listings (better grandma path, but direct-APK works day one)
- ~~In-app update check, notification-locale fix, link-guard home card~~ — all shipped in v1.0.0
- Supabase anon key (✅ wired 2026-08-31) / Family Hub (optional — shield needs no account; accounts stay dead until real SMTP, see GO_LIVE_CHECKLIST blocker #1)
- iOS (no Org Apple account; explicitly out of scope for this launch)

~~**The founder's very first move is `keytool` (step 1).**~~ Done. **The founder's very first move is now `NEXT_PUBLIC_APK_URL` in Vercel + a redeploy without build cache** — until then `/ru/android` says «скоро» and there is nothing to put in an SMS. The keystore is the one artifact that must never be lost; keep its backup alive (B1).

---

## 8. Текст SMS

**Черновик** (65 символов — кириллица, значит UCS-2, лимит одного сегмента 70; влезает в один):

> Защита от фишинга для Android — бесплатно. cleanway.ai/ru/android

**Правила:**

- **Слово «VPN» — никогда.** Ни в SMS, ни в названии приложения, ни в описании ссылки. Позиционирование — «защита от фишинга» (см. §6: продукт — локальный DNS-фильтр, а не туннель).
- **Первая когорта — не больше 1–2 тыс. абонентов.** Origin без CDN и воронка без стора должны выдержать реальную нагрузку до масштабирования; CGNAT Tele2 = тысячи телефонов за одним IPv4 (§7).
- **Гейт на отправку: рассылка не уходит, пока `/ru/android` не показывает кнопку скачивания.** Сейчас там «скоро» — до тех пор, пока в Vercel не задан `NEXT_PUBLIC_APK_URL` и сайт не пересобран без build cache. Проверять с телефона в сети Tele2, а не с ноутбука.
- **Время отправки согласовать с Tele2** заранее — рабочий день, дневное окно, чтобы в момент всплеска установок founder был у монитора (§3 шаг 11).
- Ссылка без `https://` и без сторонних сокращателей: короче, Android открывает как есть, и антифишинговый продукт не должен вести через чужой редирект.
- После любой правки текста пересчитать длину: 70 символов на UCS-2-сегмент, тире «—» тоже считается; второй сегмент — двойная цена и обрезка у части операторов.