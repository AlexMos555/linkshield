All findings ground out. Writing the plan.

---

# Cleanway → Tele2 Launch Plan

*Android-only, RU-first, direct-APK + RuStore. Grounded in the 5 audits and live-prod/file verification (2026-08-25).*

## 1. Verdict

**Yes, we can launch to a small first cohort — but not this week, and not with the current APK.** The engine is genuinely ready: prod blocklist is live (2.6 MB, verified 200), the on-device shield blocks listed phishing and lets `sberbank.ru`/`gosuslugi.ru` resolve on a real A16, the link guard (the exact SMS-phishing defense Tele2 subscribers are sold) is shipped and enableable, RU is 100% translated, and the RF-critical honest VPN disclosure ("это не VPN для анонимности") already exists. The single thing standing between "now" and "a Tele2 subscriber installs and is protected" is **a real release keystore + a hosted, versioned APK download page** — everything else is either already working or a fast follow. The APK today is signed with the world-known Android debug key (`build.gradle:112 signingConfig signingConfigs.debug`, verified) and hardcoded to `versionCode 1`, so it cannot go to any store, has no trustworthy identity, and cannot even be updated over itself. Fix signing + hosting + the download page and a Tele2 subscriber can install and be protected; the rest sharpens conversion and survives the spike.

---

## 2. Launch-blockers (must-fix before ANY Tele2 traffic)

Ordered by how much each unblocks.

| # | Blocker | Owner | Concrete step |
|---|---------|-------|---------------|
| **B1** | **No release keystore** — APK signed with debug key (`build.gradle:97-112`, only `debug.keystore` on disk, verified). Blocks both stores AND stable update identity. This key is permanent — losing it = users must uninstall/reinstall forever. | **Founder (generate/hold) + Claude (wire gradle)** | Founder runs `keytool -genkeypair -v -keystore cleanway-release.jks -alias cleanway -keyalg RSA -keysize 4096 -validity 10000 -storetype PKCS12`, stores it in a password manager + one offline backup, records store/key passwords. Claude adds a `release` signingConfig reading from env/`~/.gradle/gradle.properties` (never git) and flips `build.gradle:112` to `signingConfigs.release`. Persist via checked-in `android/` (sandbox already has it) so `expo prebuild` can't revert it. |
| **B2** | **versionCode hardcoded to 1** (`build.gradle:94`, verified). Even after B1, the next build won't install over the first — "App not installed". | **Claude** | Drive `versionCode` from `-PversionCode=N` env in the build script; ship the first public APK at `versionCode 100`, `versionName "1.0.0"` for headroom. Increment every build. |
| **B3** | **No hosting path for the APK** — landing is Vercel, no APK route, `install-urls.ts` android is `available:false → /dns` (verified). The Tele2 web funnel currently dead-ends at the DoH-profile page. Serving 107 MB off Vercel blows the egress budget on a single SMS blast. | **Founder (pick host) + Claude (build page)** | Host on **GitHub Releases** (free, unmetered, Fastly-backed, stable versioned URL — already referenced in `docs/STORES.md:124`) or Cloudflare R2 (`get.cleanway.ai`, zero egress). Claude builds the `/android` (RU) download route + flips `install-urls.ts` android → `available:true` pointing at the CDN URL. Founder creates the release/bucket. |
| **B4** | **Blocklist has no CDN** — single Railway `ams1` origin serves every 2.6 MB first-sync (verified: `server: railway-hikari`, no `cf-ray`; response already `public, max-age=1800` + strong ETag). A synchronized SMS blast saturates one instance; compounds with the 3000/h per-IP cap that a Tele2 CGNAT gateway (thousands of phones on one IPv4) can exhaust → fresh phones sit with an empty list, unprotected up to ~1h. | **Founder (CF account/DNS) + Claude (cache rule + trusted-proxy CIDRs)** | Put Cloudflare in front of `/api/v1/blocklist/dns` (a `dl.`/`blocklist.` subdomain is enough). The existing headers make it edge-cacheable — absorbs ~99% of first-syncs and dissolves the CGNAT 429 for the static artifact. **Claude interim (no account needed):** drop the per-IP rate-limit dependency from the blocklist GET (it's a signed, ETag'd public static file — nothing to protect per-IP) so it can't 429 even before the CDN lands. |
| **B5** | **Store-listing over-claims + dead support URL.** `mobile/STORE_LISTING.md` is English-only and reintroduces retired false claims ("YOUR DATA STAYS ON YOUR DEVICE", "even if breached your data is safe", "93.5% recall / AUC 0.95", a disabled "Breach Check"). Declared support URL `cleanway.ai/support` → **404 (verified, both /support and /ru/support)**. Violates the honesty ethic and is a rejection trigger. | **Claude (rewrite + support page) + Founder (mailbox)** | Claude rewrites listing in honest RU (lead "защита от фишинга / DNS-фильтр", domain-not-full-URL, drop hardcoded recall/AUC or cite live `latest.json`, remove breach-check) and builds `landing/app/[locale]/support` route. Founder confirms `support@cleanway.ai` receives mail. *(Blocker for store channels; the direct-APK funnel can go live once B1–B4 are done.)* |

---

## 3. The critical path — today → "Tele2 sends the first SMS"

Interleaved. **[C]** = Claude builds, **[F]** = founder-only, **[both]**.

1. **[F]** Generate `cleanway-release.jks` with `keytool` (B1). Back it up in two places. *(Nothing signs correctly until this exists.)*
2. **[C]** Wire the `release` signingConfig + env-driven `versionCode`/`versionName` into `build.gradle`; add arm64-first ABI build flag (B1, B2, §4). *(Can start in parallel with step 1; needs the keystore to actually build.)*
3. **[C]** Build the arm64-only release APK (~42 MB) from the sandbox once the keystore is in place. Verify it installs on the A16 and updates over itself (bump versionCode, reinstall).
4. **[F]** Pick + create the APK host (GitHub Release recommended). Upload the signed APK; get the stable URL.
5. **[C]** Build `/android` RU download page + Samsung "unknown sources" illustrated walkthrough; flip `install-urls.ts` android → `available:true` → CDN URL (B3).
6. **[C]** Build `landing/app/[locale]/support` route; **[F]** confirm mailbox live (B5).
7. **[F]** Create the Cloudflare account, point a `blocklist.cleanway.ai` (or api) subdomain at CF (B4). **[C]** add the cache rule + CF egress CIDRs to `trusted_proxy_cidrs`; **[C]** ship the interim "no-429 on blocklist GET" patch immediately regardless.
8. **[C]** Add `GET /api/v1/mobile/version` + in-app update check (§4). **[C]** notification-locale native bridge fix + link-guard home card (§4).
9. **[both]** **Smoke test the full funnel end-to-end on the real A16 over mobile data:** tap a test SMS link → land on `/android` → download → install past Samsung/Play-Protect prompts → enable shield → enable link guard → confirm a listed phishing domain blocks and `gosuslugi.ru` resolves.
10. **[F]** (Parallel track, for store channels) Register RuStore developer account (физлицо OK for a free app, ЕСИА-verified); **[C]** draft `docs/RUSTORE_SUBMISSION.md` + RU listing + data-collection declaration. Google Play secondary.
11. **[F]** External uptime+latency monitor (UptimeRobot/Better Stack) on `/health` + a HEAD on the blocklist path, phone/push alert, for launch week (§6).
12. **[F]** Coordinate with Tele2: agree the SMS copy (frame as phishing protection, not "VPN"), the cohort size, and the send window. **Send the first SMS to a SMALL cohort** (see §7 cut-line).

**Direct-APK funnel is live after step 9.** Steps 10–11 gate the store channels and launch-night safety; step 12 is the go.

---

## 4. What Claude builds now (this session / next)

Ready task list, file-specific. All are Claude-ownable and launch-relevant.

- **Gradle signing + versioning** — `android/app/build.gradle`: add `release` signingConfig (env/`gradle.properties`-sourced), flip line 112 to `signingConfigs.release`, drive `versionCode`/`versionName` from `-P` props. *(needs founder's keystore to build, but the wiring lands now.)*
- **Per-ABI / arm64 build** — `android/gradle.properties:31` + build script: ship arm64-only for the SMS funnel (~42 MB vs 107 MB, ~60% cut, zero real-device loss in RF). Optionally enable R8 + resource shrinking.
- **Android download page** — new `landing/app/[locale]/android/page.tsx` (RU-first): three paths (direct APK, RuStore, Play), illustrated Samsung "Разрешить установку / Всё равно установить" walkthrough. Flip `landing/lib/install-urls.ts` android `available:true` + CDN href.
- **Support page** — new `landing/app/[locale]/support/page.tsx` (RU): `support@cleanway.ai` + basic FAQ. Kills the 404 store field.
- **In-app update check** — `GET /api/v1/mobile/version` in a new FastAPI router returning `{latest_version_code, min_supported_version_code, apk_url, release_notes}`; on-launch/daily compare in mobile app → non-blocking "Обновление доступно" prompt (blocking below min_supported). Honest manual-reinstall flow (works only post-B1/B2).
- **Notification locale fix** — `CleanwayVpnModule.kt` add `Function("setUiLocale")` → `LocalizedContext.set`; expose from `modules/cleanway-vpn/index.ts`; call from `i18n changeLocale()` + boot `restoreSavedLocale()`. Without it, block notifications ignore the in-app Russian pick (`cleanway_ui/locale` is never written — verified in audit).
- **Link-guard home card** — `app/(tabs)/index.tsx`: add a Shield-Checklist card reading `isDefaultLinkHandler()` → enable CTA (`requestLinkHandler()`); **remove the `browser`/`mobile.rollout.browser_android` "На подходе" item** so a shipped feature stops advertising itself as "coming soon".
- **Blocklist no-429 interim** — drop the per-IP rate-limit dependency from `api/routers/blocklist.py` GET (signed public static file); add CF CIDRs to `trusted_proxy_cidrs`.
- **CF cache rule spec** + **store listing RU drafts** (`STORE_LISTING.md` rewrite, honest; RuStore + Play variants) + **`docs/RUSTORE_SUBMISSION.md`** + **mobile Data-Safety / RuStore data-collection answers** grounded in `PRIVACY.md` + the mobile egress map + **Play VpnService declaration text + ≤90s demo shot-script**.
- **Link-guard no-browser fallback** — `LinkGuardActivity.forwardToBrowser()`: when no non-self browser exists, route to in-app verdict screen instead of an unpackaged `ACTION_VIEW` that can loop/throw.

---

## 5. What only the founder can do (and why)

- **Generate + permanently hold the release keystore** — it's identity/secret material; Claude must not create or hold it. Losing it = never updating the app.
- **Register the RuStore developer account** (ЕСИА/Gosuslugi-verified; физлицо OK for a free app) and Google Play account — requires RF identity verification Claude can't perform.
- **Pick + create the APK host** (GitHub Release or R2 bucket) and the CDN account/DNS — account creation + DNS control.
- **Set `EXPO_PUBLIC_SUPABASE_ANON_KEY`** in `eas.json` if sign-in/Family is wanted (optional for launch — shield works without it; else Claude hides the Family/Sign-in rows).
- **Stand up the external uptime/latency monitor** with a phone/push channel for launch week.
- **Tele2 coordination** — SMS copy sign-off (phishing framing, never "VPN"), cohort size, send window.
- **Record + upload the Play VpnService demo video** and fill the Play Console declaration form.
- **Deploy the landing changes** (Vercel) and confirm the `support@` mailbox.

---

## 6. RF-specific risks (plain) + de-risking

- **The "VPN" framing under RF VPN restrictions.** Roskomnadzor targets tools that *unblock/hide* traffic. Cleanway does the opposite — it's a **local DNS filter that adds blocking**, never a tunnel to a remote server. **De-risk:** in all RU copy lead with "защита от фишинга / DNS-фильтр", reuse the existing honest disclosure ("это не VPN для анонимности, он не скрывает, куда вы заходите"), keep "VPN" out of the app title. If a RuStore reviewer raises the category, respond with the local-filter + public-resolver-forwarding evidence. This is presentational risk only, not a fatal blocker.
- **RuStore review (primary channel, currently zero prep — verified: 0 repo mentions).** **De-risk:** draft the full RU runbook + honest listing + data-collection declaration now so the founder submits a clean, consistent package; prefer the store install path for grandma (skips the unknown-sources gate entirely).
- **CGNAT rate-limits.** Thousands of Tele2 phones share one IPv4 → the 3000/h blocklist cap and 5-fresh/min `/public/check` cap are hit collectively. **De-risk:** CDN dissolves the blocklist cap (B4); the `/public/check` cap only throttles the *best-effort novel-warn bonus* — the forward-then-check design already makes a 429 harmless (link forwarded first, local 432k list still blocks known-bad in µs, 429 silently ignored — verified in `LinkGuardActivity.kt` / `checkUrlAsync`). Do **not** raise the 5/min cap blindly (it bounds the paid analyzer fan-out).
- **Play Protect friction on Samsung.** A debug-signed 107 MB VPN app triggers unknown-sources gates + Play Protect warnings that read as "dangerous" to grandma. **De-risk:** real keystore (builds reputation), arm64-only slimmer APK, illustrated RU walkthrough on `/android`, and steer non-technical users to RuStore/Play (store install skips the gate). Never tell users to disable Play Protect.

---

## 7. Honest cut-line

**Minimum to launch safely to a FIRST small Tele2 cohort (direct-APK funnel):**
- B1 real keystore + B2 versionCode fix + arm64 build (installs, updates over itself)
- B3 APK hosted on a CDN + `/android` RU download page live
- B4 blocklist can't 429 (interim patch is enough; full CF can follow within days)
- B5 support page live (kills the 404) + honest RU direct-download copy (full store listings can follow)
- End-to-end smoke test passed on a real device over mobile data
- Basic uptime/latency monitor on `/health` + blocklist path

That gets a Tele2 subscriber to install and be genuinely protected. **Keep the first cohort small** (a few hundred to low thousands, well under the 3000/h-per-CGNAT-IP edge) precisely so the un-CDN'd origin and the store-less funnel are proven under real load before scaling.

**Can follow (not launch-blocking):**
- Full Cloudflare in front of the blocklist (do it before any large blast)
- RuStore + Google Play listings (better grandma path, but direct-APK works day one)
- In-app update check, notification-locale fix, link-guard home card (all improve retention/UX; the shield and link guard already work without them)
- Supabase anon key / Family Hub (optional — shield needs no account)
- iOS (no Org Apple account; explicitly out of scope for this launch)

**The founder's very first move is `keytool` (step 1).** Nothing downstream signs correctly until that key exists, and it's the one artifact only they can create and must never lose.