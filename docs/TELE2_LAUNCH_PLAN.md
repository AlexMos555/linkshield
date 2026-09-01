All findings ground out. Writing the plan.

---

# Cleanway → Tele2 Launch Plan

*Android-only, RU-first, direct-APK + RuStore. Grounded in the 5 audits and live-prod/file verification (2026-08-25).*

## 1. Verdict

**Yes, we can launch to a small first cohort — but not this week, and not with the current APK.** The engine is genuinely ready: prod blocklist is live (2.6 MB, verified 200), the on-device shield blocks listed phishing and lets `sberbank.ru`/`gosuslugi.ru` resolve on a real A16, the link guard (the exact SMS-phishing defense Tele2 subscribers are sold) is shipped and enableable, RU is 100% translated, and the RF-critical honest VPN disclosure ("это не VPN для анонимности") already exists. The single thing standing between "now" and "a Tele2 subscriber installs and is protected" is **a real release keystore + a hosted, versioned APK download page** — everything else is either already working or a fast follow. **Update 2026-08-31: signing and versioning are now solved** — a real keystore exists and the shipped APK verifies as `CN=Cleanway`, 55 MB, versionCode 100. What remains before traffic is **hosting the APK + merging the branch to prod**, plus two newly-found founder blockers: Supabase email is capped at **2 messages/hour** (no real SMTP ⇒ nobody receives a login code) and `cleanway.ai` has **no MX records** (`support@` bounces). See docs/GO_LIVE_CHECKLIST.md for the live status.

---

## 2. Launch-blockers (must-fix before ANY Tele2 traffic)

Ordered by how much each unblocks.

| # | Blocker | Owner | Concrete step |
|---|---------|-------|---------------|
| **B1** | ✅ **CLEARED 2026-08-31.** Keystore generated (`~/cleanway-release/`, RSA 4096, valid to 2054) and the first release APK built and verified — `apksigner`: *Verifies*, v2 scheme, `CN=Cleanway`, 55 MB, versionCode 100. *(Original problem: the APK was signed with the world-known Android debug key, so no store would take it and it had no stable update identity.)* | **Claude ✅ built it — Founder must BACK IT UP** | `mobile/plugins/withReleaseSigning.js` re-wires the `release` signingConfig on every `expo prebuild` (managed workflow regenerates `android/`), reading `keystore.properties`, and falls back to debug signing when absent — it can only upgrade a build, never break it. 8 transform assertions. ⏳ **Founder:** back up `cleanway-release.jks` + `keystore.properties` (password manager + one offline copy). Regenerating is still free — zero installed users — see docs/RUSTORE_SUBMISSION.md §1. |
| **B2** | **versionCode hardcoded to 1.** Even after B1, the next build won't install over the first — "App not installed". | **Claude ✅ DONE** | ✅ Set `app.json` to `version "1.0.0"` / `versionCode 100` (first public build, headroom) — Expo prebuild writes it into `build.gradle`. This also **matches the update-check server default** (`mobile_latest_version_*` = 100 / "1.0.0"), so a fresh install does NOT see a spurious "update available" (a mismatch the 2026-08-25 audit caught while it was 0.1.0/1). Founder bumps `versionCode` + `expo.version` per release, in step with the Railway env. |
| **B3** | ⚙️ **Half-cleared.** ✅ Claude: `/android` RU download page shipped and `install-urls.ts` android flipped to it (was `available:false → /dns`, a dead end). The APK is also down to **55 MB** from 92, so egress is far cheaper than the 107 MB this row originally feared. ⏳ **Founder:** the file still has no public home, and `NEXT_PUBLIC_APK_URL` is unset, so the download button shows "скоро" rather than a link. | **Founder (host + Vercel env)** | Publish the signed APK — a **GitHub Release** on this public repo is free, unmetered and Fastly-backed (Claude can create it on request); Cloudflare R2 (`get.cleanway.ai`) also works. Then set `NEXT_PUBLIC_APK_URL` in Vercel (needs the founder's Vercel login) and the `/android` CTA goes live with no code change. |
| **B4** | **Blocklist has no CDN** — single Railway `ams1` origin serves every 2.6 MB first-sync (verified: `server: railway-hikari`, no `cf-ray`; response already `public, max-age=1800` + strong ETag). A synchronized SMS blast saturates one instance; compounds with the 3000/h per-IP cap that a Tele2 CGNAT gateway (thousands of phones on one IPv4) can exhaust → fresh phones sit with an empty list, unprotected up to ~1h. | **Founder (CF account/DNS) + Claude (cache rule + trusted-proxy CIDRs)** | Put Cloudflare in front of `/api/v1/blocklist/dns` (a `dl.`/`blocklist.` subdomain is enough). The existing headers make it edge-cacheable — absorbs ~99% of first-syncs and dissolves the CGNAT 429 for the static artifact. **Claude interim (no account needed):** drop the per-IP rate-limit dependency from the blocklist GET (it's a signed, ETag'd public static file — nothing to protect per-IP) so it can't 429 even before the CDN lands. |
| **B5** | **Store-listing over-claims + dead support URL.** Old `mobile/STORE_LISTING.md` reintroduced retired false claims + declared support URL 404'd. | **Claude ✅ DONE + Founder (mailbox)** | ✅ Rewrote `mobile/STORE_LISTING.md` — honest, RU-authoritative: leads "защита от фишинга / DNS-фильтр on-device", domain-not-full-URL, explicit "не VPN для анонимности", numbers point to `/transparency/methodology` (no hardcoded recall/AUC), dropped the false data-residency line, breach/audit/weekly/score/paid tiers omitted until verified on-store. ✅ Support page shipped (commit 942454c). ✅ `docs/RUSTORE_SUBMISSION.md` runbook: keystore.properties setup, arm64 build recipe, Data-Safety answers (grounded in verified egress), VpnService justification text, review notes. ⏳ **Founder:** confirm `support@cleanway.ai` receives mail; register RuStore account. |

---

## 3. The critical path — today → "Tele2 sends the first SMS"

Interleaved. **[C]** = Claude builds, **[F]** = founder-only, **[both]**.

1. ✅ **DONE** — keystore generated at `~/cleanway-release/` and the signed APK built. **[F] Remaining: back the key up** (password manager + one offline copy).
2. ✅ **[C]** DONE — `release` signingConfig + explicit `versionCode` wired via config plugin + `app.json` (B1, B2). *(arm64-first ABI flag still pending, §4.)*
3. ✅ **[C]** DONE — signed release APK built from the sandbox: **55 MB**, `armeabi-v7a + arm64-v8a`, `CN=Cleanway`, versionCode 100. ⏳ **[F+C] still unproven:** that it installs on the A16 and updates over itself (bump versionCode, reinstall) — no device is attached.
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

- ✅ **Gradle signing + versioning** — DONE via `mobile/plugins/withReleaseSigning.js` (managed-workflow config plugin, reads git-ignored `android/keystore.properties`, debug fallback, idempotent + fail-safe) and `app.json` `versionCode`. *(Needs founder's keystore + keystore.properties to produce a store-signed build; the wiring is in place and can't break the current sideload build.)*
- ✅ **Per-ABI build** — DONE, but NOT the way this plan assumed. Measured 2026-08-31: `-PreactNativeArchitectures` does **not** slim an APK (it only feeds `splits.abi.include`, and splits are disabled by default — the first signed build was 92 MB with all four ABIs). Shipped `mobile/plugins/withAbiFilters.js` instead, which injects `ndk { abiFilters }`: it drops the emulator-only `x86`/`x86_64` and keeps **both** ARM ABIs, so no real phone is excluded. Result: **55 MB**. Store AABs still carry every ABI.
- **Android download page** — new `landing/app/[locale]/android/page.tsx` (RU-first): three paths (direct APK, RuStore, Play), illustrated Samsung "Разрешить установку / Всё равно установить" walkthrough. Flip `landing/lib/install-urls.ts` android `available:true` + CDN href.
- **Support page** — new `landing/app/[locale]/support/page.tsx` (RU): `support@cleanway.ai` + basic FAQ. Kills the 404 store field.
- ✅ **In-app update check** — DONE. `GET /api/v1/mobile/version` (new `api/routers/mobile.py`, env-driven, CGNAT-safe no per-IP limit) returns version name+code, security floor, apk_url, notes. Mobile `useUpdateCheck` compares the build's embedded version *name* (expo Constants, no new native dep, offline-safe) → `UpdateBanner` on home: dismissible nudge when newer exists, non-dismissible card (never a hard lock) below the floor. Network failure shows nothing; the last snapshot is persisted so a "must update" verdict survives offline. Pure decision logic unit-verified (13 assertions). Download falls back to the localized `/android` page when no signed APK url is set.
- **Notification locale fix** — `CleanwayVpnModule.kt` add `Function("setUiLocale")` → `LocalizedContext.set`; expose from `modules/cleanway-vpn/index.ts`; call from `i18n changeLocale()` + boot `restoreSavedLocale()`. Without it, block notifications ignore the in-app Russian pick (`cleanway_ui/locale` is never written — verified in audit).
- ✅ **Link-guard home card** — DONE. `app/(tabs)/index.tsx` now shows a link-checking ShieldCard driven by `useLinkGuard` (live `isDefaultLinkHandler()`, enable CTA → `requestLinkHandler()`, re-checks on focus). Dropped the Android `browser` "На подходе" rollout item — the shipped feature no longer advertises itself as coming soon.
- **Blocklist no-429 interim** — drop the per-IP rate-limit dependency from `api/routers/blocklist.py` GET (signed public static file); add CF CIDRs to `trusted_proxy_cidrs`.
- **CF cache rule spec** + **store listing RU drafts** (`STORE_LISTING.md` rewrite, honest; RuStore + Play variants) + **`docs/RUSTORE_SUBMISSION.md`** + **mobile Data-Safety / RuStore data-collection answers** grounded in `PRIVACY.md` + the mobile egress map + **Play VpnService declaration text + ≤90s demo shot-script**.
- ✅ **Link-guard no-browser fallback** — DONE. `LinkGuardActivity.forwardToBrowser()` now always forwards with an EXPLICIT browser package; when Cleanway is the only http/https handler it routes to the in-app verdict screen (`cleanway://`, which this activity doesn't handle → cannot loop) instead of firing an unpackaged `ACTION_VIEW` that resolved straight back to itself. Launch-failure also falls back to the app screen rather than dropping the link.

---

## 5. What only the founder can do (and why)

- ~~Generate the release keystore~~ — **done 2026-08-31** (Claude generated it at `~/cleanway-release/`, RSA 4096, valid to 2054; the first signed APK verifies as `CN=Cleanway`). The founder's job is now to **back it up** (password manager + offline copy). Regenerating is still free while there are zero installed users — see docs/RUSTORE_SUBMISSION.md §1.
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
- **Play Protect friction on Samsung.** A sideloaded VPN app triggers unknown-sources gates + Play Protect warnings that read as "dangerous" to grandma. **Partly de-risked:** the APK is now release-signed (reputation can start accruing) and down to 55 MB, and `/android` carries the illustrated RU walkthrough. Remaining: reputation takes installs+time, so steer non-technical users to **RuStore** (a store install skips the unknown-sources gate entirely). Note Google Play is not an option today — it now requires targetSdk 36 and we ship 34. Never tell users to disable Play Protect.

---

## 7. Honest cut-line

**Minimum to launch safely to a FIRST small Tele2 cohort (direct-APK funnel):**
- ✅ B1 real keystore + B2 versionCode + slim ABI build — DONE (55 MB, release-signed, versionCode 100). Still unproven on a real device: *installs, and updates over itself* (no phone attached).
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