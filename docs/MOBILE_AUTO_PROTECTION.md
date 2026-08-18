# Mobile Auto-Protection — Architecture Spec + Adversarial Review

> Produced 2026-07-29 by an 8-agent research workflow (6 web-verified research deep-dives →
> architect synthesis → adversarial critique). Verdicts below are grounded in July-2026
> App Review / Play policy checks with sources. This document is the single reference for
> replacing the paste-a-link hero flow with OS-level auto-protection.

## Resolution (amended plan, post-critique)

The critique CONFIRMED the 4-layer model and the kill-list, and AMENDED the phasing:

1. **Phase 1 is Android-only**: VPN DNS shield (branch `mobile-android-vpn`, ~9/10 done) +
   Shield Checklist home screen + kill the placebo `isProtected=true` toggle
   (`mobile/app/(tabs)/index.tsx:16`). Android is where 2-tap verified setup, visible
   block events, and the cultural-explainer notification are actually possible.
2. **iOS DNS shield slips behind 3 gates**: (a) DoH availability design — edge/CDN
   fail-open layer or deliberate soft-launch (see critique 4.1: always-on DNS makes us a
   one-person ISP; single-region Railway outage = "internet down" for every install);
   (b) on-device verification of the Private Relay claim; (c) a "recently blocked"
   surface decision — without it iOS DNS protection is experienced only as breakage.
3. **On iOS the real grandma product is the Safari Web Extension (Phase 2)**; the DNS
   layer there is silent infrastructure, never marketed as visible protection.
4. **Rule-data codegen pipeline moves to Phase 2 start** (before Safari port), not
   Phase 3 — every phase shipped before it mints new local-scorer drift surface
   (July-20 drift bugs are the recorded precedent).
5. Play Data Safety declaration ("web browsing history — collected, not linked, not
   shared"), prominent-disclosure screen, and VpnService declaration video are Phase 1
   line items, not afterthoughts. Oct 28, 2026 sensitive-permissions policy re-read at submit.
6. Hero copy: absolutes ("You're protected") only when ALL shields verified-on;
   partial coverage always shows the count. Honor-system shields (iOS SMS filter)
   never count toward the hero state.

---

# Cleanway Mobile — "Auto-Protection" Architecture Spec

**Status:** Definitive design, replaces paste-a-link hero flow
**Date:** 2026-07-29 | **Owner:** Founder (solo) | **Apple account:** Individual (sufficient for everything in Phases 1–3)

---

## 0. The one-sentence thesis

Stop making grandma do the work (paste a link) and start making the OS do the work: one shield per surface, each shield is a real OS-level mechanic, each shield's state is **verified, never assumed**, and each shield tells the truth about what it can and cannot see.

---

## 1. Layered protection model

Four layers, ordered by "protects without user action per-threat." Each layer has exactly one mechanic per platform, chosen for Individual-account shippability + reuse of existing assets.

| Layer | iOS mechanic | Android mechanic | Catches | **Misses (say it out loud)** |
|---|---|---|---|---|
| **Network (always-on)** | **NEDNSSettingsManager DoH app** → existing `/dns-query` gateway. NOT the VPN (5.4 org-gate); NOT in-app .mobileconfig (5.5 risk — keep profile web-only). | **VpnService DNS filter** (branch `mobile-android-vpn`, 9/10 done). Private DNS/DoT = power-user fallback only (needs `dot.cleanway.ai`, no grandma path). | Known-bad domains in **every app** — Safari, Chrome, WhatsApp/Instagram in-app browsers, email clients. Survives iCloud Private Relay (documented Apple behavior). | Novel domains not yet in the 6h-refreshed blocklist; URL paths; subdomain-phish on hosting platforms (by design); anything when user's other VPN is active. **On HTTPS the user sees a connection error, not our block page.** |
| **Browser (real-time, full-URL)** | **Safari Web Extension** — wrap of already-synced `extension-safari/` MV3 build (8/10 reuse). 74% of iOS browsing; the ONLY in-browser channel on iOS. | **Default-browser link interceptor** (URLCheck precedent, `RoleManager.createRequestRoleIntent(ROLE_BROWSER)` = one system dialog). Local scorer verdicts <50ms, safe links forward invisibly via Custom Tab. | Novel typosquats/homoglyphs via local scorer (works even when Safari kills the SW), full block-page with persona copy, credential-guard, honeypot, pw-pwned. Interceptor covers links tapped from **any** app. | iOS: Chrome/Firefox iOS (no extensions exist there, nobody covers this). Android: in-app WebView browsers bypass the default browser (DNS layer is the complement). Webmail module OFF on iOS v1 (desktop DOMs). |
| **Messaging (pre-tap)** | **ILMessageFilterExtension, offline-only** (Individual OK, no entitlement gate). Swift rule engine over **code-generated JSON from extension-core** — never a fourth hand-fork. Server-assisted mode is banned (fixed payload = full message text to our server = kills server-blind). | **Notification listener — DEFERRED, likely never** (greenfield 2/10, MEDIUM Play risk for unknown dev, Android 17 Sherlocks it). Share-sheet is the documented fallback. | SMS/MMS/RCS from unknown senders → Junk (iOS 26: dead links + silenced). | **iMessage — permanently invisible to any third party** (and it's where 2025-26 smishing lives). Known senders, post-3-replies threads. Android RCS filtering is Google-only. Market as "filters scam texts (SMS)", never "blocks smishing." |
| **On-demand (fallback, demoted from hero)** | Share-sheet (`mobile-share-flow` branch, 80% done) + paste + QR + screenshot → existing 18-check engine. | Same, `shared.tsx` already complete. | Anything the user actively suspects — including iMessage content the filter can't see. | Requires the user to suspect something. That's why it's the fallback, not the product. |

**Why this shape:** every above-the-line mechanic is (a) shippable on the Individual account today, (b) ≥5/10 built already, (c) precedented in the App Store / Play (DNSecure, URLCheck, Norton/Malwarebytes Safari extensions, Bitdefender), and (d) the layers' blind spots are mutually covering: DNS catches what the browser layer can't reach (in-app browsers), the browser layer catches what DNS can't see (novel domains, full URLs), share-sheet catches what messaging legally can't see (iMessage).

### Privacy egress map (per mechanic — publish this)

| Mechanic | What leaves the device | What never leaves |
|---|---|---|
| iOS DNS / Android VPN-DNS | Every DNS query (domain names) → api.cleanway.ai. No per-user logs (existing posture). | URLs, page content, identity. |
| Safari ext / interceptor | Caution-band domains only → public /check (local scorer verdicts safe/danger without network). | Full URLs for local-scored pages; webmail content (module disabled on mobile). |
| SMS filter (iOS) | **Nothing. Ever.** Offline rules via App Group. | Message text, sender numbers. |
| Share-sheet / paste | The domain the user explicitly submitted. | Everything else. |

---

## 2. Home screen: the Shield Checklist

Replaces the paste hero AND the current **placebo shield** (`mobile/app/(tabs)/index.tsx` defaults `isProtected=true` with no mechanism — this is an honesty bug by our own grandma-ethics bar; fixing it is part of Phase 1, not optional polish).

### Layout

```
┌─────────────────────────────────┐
│        ● Big Shield (hero)      │   Green ONLY when ≥1 shield verified-on.
│   "You're protected" /          │   Gray: "Let's set up your protection"
│   "2 of 3 shields on"           │   Never green unverified.
├─────────────────────────────────┤
│ 🛡 Every app          [ON ✓]    │   Network layer
│   "Blocks known scam sites in   │
│    every app — even WhatsApp"   │
│   ⓘ Can't catch brand-new scams │
├─────────────────────────────────┤
│ 🌐 Your browser       [Set up]  │   Browser layer (Phase 2 card hidden in P1)
│   "Warns you on the page,       │
│    before you type anything"    │
├─────────────────────────────────┤
│ 💬 Text messages     [Set up]   │   Messaging layer (Phase 3 card hidden until built)
│   "Moves scam texts to Junk.    │
│    Can't see iMessage — Apple's │
│    rule, not ours."             │
├─────────────────────────────────┤
│ 🔍 Check anything        [>]    │   On-demand: share/paste/QR/screenshot
└─────────────────────────────────┘
```

### States (per shield)

| State | Visual | Copy (grandma-grade) | Trigger |
|---|---|---|---|
| ON (verified) | Green check | "On. Working right now." | iOS DNS: `manager.isEnabled` on `appDidBecomeActive` + canary NXDOMAIN through the resolver. Android VPN: `isRunning` + canary. Safari ext: App-Group flag written by extension's first run + "Test it" page. |
| NEEDS SETUP | Blue "Set up" button | "One-time setup, about a minute." | Default. |
| PAUSED | Gray | "Paused. Tap to turn back on." | iOS: disconnect-all on-demand rule (AdGuard lesson — NEVER `removeFromPreferences`, or the Settings trek repeats). |
| CONFLICT | Amber | "Your VPN is in charge right now. Cleanway steps aside so nothing breaks." | VPN detected overriding DNS settings; another DNS app selected. |
| NETWORK BLOCKED | Amber | "This Wi-Fi blocks our protection. Your apps may not load — switch off Cleanway here if the internet seems broken." | Canary probe fails (DoH hard-fails, no cleartext fallback — must explain or it reads as "internet broken"). |
| UNVERIFIABLE | Neutral "Did you finish?" | (SMS filter only — Apple has NO enabled-state API; the `ILMessageFilterExtensionConfigurationManager` you'll find online is an AI hallucination.) Honor-system confirm + expectations copy. | Always, for SMS. |

**Rule: a shield never claims ON without a verified signal.** The canary check (resolve a known-blocked test domain, expect NXDOMAIN) is the truth source for both DNS mechanics.

> **Android status 2026-08-18 (emulator-verified, see `finding_2026-08-18_*` memories):** the states above are implemented as `setup / on / offline / unverified` plus an `interrupted` flag on `setup` ("Protection stopped — usually after a restart"). CONFLICT was removed: nothing in the code detects a competing VPN, so nothing may claim one. Verified transitions: on → green (canary counter delta, not NXDOMAIN inference); pause → 0 shields + tunnel gone; data off → on: tunnel survives, re-verifies green; offline: neutral "no internet" state, not an alarm; **reboot: BootReceiver → service → `prepare()`-then-`establish()` → tunnel_started → app opens straight to canary-green with no tap and no dialog.** The earlier belief that "Android drops VPN consent on reboot" was wrong — the AppOps grant persists, only ConnectivityService's in-memory prepared-package does not, and `prepare()` from the service restores it. Always-on VPN is now offered as an upgrade (starts with the phone, before BOOT_COMPLETED reaches any app — a gap of minutes on the emulator), not as the only path to survival.

### First launch

1. No account wall. Straight to the checklist with everything in NEEDS SETUP.
2. One primary CTA: **"Turn on protection"** → starts the platform's network-layer flow:
   - **Android:** tap → system VPN-consent dialog → done. Two taps total. Shield flips green on `isRunning` + canary.
   - **iOS:** tap → `saveToPreferences` (silent, no dialog) → immediately show the 3-step illustrated guide: "Settings → General → VPN & Device Management → DNS → tap Cleanway" with per-iOS-version screenshots (label drifts 14→26; verify iOS 26 wording on-device before writing 10-locale strings). "Open Settings" button (lands on app settings page — be honest it can't jump further; no deep link exists, DTS-confirmed). On return, poll `isEnabled`; on true → celebrate: **"You're protected everywhere — even links inside WhatsApp."** If false after 60s → offer guide again + 20-sec video.
3. Each remaining shield is a card the user can do later. No forced march.
4. Every block event → notification with the cultural-explainer reason (never bare "dangerous site") — this is our line-item nobody else does.

### The disarming card (Safari extension, Phase 2 — make-or-break)

Before the user hits Apple's "can read and alter webpages… including passwords" warning:
> "Apple shows this warning to every safety app. It means Cleanway is allowed to check pages for danger. Cleanway never reads your passwords — it warns you before a thief does."

---

## 3. Roadmap

### Phase 1 — ship this month (Individual account, ~2 weeks focused)

| Item | Effort | Notes |
|---|---|---|
| **Android VPN**: compile + device-QA `mobile-android-vpn` branch per MOBILE_VPN.md; **reroute unknown-domain lookups off the 5/min public /check** (use DoH gateway or blocklist sync — under real DNS volume /check starves and unknowns stay permanently unchecked) | 3–6 days | Store risk MEDIUM-LOW: "device security" is an explicitly permitted VpnService category, but the declaration form + ≤90s demo video + prominent-disclosure video + listing documentation are mandatory — skipping is a removal offense. |
| **iOS DNS shield**: local Expo Module (~150–200 LOC Swift: setDoH/getStatus/pause/resume), entitlement via `app.json ios.entitlements` (EAS auto-syncs Network Extensions), enable/guide screen ×10 locales, canary verification | 2–4 days | Store risk LOW — DNSecure precedent (Individual account, approved 2025-12-29). Review notes must say: "Uses the public DNS Settings API (NEDNSSettingsManager), not a VPN" to pre-empt a 5.4 misfile. Never say "VPN" anywhere in listing/UI. Budget one rejection-appeal cycle. EAS cloud build sidesteps the Xcode 26/SDK 52 gap. Real-device QA required. |
| **Merge share flow** (`mobile-share-flow`): iOS prebuild + device test | 1–2 days | Completes the on-demand layer; the documented iMessage fallback. |
| **Shield Checklist home screen** + kill placebo toggle + demote paste | 2–3 days | The honesty fix ships with, not after. |
| **Pre-flight infra**: confirm `dns.cleanway.ai` CNAME actually resolves (was pending — if not, every install breaks device DNS); pool the per-query `httpx.AsyncClient` in `doh_gateway.proxy_to_upstream` before real install volume; sign the web .mobileconfig | 1 day | Blockers, not polish. |

**Phase 1 exit:** both platforms have a real, verified, always-on network shield + universal share-sheet. That is already a competitive "auto-protection" story.

### Phase 2 — browser layer (~3–4 weeks)

| Item | Effort | Store risk |
|---|---|---|
| **iOS Safari extension**: prune manifest (drop notifications/contextMenus perms), gate ~8 unsupported call sites, harden SW-death paths (state to `browser.storage`, fail-soft sendMessage — local scorer in content scripts already survives SW death by accident of architecture), disable webmail module, responsive popup, App-Group "active" flag, packaging (web-based App Store Connect packager for fast validation → in-app target via config plugin as end state) | 1.5–2.5 wks to TestFlight | LOW-MEDIUM. Precedent-rich (Norton, Malwarebytes, AdGuard). Privacy label = translate docs/CWS_SUBMISSION.md. No IAP/upsell inside extension UI (4.4). **Re-sync local-scorer.js with backend first** — the July-20 drift bugs ship into Safari otherwise. |
| **Android link interceptor**: ACTION_VIEW http/https intent-filter + ROLE_BROWSER request + interstitial reusing shared.tsx flow + forward via Custom Tab with explicit package (exclude self, or it loops) | 1–2 wks | LOW — 6-year URLCheck precedent, zero sensitive permissions. Interstitial must stay ad-free and instant. |
| **DoT server** `dot.cleanway.ai:853` (dnsdist/dnsproxy in front of existing resolver) for Private DNS power users | 2–4 days | None (infra). |

### Phase 3 — messaging layer + horizon (~3–4 weeks, sequenced after traction signals)

| Item | Effort | Notes |
|---|---|---|
| **iOS SMS filter** (offline-only): @bacons/apple-targets `message-filter` target; thin Swift engine over **CI-code-generated JSON rule data from extension-core** (brands/homoglyphs/TLDs/lexicons) with a drift guard like the i18n one; App-Group blocklist snapshot (compact — ~6MB ceiling, bloom/top-N); onboarding walkthrough ×10 locales | 1.5–2.5 wks | LOW risk. Needs a second phone/SIM for QA. Budget iOS 26.0/26.1 filter-invocation flakiness time. Marginal value is bigger on iOS 17–18 (dumb built-in) than iOS 26 (built-in spam filter on by default) — our edge is URL-forensics + 10-locale bank brands + explanation. |
| **Android notification listener** | build-or-kill decision point | Default: **skip** (see §4). Revisit only if Play track-record evidence accumulates. |
| **Watch, don't build**: NEURLFilter (iOS 26) — full-URL system-wide filtering with PIR/OHTTP, philosophically perfect for server-blind, but entitlement is restricted and App Store Connect rejected entitled builds through Nov 2025. Request the capability early; plan nothing on it. | 0 | The acquirer-roadmap slide, not a 2026 dependency. |

**Prerequisite thread through all phases:** resolve the Expo SDK 52 vs Xcode 26 toolchain gap (SDK upgrade to 54/55, or Xcode 16 side-install) before any local iOS build; EAS cloud builds are the interim path. Target-API deadline Aug 31, 2026 pressures the SDK upgrade anyway — do it once, early in Phase 2.

---

## 4. Kill / demote list

| Item | Verdict | Why |
|---|---|---|
| **Placebo shield toggle** (`isProtected=true`, cosmetic) | **KILL in Phase 1** | Violates our own grandma-ethics bar. A fake "protected" state is the exact false-sense-of-security we accuse competitors of. |
| **Paste-a-link hero** | **DEMOTE** to "Check anything" card (4th position) | Table stakes minus everything in 2026; it's the fallback for iMessage and suspicion, not the product. |
| **Clipboard auto-monitor on foreground** | **KILL** | iOS pasteboard-access banners read as creepy; marginal value once share-sheet + interceptor exist; contradicts privacy-first optics for near-zero recall gain. |
| **iOS PacketTunnel VPN** | **KEEP PARKED** (already a no-op stub) | 5.4 org-gate. NEDNSSettingsManager delivers the same domain-level coverage without org enrollment, without the battery-drain complaint class, without a second VPN slot fight. Revisit only if an acquirer wants it. |
| **SMS server-assisted mode** | **NEVER** | Fixed payload = full message text + sender number to our server, un-strippable, Apple doesn't proxy. Single largest possible regression to the server-blind story. |
| **Android READ_SMS / default-SMS-handler** | **NEVER (as solo)** | Smishing exception requires analyst-report track record; declaring the permission un-approved risks whole-app rejection. |
| **In-app .mobileconfig offering (iOS app)** | **KILL from app scope** | Guideline 5.5 MDM-grade scrutiny. Web-only distribution continues for no-app users; app path is NEDNSSettingsManager. |
| **Android notification listener** | **DEFAULT-SKIP** | 2/10 reuse, third scorer fork in Kotlin, MEDIUM Play risk for an unknown dev, and Android 17 (H2 2026) Sherlocks chat-notification scanning. The window is real but narrowing faster than a solo founder ships. |
| **Webmail content scripts on mobile** | **DISABLE in iOS v1** | Desktop DOMs; shipping broken is worse than absent. |

---

## 5. Acquisition-story angle

The demo that survives due diligence has three defensible props:

1. **"Only individual-shipped full-stack iOS protection"** — the exact stack (DNS settings + Safari extension + SMS filter + share extension) that Norton/Malwarebytes ship with org accounts and armies, reproduced by one person on public APIs. That's an engineering-density signal acquirers pay for. The DNS layer's "works inside WhatsApp's browser, survives Private Relay" is a live, verifiable demo no paste-checker can fake.
2. **Honest measured transparency as category differentiator** — nobody in consumer security publishes live per-domain head-to-head benchmarks (61.5% vs Cloudflare, methodology page, honest FP rate). The incumbents' weakness is trust (Guardio 1.5/5, billing scandals; false-positive fatigue), not detection tech. The Shield Checklist's "what this can and cannot see" line under every shield is the productized version of that moat — demo it next to Norton's dashboard and the difference is visceral.
3. **One rule-data pipeline, N runtimes** — turning local-scorer.js from a hand-mirrored fork into CI-generated JSON consumed by JS (extension), Swift (SMS filter), and Kotlin (future) is not plumbing; it's the asset that makes the whole surface maintainable by a small team, and it's exactly what an acquirer's DD engineer looks for after they find the July-20 drift bug in the git history. Plus: Family Hub (already E2E) lands on the emerging family-administration battleground (Truecaller Family Protection, Dec 2025) ahead of most, and the server-blind posture is a ready-made narrative fit for Apple's NEURLFilter direction.

Demo script: tap a fresh URLhaus link in WhatsApp on a stock iPhone → connection refused (DNS shield). Tap a novel typosquat in Safari → full persona block-page with cultural explanation (extension shield, local scorer, airplane-mode-capable). Open cleanway.ai/check/<domain> → live benchmark vs Cloudflare. Three minutes, all real.

---

## 6. Open questions for the founder (only true founder calls)

1. **Toolchain fork:** upgrade Expo SDK 52→54/55 now (touches everything, but the Aug 31 target-API deadline forces it soon anyway) or side-install Xcode 16 as a stopgap? Recommendation: SDK upgrade at Phase 2 start; EAS cloud carries Phase 1. Your machine, your call.
2. **iOS DNS block UX trade-off:** DNS-level blocks show a browser connection error, not our explainer page — worse grandma experience than the extension. Accept as-is for Phase 1, or invest ~2 days in a "recently blocked" screen in-app (post-hoc explanation via block-event polling of the resolver)? (Costs a small privacy trade: requires some per-device recent-block signal — needs your call on the privacy line.)
3. **Second phone/SIM** for SMS-filter QA (Phase 3): buy a cheap SIM, or is there a second device in the household? Blocks the entire messaging layer's testing.
4. **Android notification listener:** confirm the default-skip, or do you want it built Play-ready and held? (Cost: ~2 wks + a Kotlin scorer port you then maintain.)
5. **Org account / legal entity:** the only thing it unlocks is the parked iOS PacketTunnel VPN. Recommendation: don't, until an acquirer or 5.4 change forces it. Confirm.
6. **`dns.cleanway.ai` CNAME + profile-signing cert:** both are your-hands-only ops tasks and are hard Phase-1 blockers — when can you do them?
7. **Phase-1 scope of the celebration claim:** "protected everywhere — even inside WhatsApp" is true at domain-level only. Sign off on the exact hero copy vs the honesty bar (proposed: keep the claim, with the ⓘ "can't catch brand-new scam sites" line always visible under the shield).

---

*Grounding: existing assets referenced are at `/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/` — `api/routers/doh.py`, `api/services/doh_gateway.py` (client-pooling fix needed), `api/routers/mobileconfig.py`, `packages/extension-core/src/utils/local-scorer.js` (re-sync before any port), `extension-safari/`, `mobile/app/(tabs)/index.tsx` (placebo toggle), `mobile/app/shared.tsx`, branches `mobile-android-vpn` @ c296200 and `mobile-share-flow` @ 7ab1d4c.*

---

# Adversarial critique — Cleanway Mobile "Auto-Protection" spec

Grounding checks run before critique: `doh_gateway.py:239` does open a per-query `httpx.AsyncClient` (spec's claim true), `mobile/app/(tabs)/index.tsx:16` does hardcode `isProtected=true` (placebo confirmed), both branches (`mobile-android-vpn`, `mobile-share-flow`) exist. Guideline numbers verified by web search where noted.

---

## Angle 1 — App Review / Play Review

**1.1 BLOCKER (Android) — DNS-query egress is "web browsing history" in Play's Data Safety form, and the spec never mentions the form.** Under real DNS volume, every domain the device visits goes to api.cleanway.ai. Google's Data Safety taxonomy treats browsing/domain history as personal data regardless of whether you log it — Google's standard is *collection = transmission off device*, not retention. Under-declaring is a removal offense; the spec budgets for the VpnService declaration form ([Play VpnService policy](https://support.google.com/googleplay/android-developer/answer/12564964)) but not the Data Safety section, prominent-disclosure dialog copy, or the fact that "no per-user logs" is *your* posture, not Google's definition. **Change:** add a Play-specific egress declaration task to Phase 1 (Data Safety: "Web browsing history — collected, not linked to identity, for app functionality, not shared"), write the in-app prominent-disclosure screen before the VPN consent dialog, and note the new sensitive-permissions policy [effective Oct 28, 2026](https://support.google.com/googleplay/android-developer/answer/16585319) — re-read it the week you submit.

**1.2 HIGH (iOS) — same problem on Apple's side: the privacy nutrition label.** Spec says "translate docs/CWS_SUBMISSION.md" for the Safari extension label, but the *DNS app* is the bigger label problem: domain-level browsing data transmitted to your server. Apple's label definition has a genuine "not collected if not retained beyond servicing the request" carve-out, which your no-logs posture can honestly use — but you must write that reasoning into App Review notes preemptively, because a reviewer seeing "security app + network extension + server endpoint" will default to suspicion. **Change:** one paragraph in review notes: what leaves the device, what's retained (nothing), citation of your published privacy doc. The spec's §1 egress map is exactly this — it just never says it goes *into App Store Connect*.

**1.3 HIGH (iOS) — Guideline 4.2 minimum-functionality risk on the Phase 1 iOS app is understated.** Phase 1 iOS ships: a checklist, a settings-trek guide, and a share-sheet. To a reviewer that can read as a thin wrapper around a Settings toggle ([4.2 "Minimum Functionality"](https://developer.apple.com/app-store/review/guidelines/)). DNSecure survives partly because it's transparently a utility. Your mitigation is real but must be deliberate: the on-demand 18-check flow with persona explanations *is* the app-like substance — make sure it's reachable and demoed in review notes, not demoted so hard it looks vestigial. **Change:** review notes should lead with the check-engine functionality; keep "Check anything" visually first-class even though it's strategically demoted.

**1.4 MEDIUM (iOS) — the 5.4 tightrope is real but the spec's defense is right; one addition.** Verified: [5.4](https://developer.apple.com/app-store/review/guidelines/) restricts *NEVPNManager* to organizations, with security apps "from approved providers" as exceptions — NEDNSSettingsManager is a different API and the entitlement has [no approval process](https://developer.apple.com/forums/thread/816877). The spec's "never say VPN anywhere" rule is correct and must extend to *screenshots*: iOS Settings shows your DNS config under "VPN & Device Management," and if your illustrated setup guide screenshots that Settings page into App Store screenshots, a reviewer pattern-matches "VPN" → 5.4 misfile. Keep those screenshots in-app only, never in the store listing.

**1.5 MEDIUM (Android) — the link interceptor's Play risk is not "LOW," it's "LOW until a policy sweep."** URLCheck's precedent is real, but URLCheck presents as a URL-inspection utility; Cleanway presents as a security app *silently forwarding* traffic via Custom Tab. "Safe links forward invisibly" is functionally an interstitial-free redirect of all user browsing through your app — the exact shape Play's deceptive-behavior sweeps target when done badly. **Change:** the interstitial must be visible-on-demand (long-press or setting), the listing must explicitly say "acts as your link-checking browser," and the ROLE_BROWSER request needs listing copy explaining why. Budget one policy-appeal cycle here too, not just on iOS.

**1.6 MEDIUM — Guideline 4.4 citation is correct** (verified: hosted extensions "may not include marketing, advertising, or in-app purchases") — but note it also requires the *container app* to "include some functionality, such as help screens and settings interfaces." The Shield Checklist satisfies this. No change; just don't strip the container to a stub in some future simplification pass.

---

## Angle 2 — Grandma test

**2.1 BLOCKER — the iOS DNS setup trek will lose most grandmas, and the spec knows it but doesn't price it.** Settings → General → VPN & Device Management → DNS → tap Cleanway is a four-level navigation with no deep link, through a menu whose name contains "VPN" (scary word you've banned from your own UI — but Apple puts it in hers). The spec's mitigations (screenshots, video, 60s poll) are palliative. Realistic completion for a 70-year-old without a helper: well under half. **Change:** design Phase 1 iOS around *assisted setup* — the guide's primary CTA should be "Ask a family member to help" with a shareable link (this also feeds Family Hub, which you already have E2E). Treat solo-grandma completion as a bonus, not the plan. And instrument the funnel (locally-aggregated, privacy-safe) or you'll never know the drop-off.

**2.2 HIGH — the NETWORK BLOCKED copy teaches grandma to disable protection.** "Switch off Cleanway here if the internet seems broken" — she will, at the first hotel captive portal, and she will never turn it back on. Worse: DoH hard-fail means a captive portal or an api.cleanway.ai outage presents as *the entire internet being broken*, and grandma will not connect "internet broken" to an app she set up weeks ago; she'll go to the carrier store. **Change:** (a) detect captive portals and auto-pause with a notification ("This Wi-Fi needs a sign-in page — Cleanway paused itself, will resume automatically"), resume on network change; (b) never make manual-disable the offered remedy.

**2.3 HIGH — the DNS block experience is "Safari cannot open the page," and the spec's block-event notification promise is impossible on iOS (see 3.1).** So on iOS Phase 1, grandma's *entire experience of being protected* is: pages mysteriously failing. No block page, no explanation, no notification. She cannot distinguish protection from a broken phone. The spec demotes this to open question #2; it's actually the difference between "protection" and "random breakage" in her mental model. **Change:** on iOS, accept that the *Safari extension* (Phase 2) is the real grandma product and the DNS layer is silent infrastructure; do not market the iOS DNS shield to her as something she'll "see working."

**2.4 MEDIUM — Android default-browser dialog will scare her.** The system dialog says "Set Cleanway as your default browser app?" — you can't reword it, and "changing my browser" is exactly the kind of change grandma's family has told her never to accept. Pre-dialog disarming card needed (same pattern as your Safari "can read webpages" card — that card is genuinely good; clone the technique).

**2.5 MEDIUM — SMS filter availability is regional/carrier-dependent and the enable path is another Settings trek** (Settings → Apps → Messages → Unknown & Spam), and [the filter setting may not appear at all depending on region/carrier](https://support.apple.com/guide/iphone/screen-and-filter-texts-iph203ab0be4/ios). The honor-system UNVERIFIABLE state is the right honest design, but decide now: does an honor-system shield count toward "2 of 3 shields on"? If yes, the hero can be green on an unverified mechanic — violating your own "never green unverified" rule. **Change:** honor-system shields display as "set up (unverified)" and never count toward the hero state.

---

## Angle 3 — False-security audit

**3.1 BLOCKER — "Every block event → notification with the cultural-explainer reason" is architecturally impossible on iOS as specced, and fixing it would breach your own privacy line.** NEDNSSettingsManager gives the app zero feedback about queries or blocks; blocks happen at your resolver. To notify per-block you'd need per-device query attribution server-side plus a push-token mapping — i.e., exactly the per-user DNS logging your egress map swears you don't do. On Android (VpnService, on-device interception) it's fine. The spec states this feature platform-blind, in the first-launch flow, as "our line-item nobody else does." **Change:** scope the sentence to Android + browser-extension layers explicitly; on iOS DNS, the most you can honestly offer is the opt-in "recently blocked" screen from open question #2 — and answer that question *before* writing the hero copy, because without it, iOS Phase 1 has no visible evidence of value at all.

**3.2 HIGH — "Blocks known scam sites in every app" has an unstated hole: apps that do their own DoH.** Chrome on Android with Secure DNS in custom mode, Firefox with DoH on, and any app with a hardcoded resolver bypass a VpnService plain-DNS filter entirely (you can't MITM port-443 DoH). Chrome's *automatic* mode usually falls back to the VPN's resolver, so default-config grandma is covered — but "every app" is a checkable claim and a security reviewer or DD engineer will check it. The Misses column lists four honest gaps; this is the fifth and it's missing. **Change:** add "apps that bring their own encrypted DNS" to the Misses column and drop "every app" to "almost every app" or scope it.

**3.3 HIGH — the hero state "You're protected" at ≥1 shield contradicts the spec's own admission that iMessage is where 2025-26 smishing lives.** Grandma with only the DNS shield on sees a big green shield while the #1 attack vector at her is 100% uncovered — and the ⓘ line covers "brand-new scam sites," not "your text messages." This is the structurally softened version of the placebo toggle you're killing. **Change:** hero copy at partial coverage should be the count ("2 of 3 shields on"), never the absolute "You're protected"; reserve the absolute for all-verified-on. The spec's layout hints at this but the States table and celebration copy both use absolutes.

**3.4 MEDIUM — "survives iCloud Private Relay (documented Apple behavior)" is doing load-bearing work in the demo script on an unverified citation.** Private Relay's interaction with NEDNSSettingsManager configs has shifted across iOS releases and the "documented" behavior is a developer-forum answer, not a guarantee. If the acquirer demo's WhatsApp trick fails on a Private-Relay-enabled stock iPhone, the whole three-minute script dies on prop one. **Change:** verify on-device on current iOS 26 before this sentence appears anywhere outside internal docs; have the demo phone's Private Relay state pre-checked either way.

**3.5 MEDIUM — "Warns you on the page, before you type anything" (browser shield card) overpromises against AiTM/BitB**, which your own variant-audit memo lists as true blind spots. Local scorer + blocklist miss a clean-domain reverse-proxy phish; the card copy claims a *timing* guarantee ("before you type") the mechanic can't always deliver. **Change:** "Checks every page you open and warns you on the page" — drop the temporal absolutism.

**3.6 LOW — SMS filter egress row says "Nothing. Ever."** True as designed, but the ILMessageFilter sandbox also *prevents the extension writing anything* — meaning no caught-message counter, no evidence-of-value display, ever. Not a privacy problem; a marketing honesty problem waiting to happen when someone asks "how many texts did it catch?" Answer now: "we can't know, by design" — and put that in the card's ⓘ.

---

## Angle 4 — Solo-founder reality

**4.1 BLOCKER — shipping always-on DNS makes you a one-person ISP, and the spec prices it at "1 day of pre-flight infra."** Every install routes 100% of device DNS through a single-region Railway deployment fronted by a per-query-instantiated httpx client (`doh_gateway.py:239` — the spec knows about pooling, good). What it doesn't price: every page load on every installed device now carries your server's RTT (a São Paulo grandma pays intercontinental latency on *every DNS lookup in every app*); an api.cleanway.ai outage = total internet loss for every install simultaneously (DoH hard-fail, no fallback) = 1-star firestorm + emergency while you sleep; and DNS SLO infrastructure (anycast/multi-region, monitoring, paging) is not a solo-founder line item. The resolver's verdict-level fail-open (`doh.py:45`) doesn't help with *availability* failure. **Change:** before any install volume, make an explicit availability decision — either (a) front the DoH endpoint with an edge CDN/worker layer that serves cached/pass-through resolution when origin is down (fail-open on availability, fail-closed only on confirmed-bad cache hits), or (b) cap Phase 1 rollout deliberately (soft-launch markets) until multi-region exists. This is the single most dangerous unpriced item in the spec.

**4.2 HIGH — Android OEM process-killing will silently disable the VPN shield, and the spec has no state for it.** Samsung/Xiaomi/Oppo battery managers kill VpnService overnight; protection goes dark until next app open; your verified-state model (`isRunning` + canary on appDidBecomeActive) only detects it *when grandma opens the app*, which she never does. This is the top complaint class for every Android DNS-filter app (see dontkillmyapp's entire existence). **Change:** foreground service with persistent notification, always-on-VPN guidance in setup, and a periodic WorkManager canary that fires a "protection was turned off by your phone" notification. Budget the per-OEM whack-a-mole as permanent maintenance, not a bug.

**4.3 HIGH — the rule-data codegen pipeline is scheduled backwards.** The spec puts "CI-code-generated JSON from extension-core" in Phase 3 (SMS filter), but Phase 1 ships a *third* consumer (Android VPN blocklist logic) and Phase 2 ships Safari with the July-20-drift-prone local-scorer.js. Your own memory system records that hand-mirroring already produced shipped bugs (apple.com.cn FP, vvellsfargo miss). Every phase that ships before the pipeline exists mints new drift surface. **Change:** pull the codegen work to Phase 2 start (it's also your acquisition-story prop #3 — build the asset before the DD engineer looks). Phase 1's Android branch should at minimum consume a checked-in generated snapshot with the existing i18n-style drift guard, not fresh Kotlin logic.

**4.4 MEDIUM — Phase 1 "~2 weeks" is a 4–6 week reality.** Sum the spec's own line items: 3–6 + 2–4 + 1–2 + 2–3 + 1 = 9–16 focused days *before* the unpriced items this critique adds (Play Data Safety + prominent disclosure + demo videos, iOS review-rejection cycle explicitly budgeted, 10-locale strings through the build-i18n pipeline for every screen, real-device QA on hardware you've documented as toolchain-blocked locally — EAS carries builds but not device QA time). Solo, with ops interrupts, double it. **Change:** either re-date Phase 1 or cut it to Android-only (see verdict).

**4.5 MEDIUM — OS-update exposure is acknowledged unevenly.** Priced: Settings label drift, iOS 26 SMS flakiness, Aug 31 target-API. Unpriced: every iOS point release can change Safari SW-death behavior and Private Relay/DNS interplay (re-run canary + demo script each beta); Chrome's Secure DNS defaults are a Google policy change away from hollowing out the Android VPN layer (3.2); and the Android 17 notification-listener Sherlock you cite for the *deferred* feature also signals Google building native smishing protection that erodes the VPN layer's differentiation on the same timeline. **Change:** add a standing "each OS beta: re-verify canary, Private Relay claim, SMS filter invocation" checklist item; it's ~a day per OS cycle, forever.

**4.6 LOW — the second-SIM QA gap (open question 3) blocks Phase 3 entirely and has lead time.** Cheap prepaid SIM now, not at Phase 3 start — some carriers' SMS filter availability differs (2.5) and you want to discover that early.

---

## Verdict

**The layering is right; the Phase 1 platform-bundling is wrong.** The four-layer model, the kill list (placebo toggle, clipboard monitor, server-assisted SMS, READ_SMS), the honesty architecture (verified-never-assumed, misses-said-out-loud), and the Phase 2/3 ordering are all sound — this is a genuinely strong spec whose main defects are (a) treating both platforms' network shields as one Phase 1 unit when they have wildly different risk/ROI, and (b) pricing the "become everyone's DNS resolver" liability at one day.

**The single highest-ROI first ship: the Android VPN shield + Shield Checklist (killing the placebo toggle), Android-only, with the availability decision (4.1) made first.** Reasons: the branch is 9/10 done; setup is genuinely two taps with machine-verifiable state (the one surface where "grandma auto-protection" actually works unassisted); block events are visible on-device, so the cultural-explainer notification — your claimed differentiator — is *only possible on Android* in Phase 1 (3.1); and Play risk is a known, form-shaped process rather than Apple's judgment call. The iOS DNS shield should slip to late Phase 1/early Phase 2 behind three gates: the DoH availability design (4.1), on-device verification of the Private Relay claim (3.4), and an answer to open question #2 — because without a "recently blocked" surface, iOS DNS ships as protection grandma experiences only as breakage. On iOS, the Safari extension — not the DNS shield — is the real grandma product; the DNS layer there is silent infrastructure and should be marketed as such.

Sources: [App Review Guidelines (Apple)](https://developer.apple.com/app-store/review/guidelines/) · [Play VpnService policy](https://support.google.com/googleplay/android-developer/answer/12564964) · [Play sensitive permissions/APIs (Oct 2026 update)](https://support.google.com/googleplay/android-developer/answer/16585319) · [Network Extension entitlement approval thread](https://developer.apple.com/forums/thread/816877) · [Guideline 5.4 history/analysis](https://www.ivpn.net/blog/insights-apple-app-store-rules-vpn-apps/) · [4.2 minimum functionality](https://iossubmissionguide.com/guideline-4-2-minimum-functionality/) · [iPhone text filtering (region/carrier caveat)](https://support.apple.com/guide/iphone/screen-and-filter-texts-iph203ab0be4/ios) · [ILMessageFilter extension constraints](https://medium.com/@lucianboboc/creating-a-message-filter-extension-580c9957633d) · [URLCheck precedent](https://www.androidauthority.com/urlcheck-android-3528095/)