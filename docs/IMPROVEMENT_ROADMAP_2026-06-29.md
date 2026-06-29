# Cleanway 4-Week Improvement Roadmap

**Date:** 2026-06-29
**Input:** docs/AUDIT_2026-06-29.md (avg 5.7/10)
**Author:** AI synthesis with adversarial verifier pushback applied
**Status:** Imperative. Verifier corrections folded into effort sizing, file paths, and dropped items.

---

## 4-Week Sprint Plan

| Wk | Dim | Title | Owner | Effort | Impact | Success Metric |
|----|-----|-------|-------|--------|--------|----------------|
| 1 | strat | Block CWS submit date Fri 2026-07-03 | user_only | s | critical | Status = "In review" by EOD Friday |
| 1 | strat | Set 90-day go/no-go calendar trigger | user_only | xs | high | Calendar event on 2026-09-27 + criteria in audit doc |
| 1 | free | Re-run fresh-URL benchmark on fan-out endpoint | claude_now | xs | critical | latest.json dated 2026-06-29, whatever the number, replaces stale 0% |
| 1 | dns | Set dns.cleanway.ai CNAME + validate iOS install | user_only | xs | critical | curl returns 200, real iPhone blocks URLhaus URL |
| 1 | dns | Reframe /dns landing as "one layer in a stack" | claude_supervised | s | high | All 10 locales drop "system-wide" claim; honest gap table vs NextDNS |
| 1 | privacy | Scrub domain from /public/check/{domain} logs | claude_now | xs | high | Test asserts {domain} placeholder; Railway log 24h grep = 0 raw domains |
| 1 | speed | Add /metrics Prometheus endpoint (bearer-gated) | claude_now | xs | high | Grafana shows live p50/p95/p99 within 24h |
| 1 | speed | Wire SENTRY_RELEASE from Railway commit SHA | claude_supervised | xs | medium | Test error tagged with SHA appears in Sentry |
| 1 | suite | AV-Comparatives Q3 submit email + budget approval | user_only | m | critical | Lab ack within 7d; EUR 4-8K budget pre-approved |
| 1 | suite | MS Founders Hub signup (only — no AppSource featured claim) | claude_supervised | xs | medium | Approval within 2 weeks |
| 1 | ux | Trash welcome-flow PROTOTYPE (HTML mockup, no production wire) | claude_now | xs | high | Clickable mockup ready for grandparent test |
| 2 | ux | n=3 grandparent usability study on PROTOTYPE | user_only | s | critical | 3 sessions logged; defects classified ship-block/major/minor |
| 2 | ux | Implement skill-level wizard in packages/extension-core/ | claude_now | s | high | New install hits wizard; ≥60% pick non-default persona |
| 2 | ux | Wire Cultural Explainer fetch in block-page (post-DOM-attach) | claude_now | xs | high | Block page renders locale-cultural example; fail-soft <1.5s |
| 2 | speed | Cloudflare Free in front of api.cleanway.ai (precursor: trust CF-Connecting-IP) | user_only | s | high | São Paulo TTFB <80ms cached; rate limiter still works |
| 2 | privacy | Create docs/PRIVACY.md (prereq for items below) | claude_now | xs | medium | SAFE_KEYS published with literal code block |
| 2 | privacy | Caption LLM judge data boundary on privacy + methodology pages | claude_now | xs | medium | Reader can answer "does Anthropic see URL?" in <30s |
| 2 | strat | Cold-email Bitdefender BD/partnerships (not CEO) + Nord + 1Password partner program | user_only | s | high | 3 emails sent; ≥1 substantive reply in 21d |
| 2 | suite | Proton partner pitch (Eamonn Maguire, not Andy Yen) | claude_supervised | m | high | Deck sent within 2 weeks via warm intro |
| 3 | strat | Open-source engine + Show HN scheduled | claude_supervised | m | high | cleanway-engine repo public, builds clean, Show HN booked Tue 9am PT |
| 3 | free | Measure per-link badge density on Gmail/Outlook/Reddit/Discord | claude_supervised | m | medium | Table published; ≥3 surfaces >80% coverage |
| 3 | dns | Competitor parity matrix + pick ONE differentiator (scoped issue only) | claude_supervised | s | medium | docs/COMPETITOR_PARITY_DNS.md committed; differentiator selected |
| 3 | suite | Password-manager partner kit (depends on OS engine landing) | claude_supervised | l | medium | Kit + cleanway-engine npm package; outreach to 2 named contacts |
| 4 | speed | Bloom filter of known-bad domains (DELIBERATE post-CWS-approval) | claude_supervised | l | high | <10ms block render for seeded URLhaus domains; FP <1% |
| 4 | dns | De-emphasize /dns in primary nav → footer | claude_supervised | xs | medium | DNS moves to footer "Other install methods" |

**25 items total. Some week-3/4 items are conditional on week-1/2 outcomes.**

---

## Week 1: Ship the asset, fix the false artifacts

This week has one strategic purpose: **stop grooming, start submitting**. Every item is either an asset-shipper, a credibility-falsification fix, or instrumentation that makes subsequent weeks measurable.

### user_only — Friday is submission day

- **CWS submission date locked.** First step: open Calendar, create event "Cleanway Chrome Web Store submit" Fri 2026-07-03 14:00-18:00. Block all other calls. Open chrome.google.com/webstore/devconsole in a tab now.
- **90-day exit calendar trigger.** First step: create all-day event 2026-09-27 "Cleanway 90-day go/no-go decision". Append "Exit Trigger" section to `/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/docs/AUDIT_2026-06-29.md` with the three pre-committed paths (lifestyle / full OSS walk-away / acquihire close).
- **DNS CNAME.** First step: open Cloudflare dashboard for cleanway.ai zone. Add CNAME `dns` → `api.cleanway.ai`, **proxy=OFF (orange-cloud DISABLED) for this subdomain only — the apex/api remain proxied**. Then: `curl -v --doh-url https://dns.cleanway.ai/dns-query https://example.com`. Then install the iOS .mobileconfig on a real iPhone, hit a URLhaus URL, confirm block. Note: also check whether Apple's current .mobileconfig consumer-distribution policy throws a scary warning — verify before pushing to public landing.
- **AV-Comparatives Q3 submit.** First step: confirm EUR 4-8K budget this week. Then send email — verify recipient via av-comparatives.org/contact/ (use `sales@av-comparatives.org` as the documented vendor enquiry channel, not the unverified `anti-phishing@` alias). Subject: "Cleanway Anti-Phishing Engine — Submission for Q3 2026 Anti-Phishing Test". Realistic timeline: badge live end of Q4 2026 when the cycle report publishes, NOT 8 weeks.
- **MS Founders Hub.** First step: apply at https://foundershub.startups.microsoft.com/signup (15 min form). Do NOT promise AppSource featured placement this sprint — that requires customer testimonials we don't have and Co-Sell-Ready status which is a separate multi-month track.

### claude_now — fix the false artifacts

- **Re-run fresh-URL benchmark.** First step: `cd /Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield && python scripts/eval_fresh_urls.py --endpoint https://api.cleanway.ai/check --out docs/benchmarks/2026-06-29-fresh-urls.json && cp docs/benchmarks/2026-06-29-fresh-urls.json docs/benchmarks/latest.json`. **Publish whatever number comes out, dated 2026-06-29.** Do not gate publication on >0.6 — 0.45 honest beats stale 0% by an order of magnitude.
- **Scrub /public/check/{domain} log path.** First step: edit `api/main.py:165` adding regex branch `r'^/api/v1/public/check/[^/]+$' → '/api/v1/public/check/{domain}'`. Extend `tests/test_pwned_passwords.py` with scrubbed expectation.
- **Add /metrics endpoint.** First step: `pip install prometheus-fastapi-instrumentator`, edit `api/main.py` after Sentry init: `Instrumentator().instrument(app).expose(app, endpoint='/metrics', include_in_schema=False, tags=['ops'])`. Gate via METRICS_TOKEN bearer (Railway has no private-port option — bearer is the only path). Wire Grafana Cloud Agent.
- **Welcome-wizard PROTOTYPE (mockup only, NOT production).** First step: create a Figma or HTML clickable prototype of the 4-card skill-picker. Do NOT touch `packages/extension-core/` this week — the verifier caught a real risk: if grandparent test in week 2 says the copy is incomprehensible, production code shipped Monday is wasted.

### claude_supervised — instrumentation and honest copy

- **SENTRY_RELEASE wiring.** Railway env var `SENTRY_RELEASE=${{RAILWAY_GIT_COMMIT_SHA}}` + `release=os.environ.get('SENTRY_RELEASE')` in `sentry_sdk.init()`.
- **Reframe /dns landing.** First step: edit `landing/app/[locale]/dns/page.tsx` hero to "Phishing-tuned DoH. One layer in a multi-surface defense." Grep for the DNS hero key in `landing/messages/en.json`, update all 10 locale files. **Important caveat the verifier caught:** the 93.5% recall number belongs to the extension fan-out, not DoH. Before publishing any DNS comparison table, run a separate DNS-only recall benchmark via `doh.py` blocklist path. Do not import the extension number.

---

## Week 2: Validate with humans, harden the egress story

The pivot point. Week 1 shipped instrumentation and an asset. Week 2 confronts the product with non-author humans and locks the privacy posture before the OSS release.

### user_only

- **n=3 grandparent usability study.** First step: text 3 people today, "Can your mom/dad spend an hour helping me test something — I'll bring coffee." Create `docs/UX_STUDY_2026-Q3_protocol.md` with 6 scripted tasks. **Run sessions on the WEEK-1 PROTOTYPE, not on production code.** Defects classified per a written rubric (ship-blocker / major / minor), not loose count. n=3 catches ~80% of severe issues per Nielsen.
- **Cloudflare Free in front of api.cleanway.ai.** **Precursor (do BEFORE flipping orange-cloud):** land a commit that trusts `CF-Connecting-IP` in the rate-limiter middleware. Without this, every request looks like it comes from a Cloudflare edge IP and global rate limit collapses to ~5/min planet-wide (verifier caught — MEMORY notes a pre-existing rate-limiter bug). Then: Cloudflare dashboard → set api A/CNAME proxied → create one Cache Rule: GET `/check/*` 60s edge TTL, 30s browser TTL.
- **Cold-email Bitdefender BD + Nord + 1Password.** First step: create `docs/marketing/tear-sheet.md`. Copy 6 hard numbers from audit + fresh benchmark. Export to PDF. **Verifier corrections folded:** verify the actual Bitdefender corpdev/partnerships email via their press releases (not a guessed address). Target Director-of-Partnerships / BD-lead on LinkedIn, NOT Florin Talpes (CEOs at $200M+ security cos don't reply to cold M&A pitches from zero-MAU projects). Frame as "distribution partner / OEM tech licensing", not "acquihire pre-meeting".

### claude_now

- **Skill-level wizard in extension-core.** **Verifier path fix:** edit `packages/extension-core/src/popup/welcome.html` and create new `welcome.js` (which does NOT currently exist — acknowledge new file, handle MV3 CSP inline-script restriction with externalized JS). The `extension/`, `extension-firefox/`, `extension-safari/` dirs are sync TARGETS per `scripts/build-extensions.sh`; editing them gets clobbered. After core edit, run sync script. Default-highlight "Granny" for hi/ar/id/ru/pt locales.
- **Wire Cultural Explainer in block-page.** **Verifier path/timing fix:** edit `packages/extension-core/src/content/block-page.js`. Fire fetch AFTER overlay attached to DOM (around line ~630 post persona switch), NOT during synchronous `buildOverlay` HTML construction. Inject `<p class="ls-cultural-explainer">` into a placeholder node when promise resolves. Handle `chrome.i18n.getUILanguage()` returning BCP-47 (e.g. `zh-Hans`) — verify explainer LOCALES fallback for unsupported codes.
- **Create docs/PRIVACY.md.** Prereq for the LLM-judge captioning item — verifier confirmed this file does NOT exist today. Document SAFE_KEYS, the egress contract, the audit log fields, the retention timeline. Source the language from `api/services/llm_judge.py:106` directly.
- **Caption LLM judge data boundary.** First step: read `api/services/llm_judge.py` lines 100-140 to copy SAFE_KEYS verbatim. Locate `landing/app/[locale]/privacy/page.tsx`. Add "What leaves the box to Anthropic" section with literal code block + paragraph: "The domain is never sent. The URL is never sent. The verdict and a signal name list are." Link from methodology page LLM-judge row.

### claude_supervised

- **Proton partner pitch.** First step: create `docs/marketing/proton-partner-pitch.md` with 4 sections (gap in Proton stack, server-blind fit, commercials, tech sketch). **Target: Eamonn Maguire (Director of Account Security) via LinkedIn, NOT Andy Yen as primary — same rationale as Bitdefender, BD-tier not CEO-tier.** Export to PDF only after user reviews + provides warm-intro path.

**Dropped from week 2 (verifier-rejected):**
- IP /16 hash audit log change. Rejected: /16 collapses CGNAT/mobile users into one bucket, destroying the per-actor correlation that's the only justification for IP hashing at all. **Replace later** with HMAC + daily-rotating-key (Cloudflare-style) if dimension still needs a win. Not this sprint.
- LLM judge opt-out header. Rejected as written: `arbitrate()` function name doesn't exist (real function is `judge_ambiguous_verdict()` at `llm_judge.py:416`), and adding a header guard requires plumbing `Request` (or `opt_out: bool`) through `analyze_domain()` and every caller — that's real `s` bordering `m`, not "add a guard at function top". **Defer** to post-launch when scope is honest.

---

## Week 3: Distribution + structural moves

Week 3 is when the OSS release and Show HN land. By this point the extension is in CWS review (week 1) or approved, real users from week 2 have surfaced UX defects, and Cloudflare edge is live.

### claude_supervised

- **Open-source the engine + Show HN scheduling.** **Verifier effort correction: this is `m` (3-5 days), NOT `s`.** docs/OPEN-SOURCE.md itself says "Sprint 1: Repo split 3-4 days solo work." `git filter-repo` with history preservation, LICENSE/README/CONTRIBUTING/SECURITY, and crucially: **validate the public repo BUILDS AND RUNS** without closed-module imports. If `scoring.py` imports `pricing.py` (closed), the public repo is broken on arrival. Acceptable downgrade: ship just repo skeleton + LICENSE + README week 3, code carve-out week 4. Show HN scheduled Tue 9am PT in week 4 only if repo actually runs.
- **Per-link badge density measurement.** First step: read `packages/extension-core/src/content/security-score.js` to confirm DOM selector for injected badges. Create `scripts/measure_badge_density.py` with Playwright. 4 surfaces: Gmail, Outlook web, old.reddit.com r/all, Discord. Use saved storageState for logged-in. Commit `docs/benchmarks/badge-density-2026-06-29.{json,md}`. **Do not republish the "70% of phishing-click delivery" claim in landing copy without a cited source** — that founder-says-so number is exactly what we're trying to stop.
- **DNS competitor parity matrix.** First step: create `docs/COMPETITOR_PARITY_DNS.md` with the 5-column header (NextDNS / ControlD / DNSFilter / CleanBrowsing / Cleanway). Use `/deep-research` skill to seed rows. Pick ONE differentiator (recommend school-hours scheduling via Family Hub) and file a scoped issue. **DO NOT implement the scheduling endpoint this sprint** — verifier caught that the original proposal bundled matrix + endpoint + cross-surface demo into one `m`. Matrix + scoped issue only this week.
- **Password-manager partner kit + cleanway-engine npm.** **Verifier effort correction: `l`, not `s`.** This requires extracting content scripts #11 and #13 from the extension, the OPEN-SOURCE.md MIT split (which depends on the week-3 OSS release landing first — explicit dependency), API surface design, README, v0.1.0 release, dependency audit, security review. **Sequencing dependency: OSS release must land before this can ship.** Outreach to Jeff Shiner (1Password) via LinkedIn direct (1Password is NOT YC alumni — they bootstrapped + Accel Series A 2019; the "Toronto YC alumni" path the original proposal cited does not exist) and Michael Crandell (Bitwarden) via password-manager-OSS LinkedIn community. Use `1password.com/partners` open partner program as the formal channel.

---

## Week 4: Speed wins + nav cleanup (deliberate post-CWS-approval)

By week 4: extension is approved (or rejected — handle separately), benchmark numbers are live, OSS repo is public, Show HN has run.

### claude_supervised

- **Bloom filter of known-bad domains.** **Verifier-driven trade-off acknowledged:** this pushes extension from 608K to ~1.3MB pre-gzip. Chrome Web Store re-review takes 3-14 days. **Deliberate decision: ship bloom AFTER initial CWS approval lands, NOT before.** First step: create `scripts/build_bloom.py` using `pybloom-live`. Right-size for actual unique corpus (~800K not 1M after URLhaus/Tranco overlap dedup): `m=8M` bits, `k=7`, `p≈0.008`. Daily GH Actions cron sibling to existing Tranco refresh.
- **De-emphasize /dns in primary nav.** **Verifier path correction:** the files `landing/components/Navigation.tsx` and `Footer.tsx` do NOT exist (only `LanguageSwitcher.tsx`, `ServiceWorkerRegistration.tsx`, `ShareScanButton.tsx` are present). First step: `rg -n '/dns' /Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/landing/` to locate the actual nav (likely `landing/app/[locale]/layout.tsx`). Move DNS link to footer "Other install methods" group. Commit a `docs/STRATEGY.md` line: "DNS = secondary surface until mobile native ships."

---

## Owner Split

### claude_now (this session, no user input needed)
- Re-run fresh-URL benchmark (week 1)
- Scrub /public/check/{domain} log path (week 1)
- /metrics Prometheus endpoint (week 1)
- Welcome wizard PROTOTYPE (week 1)
- Skill-level wizard production wire (week 2)
- Cultural Explainer fetch wiring (week 2)
- Create docs/PRIVACY.md (week 2)
- Caption LLM judge data boundary (week 2)

### claude_supervised (I implement, user picks direction)
- Reframe /dns landing copy (week 1)
- SENTRY_RELEASE wiring (week 1)
- MS Founders Hub signup (week 1)
- Proton partner pitch deck (week 2)
- Open-source engine + Show HN (week 3)
- Per-link badge density measurement (week 3)
- DNS competitor parity matrix (week 3)
- Password-manager partner kit (week 3-4)
- Bloom filter (week 4)
- De-emphasize /dns in nav (week 4)

### user_only (DNS, secrets, store accounts, calendars, human outreach)
- CWS submission Friday block (week 1)
- 90-day go/no-go calendar event (week 1)
- DNS CNAME + iOS install validation (week 1)
- AV-Comparatives Q3 submission + EUR 4-8K budget approval (week 1)
- Grandparent n=3 usability study (week 2)
- Cloudflare orange-cloud flip (week 2)
- Cold-emails to Bitdefender BD / Nord / 1Password (week 2)

### external_party (responses depend on people who are not us)
- AV-Comparatives lab Q3 round (Q3 ack week 1; results Q4)
- Proton response (target: substantive reply by week 8)
- Bitdefender / Nord / 1Password BD replies (target: 1 reply by week 5)
- Microsoft Founders Hub approval (target: week 3)
- HN front page (target: week 4 Show HN slot)

---

## Effort Budget Honest Accounting

**Solo dev capacity assumption:** 40h/week sustainable, 50h/week occasional, 60h sustained = burnout in 6 weeks.

Estimated solo hours per week:

| Week | claude_now (auto) | claude_supervised (review + decisions) | user_only (manual + meetings) | Total user-hour load |
|------|---|---|---|---|
| 1 | ~16h (parallel) | ~6h review | ~8h (CWS prep + calls + DNS + emails) | **30h** |
| 2 | ~12h (parallel) | ~6h review | ~12h (3× 90-min grandparent sessions + 3 cold-emails + Cloudflare validation) | **30h** |
| 3 | ~4h | ~12h (OSS release is heavy) | ~6h (Show HN scheduling, partner kit review) | **22h** |
| 4 | ~2h | ~14h (bloom filter is `l`) | ~4h | **20h** |

**Total: ~102h over 4 weeks.** Sustainable. Below the 160h cap (40h × 4wk).

**FLAGS:**
1. **Week 1 is the heaviest user-hour week.** Five distinct user-only items: CWS calendar block, 90-day trigger, DNS CNAME validation, AV-Comparatives submit, MS Founders Hub. If user availability that week is <20h, **defer AV-Comparatives to week 2** (it's a single email + budget approval — not time-critical against the Q3 window).
2. **Bloom filter (week 4) is the single biggest claude_supervised item.** If CWS approval slips into week 4, defer bloom to post-week-4 entirely — the CWS-re-review-delay risk is real.
3. **OSS release (week 3) is `m` not `s`.** Verifier caught this. If week 3 capacity is constrained, ship just the repo skeleton + LICENSE + README in week 3 and push code carve-out to week 4.
4. **Grandparent study (week 2) cannot be parallelized.** Three 90-minute sessions require physical time. If user can't recruit 3 people by Wednesday week 2, drop to n=2 — still catches ~70% of severe issues.

---

## What We Explicitly Are NOT Doing in These 4 Weeks

Killing the "just one more feature" loop is the point.

**Not doing:**

1. **IP /16 hash audit log change.** Verifier-rejected: /16 destroys per-actor fraud correlation. Replace later with HMAC + daily-rotating-key if dimension still needs a win.
2. **LLM judge opt-out header.** Verifier-rejected as scoped. Real implementation requires plumbing `Request` through `analyze_domain()` and all callers — that's `m`, not `s`. Defer to post-launch with honest scope.
3. **EFF / NCC / Mozilla privacy review outreach.** Verifier-rejected wholesale: EFF doesn't run code audits, NCC's "free OSS review" program is invented, MOSS is wound down. Replace later with privacytests.org submission, crxcavator score, Mozilla AMO reviewer feedback, Exodus Privacy listing — all gated on actual artifacts, not cold-email theater.
4. **AppSource featured placement / co-sell badge.** Requires customer testimonials + IP-Co-Sell-Ready status (multi-month). Founders Hub signup is the only week-1 move; everything beyond waits for first 5 M365 customers to actually exist.
5. **DNS school-hours scheduling endpoint.** Week 3 ships only the parity matrix + scoped issue. Endpoint implementation is `m` standalone; cross-surface Family Hub demo is `l`. Not this sprint.
6. **Mobile native app.** Out of scope. The audit identifies DNS as `4/10`; the honest move is de-emphasize, not multi-quarter native build.
7. **Adding a 21st strategy item to the top-20 list.** Every shipped feature is a new reason to delay distribution. No new strategy work this sprint. Period.
8. **Norton replacement pitch.** Audit said do not pitch as Norton replacement. Bundle/partner play with Proton + Bitdefender BD + password managers only.
9. **WordPress/Shopify/web-platform integrations.** Adjacent surface, zero validation, infinite work.
10. **A Twitter/X presence, TikTok, YouTube channel, podcast tour.** Pre-MAU marketing is mostly noise. Show HN is the one channel; spend it on the asset.
11. **Custom blocklist UI for power users.** NextDNS owns this. We picked "not competing on this axis" in week 1 reframe.
12. **Acquihire pitch deck deliberately formatted as acquisition material.** Cold-email frame is "distribution partner / OEM tech licensing", per verifier correction. The conversation IS the goal; making the ask too aggressive at zero MAU kills the reply rate.

---

## 90-Day Exit Decision Gate

**Trigger date: 2026-09-27 (90 days from 2026-06-29).**

Calendar event must exist by EOD week 1. Decision criteria committed in writing to `docs/AUDIT_2026-06-29.md` "Exit Trigger" section:

- **MAU < 100 on 2026-09-27** → one of three paths, no fourth:
  - (a) Lifestyle revenue mode: kill SaaS billing, keep engine open-source, no further active dev.
  - (b) Full open-source release + walk away cleanly.
  - (c) Acquihire close: only valid if a week-2 cold-email conversation produced a live BD contact and meeting in the 60-90 day window.
- **MAU 100-1000 on 2026-09-27** → re-evaluate explicitly. Do not auto-grind for another quarter. Verifier caught this: "MAU = 150" cleared the floor under the original proposal, which reproduces the indefinite-grind problem the time-box was supposed to kill.
- **MAU > 1000 on 2026-09-27** → continue with new 90-day target of 10k MAU (the real acquihire-valuation gate per audit).

**Weekly check-in calendar reminders set for 12 weeks.** Each logs the MAU number. Trend data is the actual decision input — single point on day 90 is too brittle.

The credibility-grooming pattern dies on the calendar event. The product either has non-author users or it does not, and 90 days from today the answer becomes a number, not a vibe.

---

**End of roadmap.** Ship week 1 starting Monday 2026-06-30.