# STATE: LinkShield

## Current Position
- **Milestone:** 1 (MVP — Chrome Extension)
- **Phase:** Pre-Phase 1 (Architecture finalized)
- **Status:** Ready to build

## Key Decisions

### Architecture: "Boring Database" (FINAL)
Server stores account data (boring if leaked). Device stores behavior data (sensitive, never leaves).

**Server (Supabase):**
- users, subscriptions, devices, families, family_members
- weekly_aggregates (total_checks, total_blocks — numbers only)
- security_score (number only, not breakdown)
- settings (synced across devices)

**Device (SQLite / IndexedDB):**
- Full URL check history with details
- Privacy Audit results per site
- Security Score factors and breakdown
- Weekly Report raw data
- Tracker/fingerprinting encounter log
- Family alert content (E2E encrypted)

**Rule:** server knows WHO. Device knows WHAT. Browsing behavior never leaves device.

**Breach scenario:** attacker gets emails + subscription status + "checked 2847 links this week." No URLs, no audits, no browsing profile.

### Auth & Payments
- **Auth:** Supabase Auth (Apple, Google, email+password)
- **Web payments:** Stripe
- **Mobile payments:** Apple IAP + Google Play Billing (+ Stripe fallback)
- **B2B:** Stripe Invoicing
- **Cross-platform:** same account, login once

### Tech Stack
- **Backend:** FastAPI — URL analysis (logs domain+score, never full URL)
- **Edge:** Cloudflare Workers — bloom filter CDN + URL check
- **Database:** Supabase (PostgreSQL + Auth + Realtime)
- **Payments:** Stripe + Apple IAP + Google Play
- **On-device:** SQLite (mobile), IndexedDB (extension)
- **Sync:** Supabase Realtime (settings + aggregates)
- **Family relay:** Supabase Realtime + E2E encryption
- **Extension:** TypeScript, Manifest V3
- **Mobile:** React Native
- **Landing:** Next.js 15

### What this architecture unlocks
1. Cross-device sync (settings + aggregates)
2. Real percentile in Weekly Report (server aggregate)
3. Simpler Family Hub (server membership + E2E content)
4. Normal customer support (user has account)
5. Opt-in email marketing (we know email)
6. Server-enforced free tier (real rate limit by user_id)
7. B2B on same infrastructure (add org_id)
8. Stripe for everyone (simpler billing)

### Privacy messaging
"Your browsing data lives only on your device. Our servers know your account — not what you do online. Even if we're breached, attackers learn nothing about your online life."

### Pricing
| Tier | Price | Server data | Device data |
|---|---|---|---|
| Free | $0 | Account + aggregates | Full history + audit |
| Personal | $4.99/mo | Account + aggregates | Full history + audit |
| Family | $9.99/mo | + family membership | + E2E alert content |
| Business | $3.99/user/mo | + org aggregates | + employee device data |

## Blockers
- [ ] Домен linkshield.io
- [ ] Supabase project setup
- [ ] Google Safe Browsing API key
- [ ] Apple Developer account ($99/yr)
- [ ] Google Play Developer account ($25)
- [ ] Stripe account
- [ ] Cloudflare Workers account
- [ ] Firebase project (push notifications)

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Apple VPN review | 2-4 weeks | DNS Profile fallback |
| VPN conflict (~30% mobile) | Can't use local VPN | Smart auto-detection → DNS |
| Server breach | Email + subscription exposed | No browsing data on server — boring leak |
| Extension Aha-moment limited | Only open emails scanned | Still effective, add Gmail API later |
| B2B compliance | SOC 2 questions | Minimal server data = minimal scope |
| Supabase vendor lock-in | Migration pain | Standard PostgreSQL, can self-host |

## Open Questions
- [ ] Название: LinkShield или ребрендинг?
- [ ] Anonymous telemetry: opt-in anonymous aggregate for product analytics?
- [ ] Safari extension: M1 or M2?
- [ ] Gmail API for deeper Aha-moment: pursue after V1 launch?

## Session Log
- **S1:** Концепция: автоматическая защита. Extension → mobile → email proxy.
- **S2:** Конкурентный анализ V1. GSD-план V1.
- **S3:** Мокапы. Privacy architecture (bloom filter, domain-only).
- **S4:** +Aha-moment, Weekly Report, Security Score, Family Hub, VPN conflict, Phishing Sim.
- **S5:** Конкурентный анализ V2: 13 конкурентов, 6 гэпов подтверждены.
- **S6:** Zero-storage architecture. Убрана база пользователей.
- **S7:** Honesty audit: 7 проблем найдены и исправлены.
- **S8:** "BORING DATABASE" — вернули серверную базу, но только для account data. Browsing behavior остаётся на устройстве. Решены: sync, percentile, Family Hub, support, free tier enforcement, B2B same infra, Stripe for all. Архитектура финализирована.
