# ROADMAP: LinkShield (Mobile-First)

## Milestone 1: MVP — Backend + Mobile App + Landing (16 weeks)

### Phase 1: Backend — URL Engine + Bloom Filter + DB [3 weeks]
**Goal:** Stateless API <500ms + bloom filter + Supabase "boring database"
- FastAPI: POST /check → score, level, reasons (domain only, zero URL logging)
- Supabase: users, subscriptions, devices, weekly_aggregates, families
- Rate limiting: server-side by user_id (free: 10 API/day)
- Redis: domain→result cache (TTL-based)
- Bloom filter compiler: hourly → .bin → Cloudflare CDN
- Scoring engine: Safe Browsing + PhishTank + WHOIS + SSL
- Deploy: Railway + Redis add-on
- **Status:** In progress (API + DB schema written, tests passing)

### Phase 2: Mobile App — Core + VPN + Block Screen [5 weeks]
**Goal:** "Один тогл — и телефон защищён" на iOS + Android
- React Native (Expo) — iOS + Android из одной кодовой базы
- Smart VPN: no VPN → local VPN; has VPN → DNS Profile
- NEPacketTunnelProvider (iOS) / VpnService (Android)
- Bloom filter on-device (<1ms check), API fallback (domain only)
- Block screen: phishing tap → explanation + "what site wanted"
- Push notifications on block
- Main screen: shield + toggle + stats (checks today, blocks today)
- On-device SQLite: full check history (URLs never leave device)
- **Depends on:** Phase 1

### Phase 3: Auth + Payments + Landing + App Store [4 weeks]
**Goal:** Подписка + публикация + лендинг
- Supabase Auth: Apple, Google (in-app sign in)
- Apple IAP + Google Play Billing
- Stripe Checkout (for web/landing subscribers)
- Landing page (linkshield.io): Next.js 15, privacy-first messaging
- iOS App Store submission (VPN category — submit early, review takes 2-4 weeks)
- Google Play submission + Data Safety
- Freemium: unlimited bloom filter, 10 API/day server-enforced
- Onboarding: "Turn on protection" → one toggle → done
- **Depends on:** Phase 2

### Phase 4: Mobile Features — Score + Report + Family + Aha [4 weeks]
**Goal:** Retention + viral growth + engagement
- **Security Score:** 0-100, on-device calc, k-anonymity breach check
- **Weekly Report:** on-device generation + server percentile + push
- **Aha-moment:** on first launch scan recently opened links (on-device history)
- **Family Hub:** server membership + E2E encrypted alerts
  - QR key exchange (in person) / link + PIN (remote)
  - Family dashboard: devices, threat alerts
- Privacy Audit (mobile browser): when user opens link → audit card
- Settings sync via Supabase Realtime
- **Depends on:** Phase 3

---

## Milestone 2: Browser Extension + Desktop (8 weeks)

### Phase 5: Chrome Extension [3 weeks]
**Goal:** Extension с автопроверкой + Privacy Audit
- Manifest V3 (TypeScript), content script, batch API
- On-device bloom filter (same as mobile, 95% local)
- Visual badges on every link (safe/suspicious/phishing)
- Privacy Audit: trackers, forms, fingerprinting → Grade A-F (100% local)
- Aha-moment: scan links on open Gmail/Outlook page
- Same Supabase account — login once, synced
- Chrome Web Store submission
- **Depends on:** Milestone 1

### Phase 6: Firefox + Safari + Dashboard [3 weeks]
**Goal:** Cross-browser + web dashboard
- Firefox extension (WebExtension API port from Chrome)
- Safari Web Extension (macOS)
- Web dashboard (light): account, subscription, devices, family
- Extension popup (detailed): history, audits, transparency counter
- **Depends on:** Phase 5

### Phase 7: Mobile Extras [2 weeks]
**Goal:** Polish + extra features
- iOS/Android widget (protection status)
- QR code scanner (check link from QR)
- Parental mode (simplified UI for setting up parents)
- Safari Content Blocker (iOS, additional layer)
- **Depends on:** Phase 5

---

## Milestone 3: B2B — Email + Enterprise (14 weeks)

### Phase 8: Email Proxy [4 weeks]
- SMTP: in-memory scan → annotate → forward → purge
- SPF/DKIM/DMARC passthrough
- MX-setup wizard

### Phase 9: B2B Dashboard + Phishing Sim [5 weeks]
- Org dashboard, SSO, bulk deployment
- Phishing simulation: templates, campaigns, tracking, micro-training

### Phase 10: Public API + Integrations [5 weeks]
- REST API, SDKs, Slack/Teams bots, Threat Intelligence feed

---

## Timeline Summary

| Phase | What | Duration | Cumulative |
|---|---|---|---|
| 1 | Backend (API + DB + Bloom) | 3 weeks | Week 3 |
| 2 | Mobile app (VPN + block screen) | 5 weeks | Week 8 |
| 3 | Auth + payments + App Store | 4 weeks | Week 12 |
| 4 | Score + Report + Family + Aha | 4 weeks | Week 16 |
| — | **MVP LAUNCH** | — | **Month 4** |
| 5 | Chrome extension | 3 weeks | Week 19 |
| 6 | Firefox + Safari + dashboard | 3 weeks | Week 22 |
| 7 | Mobile extras | 2 weeks | Week 24 |
| — | **Full consumer product** | — | **Month 6** |
| 8-10 | B2B (email + phishing sim + API) | 14 weeks | Week 38 |
| — | **B2B launch** | — | **Month 10** |
