# REQUIREMENTS: LinkShield

## Milestone 1 — Chrome Extension + Landing (14 weeks)

### Must-Have

**R1.1** [Phase 1] URL Analysis API:
- POST /check → risk score 0-100, level, reasons. <500ms P95
- Auth: user_id token (from Supabase Auth)
- Rate limiting: server-side by user_id (free: 10 API/day, paid: unlimited)
- Logging: domain + score + timestamp only. NO full URLs, NO page content
- Integrations: Google Safe Browsing, PhishTank, WHOIS, SSL

**R1.2** [Phase 1] On-device Bloom filter:
- Compiled hourly, served via Cloudflare CDN (~2-5MB)
- 95%+ checks resolved locally <1ms
- Free tier: unlimited bloom filter (server limit only on API calls)

**R1.3** [Phase 1] Server Database (Supabase — "boring data" only):
- users: { id, email, auth_provider, created_at }
- subscriptions: { user_id, tier, status, expires_at, provider }
- devices: { user_id, device_hash, platform, last_seen }
- weekly_aggregates: { user_id, week, total_checks, total_blocks, total_trackers }
- families: { id, owner_id, name, created_at }
- family_members: { family_id, user_id, role, joined_at }
- NO tables for: urls_checked, audit_results, score_details, browsing_history

**R1.4** [Phase 2] Chrome Extension (Manifest V3):
- Autoscan all links, visual badges (safe/suspicious/phishing)
- Popup: page summary + threats
- Context menu: "Проверить ссылку"
- Batch API (grouped domains)
- On-device: full history in IndexedDB (URL, score, reasons, timestamp)
- Server receives: domain only for checking. Never full URL.

**R1.5** [Phase 2] Privacy Audit (100% on-device):
- Trackers, sensitive forms, permissions, fingerprinting, cookies → Grade A-F
- Bundled tracker DB (~500KB)
- All results stored on-device only. Never sent to server.
- Free: grade only. Paid: full breakdown.

**R1.6** [Phase 3] Auth + Subscriptions:
- Supabase Auth: Sign in with Apple, Google, email+password
- Stripe: web + mobile web payments
- Apple IAP + Google Play Billing: native mobile payments
- Server stores: user_id, tier, status, expires_at
- Cross-platform: same account works in extension + mobile

**R1.7** [Phase 3] Aha-moment (extension-based):
- Extension scans links on current Gmail/Outlook page
- "LinkShield found 3 suspicious links Chrome missed"
- No Gmail API, no OAuth consent review, works immediately
- Results stored on-device only

**R1.8** [Phase 3] Landing page (linkshield.io):
- Hero: "Your browsing data lives only on your device"
- Pricing, FAQ, Chrome Web Store link
- User accounts for subscription management (Supabase Auth)

**R1.9** [Phase 4] Dashboard:
- Web dashboard (light): account, subscription, devices, family management
- Detailed dashboard (extension popup): history, audit results, transparency counter
- Web shows only server data (account stuff). Extension shows on-device data.

**R1.10** [Phase 4] Weekly Report:
- On-device: generated from local history (full details)
- Server: receives weekly aggregate { total_checks, total_blocks, total_trackers }
- Percentile: computed from server aggregates ("safer than 89% of users") — now real
- Push notification + opt-in email digest

**R1.11** [Phase 4] Security Score:
- Calculated on-device from: 2FA, breach check (k-anonymity), coverage, history
- Score NUMBER sent to server (for cross-device display). Details stay on-device.
- Breach check: k-anonymity (hash prefix → server → local match)

### Should-Have (Milestone 1)

**R1.12** [Phase 4] Firefox extension
**R1.13** [Phase 3] Onboarding tour
**R1.14** [Phase 4] Safari Web Extension

---

## Milestone 2 — Mobile + Family (12 weeks)

### Must-Have

**R2.1** [Phase 5] React Native app + Smart VPN:
- Auto-detect VPN → local VPN or DNS Profile fallback
- Bloom filter on-device, API fallback (domain only)
- Full history in SQLite on-device
- Same Supabase account as extension

**R2.2** [Phase 5] Block screen + push on block

**R2.3** [Phase 6] Family Hub:
- Server manages: family membership (who's in the family)
- Server relays: E2E encrypted alert blobs (can't read content)
- Device handles: encryption/decryption of alert content
- Key exchange: QR (in person) or one-time link + PIN (remote)
- Invite flow: owner invites → server creates membership → key exchanged P2P
- Member removal: owner removes on server + key rotation on devices

**R2.4** [Phase 6] Cross-device sync:
- Via Supabase Realtime: settings, notification prefs, score NUMBER
- NOT synced: check history, audit results, score DETAILS
- New device = fresh history (privacy by design)

**R2.5** [Phase 6] Mobile Privacy Audit + Security Score + Weekly Report

**R2.6** [Phase 7] App Store / Play Store submission

### Should-Have (Milestone 2)

**R2.7** [Phase 7] Widget, QR scanner, Parental mode, Safari Content Blocker

---

## Milestone 3 — B2B (14 weeks)

### Must-Have

**R3.1** [Phase 8] Email proxy:
- In-memory processing, zero disk for email content
- Metadata: timestamp + threat_count + recipient_domain_hash
- SPF/DKIM/DMARC passthrough

**R3.2** [Phase 9] B2B Dashboard:
- Same Supabase DB with org_id field (не отдельная инфраструктура)
- Org views: team threats, phishing sim results, compliance
- Stores: org-level aggregates. NOT individual browsing.
- SSO (SAML/OIDC), bulk deployment

**R3.3** [Phase 9] Phishing Simulation:
- Templates, campaigns, tracking, micro-training
- Results per-org in same DB

**R3.4** [Phase 10] Public API + SDKs + Slack/Teams bots

---

## Server vs Device — Data Map

| Data | Server | Device | Why |
|---|---|---|---|
| Email, auth | Yes | Cached | Account management |
| Subscription | Yes | Cached | Cross-platform billing |
| Device list | Yes | — | Multi-device sync |
| Family membership | Yes | Cached | Family management |
| Weekly aggregates | Yes (numbers) | Full detail | Percentile computation |
| Security Score | Number only | Full breakdown | Cross-device display |
| Settings | Yes | Yes | Sync across devices |
| URL check history | NO | Yes | Privacy: browsing behavior |
| Privacy Audit results | NO | Yes | Privacy: site profiling |
| Tracker encounter log | NO | Yes | Privacy: surveillance data |
| Score factors/details | NO | Yes | Privacy: security profile |
| Family alert content | NO (E2E blob) | Yes (decrypted) | Privacy: family activity |
| Full URLs visited | NEVER | NEVER logged | Not needed, privacy risk |

## Out of Scope

- Антивирус, VPN for encryption, password manager, ad-blocking
- Desktop native app
- Server-side URL history or browsing profiles
- Gmail API integration (extension scanning instead)
