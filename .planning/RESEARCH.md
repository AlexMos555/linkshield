# RESEARCH: LinkShield — Technical Architecture (Final)

## "Boring Database" Architecture

### Principle
Server knows WHO you are (account). Device knows WHAT you do (behavior).
If server is breached: attacker gets emails + subscription status. Not a single URL.

### Server Schema (Supabase PostgreSQL)

```sql
-- Account (boring)
users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE,
  auth_provider TEXT, -- apple, google, email
  created_at TIMESTAMPTZ DEFAULT now()
)

-- Subscription
subscriptions (
  user_id UUID REFERENCES users(id),
  tier TEXT, -- free, personal, family, business
  status TEXT, -- active, cancelled, expired
  provider TEXT, -- stripe, apple_iap, google_play
  provider_id TEXT, -- stripe session / IAP receipt
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (user_id)
)

-- Devices (for sync + rate limiting)
devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  device_hash TEXT, -- anonymous device fingerprint
  platform TEXT, -- chrome_ext, firefox_ext, ios, android
  app_version TEXT,
  last_seen TIMESTAMPTZ
)

-- Weekly aggregates (for percentile computation — NUMBERS ONLY)
weekly_aggregates (
  user_id UUID REFERENCES users(id),
  week DATE, -- Monday of the week
  total_checks INTEGER DEFAULT 0,
  total_blocks INTEGER DEFAULT 0,
  total_trackers INTEGER DEFAULT 0,
  score INTEGER, -- Security Score number (not breakdown)
  PRIMARY KEY (user_id, week)
)

-- Family
families (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES users(id),
  name TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
)

family_members (
  family_id UUID REFERENCES families(id),
  user_id UUID REFERENCES users(id),
  role TEXT, -- owner, member
  joined_at TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (family_id, user_id)
)

-- Family alerts (E2E encrypted — server stores ciphertext)
family_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  family_id UUID REFERENCES families(id),
  sender_device_hash TEXT,
  encrypted_payload BYTEA, -- E2E encrypted, server can't read
  created_at TIMESTAMPTZ DEFAULT now()
  -- TTL: auto-delete after 7 days via Supabase cron
)

-- B2B (same DB, org-level)
orgs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT,
  admin_user_id UUID REFERENCES users(id),
  sso_config JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
)

org_members (
  org_id UUID REFERENCES orgs(id),
  user_id UUID REFERENCES users(id),
  role TEXT,
  PRIMARY KEY (org_id, user_id)
)

-- Phishing simulation (B2B)
phishing_campaigns (
  id UUID PRIMARY KEY,
  org_id UUID REFERENCES orgs(id),
  template_id TEXT,
  sent_at TIMESTAMPTZ,
  total_sent INTEGER,
  total_clicked INTEGER,
  total_reported INTEGER
)

-- Settings (synced across devices)
user_settings (
  user_id UUID REFERENCES users(id),
  settings JSONB, -- sensitivity, notifications, theme
  updated_at TIMESTAMPTZ,
  PRIMARY KEY (user_id)
)
```

**What is NOT in this schema:** url_history, audit_results, score_breakdown, tracker_log, browsing_profile. These live on-device only.

### On-Device Schema

```sql
-- SQLite (mobile) / IndexedDB (extension)

-- Full check history (SENSITIVE — never leaves device)
checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT, -- FULL URL (only stored locally)
  domain TEXT,
  score INTEGER,
  level TEXT, -- safe, caution, dangerous
  reasons TEXT, -- JSON array
  source TEXT, -- bloom_filter, api
  checked_at INTEGER -- unix timestamp
)
-- Index: checked_at DESC. Retention: 30 days rolling.

-- Privacy Audit results (SENSITIVE)
audit_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT,
  grade TEXT, -- A through F
  trackers_count INTEGER,
  tracker_names TEXT, -- JSON array
  has_fingerprinting INTEGER, -- boolean
  has_sensitive_forms INTEGER,
  permissions_requested TEXT, -- JSON: geolocation, camera, etc
  cookies_first INTEGER,
  cookies_third INTEGER,
  scanned_at INTEGER
)

-- Security Score details (SENSITIVE)
score_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  score INTEGER,
  factors TEXT, -- JSON: { "2fa": +15, "breach": -15, ... }
  tips TEXT, -- JSON array of improvement tips
  calculated_at INTEGER
)

-- Tracker encounter log (SENSITIVE)
tracker_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT, -- site where tracker was found
  tracker_name TEXT,
  tracker_category TEXT, -- analytics, advertising, fingerprint
  seen_at INTEGER
)

-- Family alert content (decrypted locally)
family_alerts_local (
  id TEXT PRIMARY KEY,
  sender_name TEXT,
  alert_type TEXT, -- phishing_blocked, suspicious_link
  domain TEXT,
  details TEXT, -- JSON
  received_at INTEGER
)
```

### Data Flow Diagram

```
USER ACTION                     ON-DEVICE                    SERVER
─────────────                   ─────────                    ──────
Click link in WhatsApp ──→ Bloom filter check (<1ms)
                          ├─ Known safe → Allow              (nothing)
                          ├─ Known bad → Block               (nothing)
                          └─ Unknown → ─────────────────────→ /check {domain}
                                                              ├─ Check Safe Browsing
                                                              ├─ Check PhishTank
                                                              ├─ WHOIS + SSL
                                                              ├─ Score → return
                                                              └─ Log: domain+score
                             ← {score, level, reasons} ──────┘
                             Store in local checks table      (nothing stored)
                             If blocked → show block screen

Visit website ──────────→ Privacy Audit (DOM scan)
                          ├─ Count trackers
                          ├─ Detect forms
                          ├─ Check permissions
                          ├─ Detect fingerprinting
                          └─ Store in audit_results           (nothing — 100% local)

End of week ────────────→ Generate Weekly Report
                          ├─ Query local checks table
                          ├─ Compute stats
                          ├─ Send aggregate ─────────────────→ weekly_aggregates
                          │  {total_checks: 2847,              (numbers only)
                          │   total_blocks: 3,
                          │   total_trackers: 87}
                          ← percentile rank ─────────────────┘
                          Show report with "safer than 89%"

Family alert ───────────→ Encrypt alert content
                          ├─ E2E encrypt (AES-256)
                          └─ Send blob ──────────────────────→ family_alerts
                                                               (encrypted_payload)
                             Receiving device fetches blob     (can't read it)
                          ← Decrypt locally
                          Show: "Mom's phone blocked phishing"
```

### URL Check API

```
POST /api/v1/check
Headers: { Authorization: "Bearer <supabase_jwt>" }
Body: { domains: ["paypa1-verify.com", "google.com"] }

Flow:
  1. Validate JWT → get user_id
  2. Check rate limit (free: 10/day, paid: unlimited)
  3. For each domain:
     a. Redis cache? → return cached
     b. Parallel: Safe Browsing + PhishTank + WHOIS + SSL
     c. Score aggregation → 0-100
     d. Cache in Redis (TTL: 1h safe, 15min suspicious)
  4. Return [{ domain, score, level, reasons }]
  5. Log: domain + score + timestamp (for bloom filter improvement)
     NOT logged: user_id, IP, full URL, referer

Rate limit: by user_id in Redis (INCR + EXPIRE)
```

### Scoring Model

| Signal | Weight |
|---|---|
| Google Safe Browsing hit | +80 |
| PhishTank hit | +70 |
| Domain age < 7 days | +50 |
| Domain age < 30 days | +30 |
| IP-based URL | +35 |
| Typosquatting patterns | +25 |
| No HTTPS | +40 |
| Free SSL + new domain | +20 |
| Missing security headers | +15 |
| Known top-10K domain | -50 |

0-20 Safe / 21-50 Caution / 51-100 Dangerous

### E2E Family Hub

```
Key Exchange:
  IN PERSON: QR code (AES-256 key displayed → scanned)
  REMOTE: one-time link (15min TTL, key in URL fragment) + PIN via SMS/call

Alert Flow:
  Device encrypts: AES-256-GCM(family_key, alert_json) → ciphertext
  Upload to Supabase: family_alerts { family_id, encrypted_payload }
  Push to family devices via Firebase
  Receiving device: fetch blob → decrypt → display

Server sees: family_id + encrypted blob + timestamps
Server CANNOT see: domain names, threat types, alert details

Member removal:
  Owner removes member in app → server deletes from family_members
  Owner generates new key → distributes to remaining members via QR/link+PIN
  Old blobs remain encrypted with old key (acceptable: they expire in 7 days)
```

### Mobile VPN Architecture

```
App launch → detect VPN:
  ├─ No VPN → Mode A: Local VPN
  │   NEPacketTunnelProvider (iOS) / VpnService (Android)
  │   DNS-only interception → bloom filter → API fallback
  │
  ├─ VPN active → Mode B: DNS Profile
  │   iOS: Configuration Profile → DoH to our resolver
  │   Android: Private DNS → DoT to our resolver
  │   Works alongside NordVPN, ExpressVPN, etc.
  │
  └─ Safari (iOS additional) → Mode C: Content Blocker
      JSON rules from bloom filter, Safari-only
```

### Percentile Computation

```
Weekly cron job on server:
  SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total_blocks)
  FROM weekly_aggregates
  WHERE week = current_week();

  → Generates percentile brackets: [p10, p25, p50, p75, p90]
  → Cached as public JSON on CDN

Client computation:
  My total_blocks = 3
  Fetch percentile brackets from CDN
  3 blocks > p75 (1 block) → "safer than ~80% of users"
  
Privacy: individual user's aggregate is one row among thousands.
Percentile brackets are anonymous (no per-user data in CDN JSON).
```

### Security Score (on-device calc, number synced)

```
Base: 50
+ 15: 2FA on email (user self-reports or detected via OAuth scope)
+ 10: Email not in breaches (k-anonymity check)
+ 10: Protection active on all devices
+  5: Family members protected
+  5: Extension + mobile both active
+  5: No phishing clicks in 30 days
- 15: Email in breaches
- 10: Clicked phishing recently
- 10: Not on all devices
-  5: No 2FA

Device calculates full score with all factors.
Server receives: score NUMBER only (e.g., 73).
Server does NOT receive: factor breakdown, breach details, click history.
```

## Competitive Summary

13 конкурентов analyzed (see COMPETITIVE-ANALYSIS.md).
6 confirmed market gaps. No competitor has boring-database architecture where browsing behavior stays on-device while providing full product functionality.

Closest comparison: Apple's approach with Health data (processed on-device, iCloud encrypted). We apply the same philosophy to browsing security.
