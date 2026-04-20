# Phase H — Scam protection architecture

Scope of Phase H: expand LinkShield beyond link/domain reputation into
**interactive scam channels** — phone calls, SMS, pasted messenger
conversations, voice recordings.

Privacy spine (all H-features inherit):

- **Raw content never stored.** Phone numbers: SHA-256 hashed. Bodies:
  features only (reason codes, domains, risk score). Voice files:
  transcribed + discarded immediately.
- **User-initiated.** No passive listening, no automatic call recording.
  Every analysis is triggered by a user action — a share-sheet drop, a
  "report this call" tap, a "analyze this message" paste.
- **On-device first, server-augmented.** Domain lookups, LLM classification
  happen server-side; pattern matching, redaction, and UI ranking happen
  on-device so the server only sees what's absolutely necessary.

---

## H₁ — Caller ID + pre/post-call tips

Shows a verdict **before the user answers** an incoming call ("⚠️ Reported
as scam 142 times") and an educational prompt **after hangup** ("Did they
ask for a password? Report →").

Components:

| Piece | Location | Notes |
|---|---|---|
| iOS Call Directory Extension | `mobile/native/ios/CallDirectory/` (to-create) | `CXCallDirectoryExtension` — provides labels to iOS native Phone UI |
| Android CallScreeningService | `mobile/native/android/CallScreen.kt` (to-create) | API 24+. Returns allow/block + label |
| Shared hash utility | `mobile/src/services/phone-hash.ts` | `normalizeE164` + `sha256` — used for reporting + lookup |
| Hash-lookup endpoint | `GET /api/v1/phone/lookup/{hash}?cc=RU` | Public, IP-rate-limited |
| Post-call survey screen | `mobile/app/call-reflect.tsx` (to-create) | Triggered by `CXCallObserver` / `PhoneStateListener` on disconnect |
| Pre-call tip modal | `mobile/app/call-tip.tsx` (to-create) | Only in Granny/Kids modes; triggers on outgoing-call intent |

Build order:

1. **API first**: `/phone/lookup` + `/phone/report` endpoints against the
   new `phone_reports` + `verified_numbers` tables.
2. **Shared hash util**: `normalizeE164(raw, country) -> string` that matches
   how iOS/Android normalize for hashing. Covered by fixtures for the 10
   launch locales.
3. **Android CallScreeningService**: quickest return on investment — API
   surface is stable, `Settings.ACTION_MANAGE_DEFAULT_CALL_SCREEN` prompt
   is standardized.
4. **iOS Call Directory**: requires App Group + separate bundle. Non-trivial
   setup but mechanical once the shared hash util is proven.

Blockers before we start building H₁:

- [ ] Verify App Store policy around Call Directory extensions with paid
      tiers. (Truecaller / RoboKiller are precedent — it's fine.)
- [ ] Decide country scope for MVP. Russia + US + UK = 90 % of our
      addressable market.

---

## H₂ — Crowd-source + verified number DB

The data layer that makes H₁ actually useful. Two tables (see
`migrations/005_scam_protection.sql`):

- `phone_reports` — (hash, country) → (scam/spam/legit counts, tag
  histogram). Grows from H₁ reports + extension/mobile "report scam" flows.
- `verified_numbers` — operator-curated allowlist. Seeded from bank
  "contact us" pages, government directories, mobile operator docs.

Seeding plan (manual Week 1 of Phase H):

```
scripts/seed_verified_numbers.py <country_code> <csv>
```

CSV format: `display_number,org_name,org_category,source_url`.
Seeds per country (MVP):

- 🇷🇺 RU: Сбербанк, ВТБ, Тинькофф, Альфа, Россельхозбанк, Газпромбанк,
  ФНС, Пенсионный Фонд, МВД, МТС, Билайн, Мегафон, Теле2, Почта России
- 🇺🇸 US: Chase, BofA, Wells Fargo, Citi, IRS, SSA, USPS, Verizon, AT&T, T-Mobile
- 🇬🇧 UK: Barclays, HSBC, NatWest, Lloyds, HMRC, DVLA, Royal Mail, BT, EE, Vodafone

Keep `source_url` populated — auditability matters more than volume.

---

## H₃ — SMS phishing scanner

iOS: `ILMessageFilterExtension` (IdentityLookup framework). The system
passes SMS from unknown senders to the extension; extension classifies
and returns `.junk` / `.promotion` / `.transaction` / `.none`.

Android: app becomes default SMS app (one option) OR uses `SmsRetriever` +
notification listener (less invasive, less reliable). MVP: default-SMS-app
opt-in; keep it optional since replacing the default SMS handler is a big
ask.

Pipeline:

```
incoming SMS
  ↓ (platform extension)
local heuristic scorer (same regex patterns as email_analyzer body scan)
  ↓ score ≥ 40
POST /api/v1/sms/analyze {sender_hash, body_hash, domains, pattern_tags}
  → backend re-scores using GSB + ML
  ← verdict: safe | suspicious | scam
  ↓
native platform API: classify message; emit notification in Granny mode
```

What NEVER leaves the device: the SMS body text, phone numbers in
plaintext. What DOES leave: SHA-256 of sender, domains (bare), matched
pattern tags, risk score.

---

## H₄ — Scam pattern detection (LLM-assisted)

The product dif — users paste a conversation / share a voice note / send
us a screenshot, and we explain *why* it looks like a scam. Patterns we
detect:

- Pig-butchering romance → investment
- Fake delivery / customs fees (smishing)
- Tech support impersonation (Apple/Microsoft)
- Crypto investment scams ("guaranteed returns")
- Government impersonation (IRS/ФНС/HMRC)
- Job scam / fake recruiter
- Fake inheritance / lottery

### Pipeline

```
input (text | audio | image)
  ↓
Share sheet → mobile/app/share-*.tsx or web → paste form
  ↓
Client-side redaction — mask credit card numbers, IBANs, phone numbers
  ↓
POST /api/v1/scam/analyze_text  | /analyze_voice  | /analyze_image
  ↓ (server)
Voice: Whisper STT → transcript (English + 10 launch languages)
Image: OCR → extracted text
Text: used as-is
  ↓
LLM classifier (Claude Haiku / Sonnet via Anthropic API)
  Prompt: classify + score + reason_codes
  ↓
Persist {user_id, verdict, risk_score, reason_codes, language, country_code}
to `scam_analyses` (NOT the raw input)
  ↓
Return structured verdict to client
```

### External services required

- **Anthropic API key** — for LLM classification. `ANTHROPIC_API_KEY`
  env var. Cost: Haiku ~ $0.25/1M input tokens. Voice analyses cluster
  around 1-3k tokens → ~$0.001/analysis.
- **Whisper API** — OpenAI's `whisper-1` or `openai/whisper` via
  cloud-hosted instance. `OPENAI_API_KEY`. Cost: $0.006/minute of audio.
- **Tesseract** or cloud OCR (Google Vision, AWS Textract) — for image
  path. Deferrable to post-launch.

### Prompt engineering principles

- **Language-stable**: the prompt is in English but the user's input can
  be in any of the 10 launch languages. Claude handles this natively;
  response's `reason_codes` come back in English (enum).
- **Structured output**: JSON schema enforced via `response_format` so
  we never parse prose for critical fields.
- **Deterministic reason codes**: a fixed enum of ~20 codes. The UI maps
  each code to localized human-readable explanations, so adding languages
  doesn't touch the backend.

---

## Voice file analysis — legal + technical notes

### Legal (re-confirm before launch)

The user records the call with the **platform recorder** (iPhone Voice
Memos via conference call, Samsung/Pixel/Xiaomi built-in call recording,
or just speakerphone + external recorder). LinkShield **never** records
anything itself.

This keeps us out of the "wiretapping" legal bucket. We're an analyzer
of files the user already possesses. Equivalent to the user emailing
themselves a recording for later review.

Caveat: if the user shares a recording they made WITHOUT consent of the
other party, **that** is the user's legal problem, not ours. Our share
sheet copy must include a reminder:

> "LinkShield analyzes recordings you make. Laws about recording calls
> vary by country — check local laws before recording."

### Technical

- **Accepted formats**: `.m4a`, `.mp3`, `.wav`, `.amr`, `.3gp`, `.aac`,
  `.ogg`. Max file size: 25 MB (Whisper limit).
- **Max duration**: 10 minutes hard cap at the API layer — longer
  recordings are rare for scam calls and would push latency/cost.
- **Transcription language**: auto-detect via Whisper; override possible
  if user picks in the UI.
- **Retention**: transcript held in-memory for the duration of the LLM
  call, then discarded. Only the structured verdict persists.

---

## Build sequence (post-Phase-G)

Week 1: H₂ data layer + seed verified numbers (mechanical, parallelizable)
Week 2–3: H₃ SMS scanner — Android default-SMS-app flow + iOS
           `ILMessageFilterExtension`
Week 4–5: H₁ Android CallScreeningService — quicker path to first demo
Week 6–7: H₁ iOS Call Directory Extension — slower path
Week 8–13: H₄ scam pattern detection — prompt engineering, eval harness,
           multi-language coverage, voice pipeline, share-sheet targets

---

## Open questions

1. **Freemium boundary for H₄**. LLM calls cost real money. Options:
   (a) 5 free analyses/mo on Free tier; (b) premium-only from day 1.
   Leaning (a) — we want the "ahaa" moment while guest.
2. **H₃ on Android**: do we push hard for default-SMS-app status? It's
   a huge UX ask. Alternative: passive notification listener (works only
   if the user grants `BIND_NOTIFICATION_LISTENER_SERVICE`, but doesn't
   block SMS delivery).
3. **Apple Sign In dependency**. H₄ requires sign-in for quota tracking;
   Apple Sign In is mandatory on iOS if we offer any auth. Need to land
   before H₄ launch.
4. **Crowd-source quality**. Bad actors can poison `phone_reports` by
   reporting legitimate numbers en masse. Mitigations: (a) require sign-in
   to report, (b) rate-limit per user per day, (c) weight reports by
   account age. See `api/routers/phone.py` when implementing.
