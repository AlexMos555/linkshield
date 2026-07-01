# Cleanway Privacy

## Summary — what Cleanway can and cannot see

Cleanway checks whether a website is a phishing or scam site. To do that, it looks at the **domain name** of the page you are on — for example `example.com` — and nothing more. It does **not** send the full web address, the path, the query string, the page content, or your browsing history to our servers. Full URLs never leave your device for a safety check; the browser extension extracts only the hostname before making any network call.

There is one important exception you should know up front: if you turn on the **webmail scanner** for Gmail, Outlook, or Yahoo, that feature sends the email's subject, sender, reply-to, and body to our server so it can be analyzed for phishing. Everything else — your link checks, your statistics, your history — stays on your device or is reduced to a domain name before it is sent. This document explains exactly what happens, backed by the code.

## What stays on your device

The browser extension keeps the following locally and never sends it to our servers:

- **Your check history.** Stored in the browser's IndexedDB (`checks` table: domain, score, level, reasons, timestamp) and automatically pruned after **30 days**.
- **Your statistics.** `total_checks`, `threats_blocked`, and `threats_warned` counters live in `chrome.storage.local`. For anonymous (not logged-in) users these are never sent to the server.
- **A per-install device ID.** A random UUID v4 generated on your device. It is not derived from your hardware and contains no fingerprint.
- **Your Family Hub secret key.** Encryption keys stay on the device (extension: `chrome.storage.local`; mobile app: hardware-backed secure storage via `expo-secure-store`). They never leave the device.
- **Honeypot and pwned-password counters.** `credguard_override_count`, `honeypot_used_count`, and `pwned_password_seen_count` are local tallies only. No honeypot usage or fake-password event is logged server-side.
- **Modern-phishing detections.** BitB, tab-napping, and overlay-credential detections increment a local count only; the host is not sent to the server.
- **An in-memory verdict cache.** The extension's background worker caches domain verdicts for 1 hour (max 1000 entries) on-device.

## What the server receives

Cleanway's server receives only what it needs, per request:

- **Domain names — never full URLs.** The authenticated check endpoint (`POST /api/v1/check`) accepts a list of domain strings only. The public endpoint (`/api/v1/public/check/{domain}`) takes a single domain as a path parameter. The DoH gateway (`/dns-query`) handles wire-format DNS queries, which are domain-only by nature. On the authenticated path, the analyzer is never even given the raw URL (it defaults to an empty string).
- **A user ID — only on authenticated endpoints.** Anonymous link checks carry no user identity; the extension does not send an auth token with public checks.
- **An email domain — only for pre-signup checks.** The `/check-email` flow receives the domain portion of an email, not the full address.
- **Your client IP — used for rate limiting.** Extracted from the request (`request.client.host`, or `X-Forwarded-For` behind a trusted proxy) to enforce request limits (public checks are capped at 60 requests/hour per IP; a tighter sub-limit throttles expensive fresh-domain analyses). It is **not stored raw**; when an action is written to the audit log, the IP is first hashed.
- **A hashed IP — for the audit log.** IPs are hashed with **HMAC-SHA-256** (keyed with the server secret) and truncated to 16 hex characters (64 bits) before storage. Caveat: 64 bits is enough to correlate rate-limit activity but is weaker than a full 128-bit hash.
- **A device hash — for optional device-level settings and Family Hub.** The random UUID described above.
- **Aggregated usage counters.** Lifetime and weekly threat counts per user, for freemium limits — numbers only, no domains.

### The webmail exception

If you enable the webmail scanner, the extension sends the email's **subject, sender, reply-to, and body (text and HTML)** to `POST /api/v1/email/analyze`. This is the one feature where page content leaves your device. It applies only to Gmail, Outlook, and Yahoo webmail and only when the feature is active. Subject lines and bodies can contain sensitive context, so treat this as an explicit trade-off you are opting into.

## What we store, and for how long

| Data | Where | Retention |
|---|---|---|
| Domain + verdict + score (cache) | Redis (server) | 5 min (dangerous) / 15 min (suspicious) / 1 hr (safe); public endpoint 24 hr |
| Domain + ML feature vector + timestamp | Local `feature_log.jsonl` file (server) | **No retention policy in code** — see caveat below |
| User ID + action + target + hashed IP + metadata | Supabase `audit_log` | 2 years (730 days), purged by `purge_old_audit_log` |
| User ID + email | Supabase `users` | Until account deletion |
| User ID + subscription tier + Stripe customer ID | Supabase `subscriptions` | Until account deletion |
| Device hash + device settings | Supabase `devices` | Until account deletion |
| User whitelist domains | Redis set `whitelist:{user_id}` | 1 year (365-day TTL, refreshed on each add) |
| Weekly threat aggregates (counts only) | Supabase `weekly_aggregates` | 1 year, then deleted |
| Family alert ciphertext + nonce + sender pubkey | Supabase `family_alerts` | 30 days (`ALERT_DEFAULT_TTL_DAYS = 30`); see caveat |
| Family public keys (32-byte curve25519) | Supabase `family_member_keys` | No TTL (needed to route encrypted alerts) |
| Family invite: SHA-256 code hash + bcrypt PIN hash | Supabase `family_invites` | Until redeemed or 7-day expiry |
| Deletion flag (soft-delete) | Redis | 30-day grace period before hard delete |
| Extension check history | Device (IndexedDB) | 30 days, auto-pruned |

**Feature-log caveat (honest disclosure):** The training feature log (`feature_log.jsonl`) records the domain name, the analysis score, and the ML feature vector to disk. The code contains **no TTL or purge mechanism** for this file — unlike the audit log, which has a 2-year purge. How long it lives depends on deployment/ops configuration, not on the application code. We disclose this because it is a real gap between "domain-only, transient" and what the code guarantees.

**Family-alert retention caveat:** The code sets a **30-day** expiry on family alerts (`expires_at = now() + 30 days`). An earlier version of our published policy referenced 7 days; the code implements 30. A database migration includes a commented-out 7-day cleanup job, but the code does not show an active cron enforcing it, so alerts should be assumed to persist for up to 30 days server-side (as ciphertext the server cannot read — see Family Hub encryption).

## What we never collect

- **Full URLs, paths, or query strings.** The system is domain-only end to end. No database table anywhere stores check history with URLs (verified across all migrations).
- **Your browsing history** as a server-side record. Cached verdicts are transient (max 1 hour on the hot path).
- **Page content, HTML, DOM, or screenshots** — except the webmail body described above, which is an explicit opt-in feature.
- **Search queries** or activity outside domain safety checks.
- **Credit card data.** Payments go directly to Stripe; card data is never stored on our servers.
- **Plaintext passwords, ever.** The pwned-password check sends only the first 5 hex characters of a SHA-1 hash (k-anonymity); the full hash is discarded after the local match. The honeypot feature replaces a password with a random string client-side before any form submits.
- **Raw client IP addresses in storage.** IPs are hashed before they reach the audit log.
- **Geolocation.**
- **Server-derived device fingerprints.** The only device identifier is the random UUID your own client generates.
- **Third-party analytics on the extension.** The extension integrates no analytics, no telemetry, and no Sentry of its own. The landing page loads no Google Analytics, gtag, or tracking pixels.
- **The email-breach (HIBP) check** is currently disabled — it returns a "coming soon" message and queries nothing.

## Third parties

Cleanway shares data with a small number of processors, each getting only what its job requires:

- **Stripe (payments).** Receives your email address and the selected plan (and your user ID as metadata) at checkout, to process payment. Stripe handles card data directly; we never see or store it.
- **Supabase (database + auth).** Stores your account: email, subscription tier, device settings, family metadata, and the encrypted family ciphertexts. Row-Level Security restricts each row to its owner.
- **Sentry (error tracking).** Receives crash/error reports. The **backend** scrubber (`sentry_scrubber.py`) redacts `domain`, `raw_url`, `url`, and `hostname` from events before they are sent, and hashes user IDs (SHA-256) so users are not directly identifiable. Sentry retains events for up to 90 days with employee read access.
  - All three Sentry surfaces now redact browsing context: the **backend** (`sentry_scrubber.py`), the **landing site** (`landing/lib/sentry-scrub.ts`), and the **mobile app** (`mobile/src/lib/sentry-scrub.ts`) all include `domain`, `raw_url`, `url`, and `hostname` in their always-redact key sets, so a domain that lands in a breadcrumb or extra field is stripped before the event is sent.
  - Note also that the backend scrubber only redacts keys it expects; new logging code that placed a domain under an unexpected key name could leak it. Domains are additionally passed to Sentry-attached logs at several backend call sites, which is why the `before_send` redaction is the load-bearing control.
- **Threat-intelligence providers.** To decide if a domain is dangerous, the server sends the **domain name** (no full URL, no user identity, no page context) to external checkers: Google Safe Browsing, PhishTank, URLhaus, PhishStats, ThreatFox, Spamhaus DBL, SURBL, AlienVault OTX, and IPQualityScore. This is inherent to how safety checks work — see "Server-blind design" below. You should review those providers' own privacy policies.
- **Anthropic (LLM judge / scam explainer), when configured.** The LLM judge sanitizes its input before sending, explicitly dropping the `domain`, `url`, and `raw_url` fields; only abstract signals are sent. The scam explainer sends up to 20 signal types plus a locale code, not the domain.

## Family Hub encryption

Family Hub lets family members warn each other about dangerous sites. Those alerts are **end-to-end encrypted**:

- Alerts are encrypted **on your device** using **curve25519 + XSalsa20-Poly1305** (NaCl `box`) before being sent.
- Each alert is encrypted separately to each recipient's public key. The server stores one row per recipient, holding **only the raw ciphertext bytes (`BYTEA`), the nonce, and the sender's public key**. The server never holds a decryption key and never decrypts.
- **Secret keys never leave the device** (extension: `chrome.storage.local`; mobile: `expo-secure-store` hardware-backed storage). Only 32-byte public keys are uploaded (`family_member_keys`).
- Invitation codes are **SHA-256** hashed server-side; PINs are **bcrypt** hashed (12 rounds). The raw code and PIN are shown once, to the inviter, and never stored in the clear.
- Row-Level Security limits each alert to its intended recipient, not the whole family.

**What the server can still infer:** Because it routes the envelopes, the server can see **metadata** it cannot avoid — who sent an alert to whom, when, the family ID, and a plaintext alert-type label (defaulting to a single neutral value). It cannot read the alert's contents. The full family roster is also visible to every member of that family. So the accurate statement is: *the server stores only the ciphertext and cannot decrypt it, but it does see routing metadata.*

## Server-blind design

The core invariant is: **the server sees the domain, not your browsing.** The extension extracts the hostname from each URL locally and sends only that. No full URL, path, or query string reaches the server on the check path; no per-user check history is stored in any database.

We are precise about one thing that is easy to overstate: "server-blind" does **not** mean the domain stays on your device. To check whether a domain is malicious, the server sends that **domain name** to external threat-intelligence services (Google Safe Browsing and the others listed above). What is *not* sent to them is your identity, your full URL, or any page context — only the bare domain, the same way a DNS resolver sees it. So the honest framing is: the domain of a site you visit is checked against third-party blocklists; who you are and what you did on that site are not part of that check.

Two operational logs do record domain names for legitimate reasons, and we disclose them rather than hide them: the ML **feature log** (see retention caveat above) and the **DoH gateway**, which logs only the last 32 characters of a blocked query name to structured logs. Neither is linked to user identity. Redis cache keys are also plaintext domain names, readable by anyone with direct Redis access — which is why that access is restricted.

## Your rights (GDPR)

- **Export and deletion.** You can request account deletion; it enters a **30-day grace period** (soft-delete) before the data is permanently removed, giving you time to cancel.
- **Data minimization by design.** For anonymous use, no account, email, or identity is collected at all — you can use link protection with no sign-up.
- **What's tied to you vs. not.** Only authenticated endpoints attach a user ID. Public checks are anonymous. IPs used for rate limiting are hashed before any long-lived storage.

If you have a privacy request or question, contact us and reference this document.

## Footer

This document describes the code as of **2026-07-01** (main branch). Generated with a code-grounded workflow whose every claim was adversarially verified against the source. Retention windows, hashing choices, and data flows above are drawn directly from the source and are intended to be auditable. The detection engine is open to inspection — see the benchmark methodology and open-source plan (`docs/OPEN-SOURCE.md`) for how to verify these claims against the code and against head-to-head accuracy results. If you find any statement here that the code does not support, that is a bug in this document; please report it.