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

The Android app has its own on-device data and its own message check; see [The Android app](#the-android-app) below.

## What the server receives

Cleanway's server receives only what it needs, per request:

- **Domain names — never full URLs.** The authenticated check endpoint (`POST /api/v1/check`) accepts a list of domain strings only. The public endpoint (`/api/v1/public/check/{domain}`) takes a single domain as a path parameter. The DoH gateway (`/dns-query`) handles wire-format DNS queries, which are domain-only by nature. On the authenticated path, the analyzer is never even given the raw URL (it defaults to an empty string).
- **A user ID — only on authenticated endpoints.** Anonymous link checks carry no user identity; neither the extension nor the mobile app sends an auth token with public checks (the shared API client strips it from `/api/v1/public/check`, even for a signed-in person).
- **An email domain — only for pre-signup checks.** The `/check-email` flow receives the domain portion of an email, not the full address.
- **Your client IP — used for rate limiting.** Extracted from the request (`request.client.host`, or `X-Forwarded-For` behind a trusted proxy) to enforce request limits (public checks are capped at 60 requests/hour per IP; a tighter sub-limit throttles expensive fresh-domain analyses). The limiter keeps the IP **as is** in Redis counter keys — `rate:ip:{category}:{ip}` (`rate_limiter.check_ip_rate_limit`, TTL = the window, 3600 s by default for public, DoH, blocklist and unsubscribe) and `public_rate:{ip}` (`routers/public.py`, 60 s) — so a raw IP lives for up to an hour. The `ip_rate_limit_exceeded` warning passes the IP as `extra`, but the JSON log formatter (`services/logger.py`) drops that field. When an action is written to the audit log, the IP is first hashed (next bullet).
- **An optional rate-limit install ID — public checks only.** Mobile carriers put thousands of phones behind one IP, so a client may send `X-Cleanway-Install: <random UUID>` with `GET /api/v1/public/check`; the request is then limited per install (same 60/hour) under a higher per-IP ceiling. The server accepts only a canonical UUID, keeps nothing but a SHA-256 of it as a rate-limit counter key that expires with its window (at most an hour), never logs the ID itself (a limit breach logs the first 8 characters of the hash), and never stores it elsewhere or links it to an account or to the device hash below. Without the header, limits are per IP as above. The ID is not authenticated, so it can only ever loosen a limit up to the per-IP ceiling; the paid services an analysis may use (IPQualityScore, the LLM judge) have their own service-wide daily caps.
- **A hashed IP — for the audit log.** IPs are hashed with **HMAC-SHA-256** (keyed with the server secret) and truncated to 16 hex characters (64 bits) before storage. Caveat: 64 bits is enough to correlate rate-limit activity but is weaker than a full 128-bit hash.
- **A device hash — for optional device-level settings and Family Hub.** The random UUID described above.
- **Aggregated usage counters.** Lifetime and weekly threat counts per user, for freemium limits — numbers only, no domains.

### The webmail exception

If you enable the webmail scanner, the extension sends the email's **subject, sender, reply-to, and body (text and HTML)** to `POST /api/v1/email/analyze`. This is the one feature where page content leaves your device. It applies only to Gmail, Outlook, and Yahoo webmail and only when the feature is active. Subject lines and bodies can contain sensitive context, so treat this as an explicit trade-off you are opting into.

## The Android app

### Message check (SMS)

- **Cleanway never reads your messages on its own.** The app requests no SMS, notification-listener or accessibility permission. It checks only a message you hand it: by tapping **Paste** on the check screen (the clipboard is read only on that tap), or by sharing a message to Cleanway from your messages app.
- **The text stays in memory on the phone.** A shared message is handed to the check screen in memory, never as a navigation parameter. The on-device analyzer (`MessageAnalyzer`) reads it in memory and drops it. The text is never written to disk or to the database, never logged, and never sent to our server or to anyone else.
- **What can leave the phone: up to 3 link hosts per message.** Links in the message are first compared with the blocklist on the phone. Then at most **3** distinct link **hosts** go to `GET /api/v1/public/check/{host}` — only hosts that are not on the on-device list and are not link shorteners, messenger links, shared system hosts such as `docs.google.com`, or IP addresses. Each link's path and query, and the rest of the message, stay on the phone. The requests carry no account token.
- **Caveats, stated plainly.** The hosts of one message are requested in parallel from the same IP address, so the server could tell they arrived together. Like any checked domain, they are then checked with the third-party threat-intelligence providers listed below. A dotted word that looks like a domain name (for example `notes.md`) can be read as a link and sent as a host.
- **What History keeps.** One row per message check in the app's SQLite database (`cleanway.db`, table `checks`, `source = 'sms'`): the verdict, the reason codes, up to 5 link hosts and the time. Never the text, and never a link's path.

### Link guard and the "All apps" shield

- **How the shield works.** The "All apps" shield is a local `VpnService` (`CleanwayVpnService`) that routes only DNS into the tunnel (`addRoute(VPN_GATEWAY_IP, 32)` — "only route DNS to us"). Page contents, messages and calls never pass through it; only the QNAME of each DNS query is parsed. A name on the on-device list is answered NXDOMAIN and logged on the phone (see the shield activity log below).
- **DNS for sites that are not blocked.** The shield decides locally which names to block. Every other lookup is forwarded — first to the DNS server of the network the phone is on (the mobile operator's or the Wi-Fi router's, as without Cleanway), and only if that fails to Cloudflare (`1.1.1.1`) or Quad9 (`9.9.9.9`), and last to Cloudflare over DNS-over-HTTPS. Those resolvers see the name, as they would without Cleanway; Cleanway's server does not.
  - Before 1.0.2 (`CleanwayVpnService`: `UPSTREAM_DNS_HOST`, `UPSTREAM_DNS_HOST_2`, `DOH_URL`): plain UDP/53 to Cloudflare `1.1.1.1`, then Quad9 `9.9.9.9`, then Cloudflare DNS-over-HTTPS (`https://1.1.1.1/dns-query`) as the last fallback.
- **Link guard.** When Cleanway is your default link app, a tapped link's host is checked against the list on the phone. A host that is not on the list is then sent, host only, to the same public check in the background — whether or not the "All apps" shield runs (since 1.0.2). A warning it produces is kept in the shield activity log below.
- **Install number (since 1.0.2).** Every public check from the app — typed, shared, from a message or from the link guard — carries an `X-Cleanway-Install` header: a random UUID made on the phone (not derived from the device, the SIM or an account), so the server can rate-limit per phone instead of per carrier-NAT IP address. It lets the server tell that checks made on the same day came from the same install: the app replaces it with a new random number every 24 hours. It is stored in the app's no-backup folder (`noBackupFilesDir`), so Android's backup never copies it to Google Drive or to a new phone, and it is gone with the app. It is not sent with the blocklist download. The server counts limits by it only from the API release that reads the header (API PR #51); before that, limits stay per IP address.
- **Blocklist download.** The "All apps" shield downloads the blocklist from `GET /api/v1/blocklist/dns` about every 6 hours (`BlocklistSync.REFRESH_MS`; on a metered network only once the list is 24 hours old, `METERED_MIN_AGE_MS`), sending the stored ETag as `If-None-Match`. The download sends nothing about your browsing. Builds from 1.0.2 also carry a copy of the list in the APK, used only until the first download succeeds.
- **Update check.** The app periodically calls `GET /api/v1/mobile/version` to learn whether a newer APK exists (`mobile/src/lib/update-check.ts`). It sends nothing about your browsing.
- **Shield activity log.** What the shields blocked, warned about or let through at your request is kept on the phone (`SharedPreferences` file `cleanway_block_log`: up to 200 events with the site name, the time, what happened and which shield acted, plus lifetime counters) and shown in History.
- **Android backup.** The app allows Android's own backup. When Google backup is on for the phone, Android copies the app's `SharedPreferences` files — the shield activity log above, the sites you marked "not a scam", and a few settings (whether protection was on, the notification language) — to your Google account, and restores them after a reinstall or onto a new phone. Cleanway never receives that backup. Not included: the check history database (`cleanway.db`), keys in `expo-secure-store`, and the install number.

### Retention on the phone

Unlike the extension, the mobile check history is **not pruned automatically**: it stays until you tap **Settings → Clear history**, which deletes every saved check (links and messages). Clear history does **not** clear the shield activity log; that log keeps its latest 200 events and drops older ones as new ones arrive.

## What we store, and for how long

| Data | Where | Retention |
|---|---|---|
| Domain + verdict + score (cache) | Redis (server) | 5 min (dangerous) / 15 min (suspicious) / 1 hr (safe); public endpoint 24 hr |
| **Switched off in production** (`PUBLISH_CONFIRMED_THREATS`). When on: a checked host that Google Safe Browsing lists as **phishing or malware** and our scorer rated **dangerous** + time of the last such check — no user, IP or URL. Only the site's own name is kept (`evil.xyz`, `www.evil.xyz`, `shop.vercel.app`, or one short plain word above it such as `login.evil.xyz`), never a longer name that could carry an email address, a full name or an ID | Redis sorted set `dangerous_domains:confirmed` | Published in the shared blocklist every phone downloads (as a hash) for 7 days after the last confirmation. Deleted 2 days after that whenever the server records another host or republishes the list (every 6 h); if both stop, the whole set expires 10 days after the last host was recorded. At most 20,000 hosts. Switched off, stored hosts leave the published list at the next refresh |
| Domain + ML feature vector + timestamp | Local `feature_log.jsonl` file (server) | **Off by default in production**; only written when `FEATURE_LOG_ENABLED=true` for an offline training run, then size-capped (default 50 MB, auto-rotated) |
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
| Mobile check history: link host(s) + verdict + reason codes + time (never message text) | Device (SQLite `cleanway.db`) | Until you tap Settings → Clear history |
| Mobile shield activity log: site name + time + event + shield | Device (SharedPreferences) | Latest 200 events; not cleared by Clear history |

**Feature-log note:** Cleanway can optionally collect a machine-learning training log (`feature_log.jsonl`) recording the domain name, the analysis score, and the feature vector. It is **off by default** — in production no domain is written to disk at all unless an operator explicitly sets `FEATURE_LOG_ENABLED=true` for a training run. When enabled, the file is size-capped (default 50 MB via `FEATURE_LOG_MAX_BYTES`) and auto-rotated to its most recent half, so it never grows without bound. It never records user identity — only the domain, score, and features.

**Family-alert retention caveat:** The code sets a **30-day** expiry on family alerts (`expires_at = now() + 30 days`). An earlier version of our published policy referenced 7 days; the code implements 30. A database migration includes a commented-out 7-day cleanup job, but the code does not show an active cron enforcing it, so alerts should be assumed to persist for up to 30 days server-side (as ciphertext the server cannot read — see Family Hub encryption).

## What we never collect

- **Full URLs, paths, or query strings.** The system is domain-only end to end. No database table anywhere stores check history with URLs (verified across all migrations).
- **Your browsing history** as a server-side record. Cached verdicts are transient (max 1 hour on the hot path).
- **Page content, HTML, DOM, or screenshots** — except the webmail body described above, which is an explicit opt-in feature.
- **Search queries** or activity outside domain safety checks.
- **Credit card data.** Payments go directly to Stripe; card data is never stored on our servers.
- **Plaintext passwords, ever.** The pwned-password check sends only the first 5 hex characters of a SHA-1 hash (k-anonymity); the full hash is discarded after the local match. The honeypot feature replaces a password with a random string client-side before any form submits.
- **Raw client IP addresses in long-lived storage.** IPs are hashed before they reach the audit log; the only raw copies are the rate-limit counter keys above, which expire within the window (at most an hour).
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
  - **Performance traces are not errors.** All three surfaces sample 10% of transactions (`tracesSampleRate` / `traces_sample_rate` 0.1), and transactions never pass through `before_send`. The landing site scrubs them (`beforeSendTransaction`) and rewrites `/check/<site>` and `/audit/<site>` paths to `[site]` in every string; the **API** (`api/main.py`) and the **mobile app** (`mobile/src/lib/sentry.ts`) set no `before_send_transaction` yet, so a sampled trace can carry a request URL such as `/api/v1/public/check/<domain>`. The public policy says so ("a report or a measurement can still contain … the name of a site"). Add the hook there before tightening that sentence.
  - **No Session Replay.** The landing site used to record 1% of sessions and every session with an error (`replayIntegration`); replays carry page URLs and bypass `beforeSend`. It was removed on 2026-09-27; the public policy states that the site records no sessions.
- **Threat-intelligence providers.** To decide if a domain is dangerous, the server sends the **domain name** (no full URL, no user identity, no page context) to external checkers: Google Safe Browsing, PhishTank, URLhaus, MalwareBazaar (`mb-api.abuse.ch`), ThreatFox, PhishStats, Spamhaus DBL, SURBL, AlienVault OTX, and IPQualityScore, plus `rdap.org` for the registration date (`analyzer.check_whois_age`; rdap.org is a redirector to the registry's RDAP server). This is inherent to how safety checks work — see "Server-blind design" below. You should review those providers' own privacy policies.
- **Cloudflare 1.1.1.1 for Families (comparison).** Every `/api/v1/public/check` response — including cache hits and the app's own host checks — looks the domain up with `family.cloudflare-dns.com` (`services/competitor_verdicts.py`, called from `routers/public._build_response`) to show Cloudflare's verdict next to ours. It is an ordinary DNS-over-HTTPS query from our server. When that answer is "no such domain" and we have no answer of our own, the server asks once more with Cloudflare's unfiltered resolver, to tell a Cloudflare block from a domain that does not exist.
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

One more thing a check can change — **currently switched off**: when Google Safe Browsing lists a checked host as phishing or malware and our scorer rates it dangerous (a heuristic guess never counts, and no other threat-intelligence service does), the server can keep that host — without any record of who checked it — and add it to the public blocklist that every phone downloads, so the next person is protected before they tap. Only the site's own name is kept, and for how long is in the retention table. A kept host is not re-checked: if Google delists it sooner, it stays on the list until 7 days after its last confirmation. It stays off until Google's terms are confirmed to allow it, and the public privacy policy will describe it before it is switched on.

Two operational logs can record domain names for legitimate reasons, and we disclose them rather than hide them: the ML **feature log** (off by default; see note above) and the **DoH gateway**, which logs only the last 32 characters of a blocked query name to structured logs. Neither is linked to user identity. Redis cache keys are also plaintext domain names, readable by anyone with direct Redis access — which is why that access is restricted.

**Hosting request logs.** Our own request log scrubs the domain out of `/api/v1/public/check/{domain}` before it is written (`_scrub_path_for_logs` in `api/main.py`), and uvicorn's access log is silenced (`api/services/logger.py`). The hosting platforms in front of us — Railway for the API, Vercel for cleanway.ai (whose `/check/{domain}` pages carry the domain in the page URL) — keep their own HTTP request logs, which can include the requested path and the client IP. We do not control their retention; their policies apply.

## Your rights (GDPR)

- **Export and deletion.** You can request account deletion; it enters a **30-day grace period** (soft-delete) before the data is permanently removed, giving you time to cancel.
- **Data minimization by design.** For anonymous use, no account, email, or identity is collected at all — you can use link protection with no sign-up.
- **What's tied to you vs. not.** Only authenticated endpoints attach a user ID. Public checks are anonymous. IPs used for rate limiting live raw in expiring counter keys (at most an hour) and are hashed before any long-lived storage.

If you have a privacy request or question, contact us and reference this document.

## Footer

This document describes the code as of **2026-07-01** (main branch); the Android app section was added on **2026-09-25** with the on-device message check, and the shield's DNS upstreams, blocklist cadence, update check and hosting-log note on **2026-09-26**; the raw-IP rate-limit keys, Sentry traces/replay, rdap.org, MalwareBazaar and the Cloudflare comparison lookup were corrected on **2026-09-27**. The public policy at cleanway.ai/privacy-policy (source: `landing.privacy_policy` in `packages/i18n-strings/src/`, all 10 languages) is the plain-language version of this document — change both together. It has not yet been reviewed by a lawyer against 152-FZ (operator details, consent, cross-border transfer, data-subject request channel). Generated with a code-grounded workflow whose every claim was adversarially verified against the source. Retention windows, hashing choices, and data flows above are drawn directly from the source and are intended to be auditable. The detection engine is open to inspection — see the benchmark methodology and open-source plan (`docs/OPEN-SOURCE.md`) for how to verify these claims against the code and against head-to-head accuracy results. If you find any statement here that the code does not support, that is a bug in this document; please report it.