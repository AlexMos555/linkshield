# Runbook: Email

## What this is

Operational procedures for LinkShield's transactional email system. For how the code works, see `packages/email-templates/README.md`.

## Provider switch

`EMAIL_PROVIDER` env var controls which provider is used at runtime:

| Value | Use in | Behavior |
|---|---|---|
| `noop` (default) | Local dev, tests, anything without creds | Logs envelope, sends nothing. Safe for tests. |
| `resend` | Staging, optional prod | HTTP API, $20/mo, great DX, shared sending domain |
| `ses` | Prod | AWS SES, cheap at scale, requires IAM + DKIM setup |

**Never set `EMAIL_PROVIDER=resend` or `ses` in local dev** — you'll spam real inboxes.

## First-time setup per environment

### 1. Pick a sending domain
We don't own `linkshield.example` — that's the dev placeholder. Before prod send:
- Decide the marketing domain (see brand decision in `.planning/STATE.md`)
- Subdomain for transactional: `mail.<domain>` or `send.<domain>` — keeps marketing domain clean of bounces
- Set `EMAIL_FROM_DOMAIN=mail.yourdomain.com` in prod env

### 2. DNS records (both Resend and SES require these)
```
# SPF (authorize provider's SMTP)
mail.yourdomain.com.  TXT  "v=spf1 include:_spf.resend.com ~all"

# DKIM (signs outgoing — provider gives the public key)
resend._domainkey.mail.yourdomain.com.  TXT  "v=DKIM1; k=rsa; p=..."

# DMARC (policy for receivers)
_dmarc.mail.yourdomain.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; fo=1"
```

Start with `p=quarantine`; upgrade to `p=reject` after 30 days of clean DMARC reports.

### 3. Provider-specific

**Resend:**
1. Sign up resend.com, verify domain, get API key
2. `RESEND_API_KEY=re_...` in Railway env vars
3. `EMAIL_PROVIDER=resend`
4. Domain must show "verified" in Resend dashboard before first send

**SES:**
1. AWS console → SES → verify domain (automatic DKIM)
2. Request production access (SES starts in sandbox, 200 emails/day, only to verified addresses)
3. IAM role attached to Railway container has `ses:SendRawEmail` permission scoped to `arn:aws:ses:REGION:ACCOUNT:identity/mail.yourdomain.com`
4. `EMAIL_PROVIDER=ses`, `AWS_REGION=us-east-1` (or wherever your domain is verified)
5. Verify production access granted: AWS will email you; typical lead time 24h

## Daily operations

### How to check: is email working?

```bash
# Send a welcome email to yourself via production API
curl -X POST https://api.yourdomain.com/api/v1/admin/test-email \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"template":"welcome","to":"you@example.com","locale":"en"}'

# (That admin endpoint doesn't exist yet — TODO in Phase E₃ when staging runbook matures)
# For now: create a test user account, trigger the onboarding flow, check inbox.
```

Alternative: Resend/SES dashboards show "Sent / Delivered / Opened / Bounced" per send in real-time.

### How to check: are bounces happening?

Weekly check during growth phase:
- **Resend:** dashboard → Emails → filter by Bounced
- **SES:** CloudWatch metrics → Reputation dashboard, Bounce Rate < 5% required for SES, Complaint Rate < 0.1%

If either rate climbs above threshold, SES will throttle you. Act before that.

## Incidents

### "Users aren't getting welcome emails"

**Likely causes in order of frequency:**

1. **Provider key expired / revoked.** Check `EMAIL_PROVIDER` env, try sending test. If 401 in logs, rotate key.
2. **Send failed silently.** Grep logs for `email.send.resend.error` / `email.send.ses.exception`. Correlate with `send_id` from the triggering event.
3. **Template build stale.** Verify `packages/email-templates/out/manifest.json` exists in the deployed container. If not, `build-emails.mjs` didn't run at build time.
4. **Landed in spam.** Ask user to check spam folder. If confirmed, check DMARC alignment + DKIM signatures pass in received headers.
5. **User previously unsubscribed.** Check user_settings.email_prefs in Supabase.

**Triage sequence:**
```bash
# 1. Most recent email attempts for this user
railway logs --filter "email.send" --since 24h | grep <email-or-user-id>

# 2. Confirm template exists
ls packages/email-templates/out/welcome/

# 3. Test provider directly (bypasses our code)
curl -X POST https://api.resend.com/emails -H "Authorization: Bearer $RESEND_API_KEY" \
  -d '{"from":"test@mail.yourdomain.com","to":"you@example.com","subject":"test","html":"hi"}'
```

### "Users complaining about spam from us"

1. Rotate API key immediately (your key is public or abused).
2. Turn off outbound by setting `EMAIL_PROVIDER=noop` in Railway env.
3. Check Resend/SES dashboard for send volume spike — there should be one; that's the smoking gun.
4. Find source: was there a rate-limit gap? Did we ship a new cron that fires to all users instead of segment?
5. Incident postmortem in `.planning/incidents/YYYY-MM-DD-email-spam.md`.
6. If complaint rate > 0.5%, expect SES to suspend. Contact AWS support.

### "Unsubscribe link returns 400"

Means HMAC signature didn't validate OR token is older than 90 days.

- If lots of users: `SUPABASE_JWT_SECRET` was rotated without draining old tokens. Set a 30-day grace period before rotating again: keep old secret as `PREV_JWT_SECRET`, try both in `_get_secret()`.
- If single user: token was mangled (link broken across lines by their email client). Ask them to copy-paste the URL.

## Capacity planning

| Volume | Provider | Cost |
|---|---|---|
| < 3K sends/mo | Resend free tier | $0 |
| 3K–50K | Resend Pro | $20/mo |
| 50K–1M | SES | ~$100/mo |
| > 1M | SES reserved | scales down per-email |

Welcome + receipt = 2 sends per paying user. Weekly report + family invite + breach alerts = maybe 4/user/month average.

At 10K paying users + 2× that free, ~40K sends/month. Stay on Resend Pro until 100K users.

## Security checklist before first prod send

- [ ] `EMAIL_FROM_DOMAIN` set to real owned domain (not `.example`)
- [ ] SPF + DKIM + DMARC records active (check via `dig TXT mail.yourdomain.com`)
- [ ] Provider dashboard shows "verified" status on sending domain
- [ ] `EMAIL_PROVIDER=resend` OR `ses` in prod Railway only — NOT in staging/dev
- [ ] `RESEND_API_KEY` / AWS IAM credentials in Railway, not in git
- [ ] Unsubscribe endpoint reachable from outside the cluster (test via `curl`)
- [ ] At least one template sent to a real test inbox in all 10 languages — no encoding issues in Arabic/Hindi
- [ ] Bounce webhook wired to `/api/v1/email/bounce` (TODO Phase E₃)

## Phase E₃ follow-ups

Not done yet, create tickets in order:

1. Add `user_settings.email_prefs` Jsonb column — persist unsubscribes
2. Hook bounce/complaint webhook to mark users suppressed
3. Admin test-email endpoint (authenticated) for smoke tests without using real flows
4. Rate limiting: max 3 emails/hour per user across ALL templates (prevents accidental loops)
5. Weekly report cron with batching (prevents sending 100K emails in 10 seconds)
6. DMARC report digest to Slack for daily monitoring
