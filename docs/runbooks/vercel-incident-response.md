# Vercel security incident — operator response

Date of notification: 2026-04-20.
Scope of notification: "unauthorized access to certain internal Vercel
systems". A "limited subset" of customers had credentials compromised.
Vercel says no evidence this account was in that subset, but investigation
is ongoing.

## What's actually on Vercel for us (audit)

Only the `landing` project. Exports a Next.js 15.1.11 SSG site.

Env vars it uses (per `grep process.env landing/app`):

- `NEXT_PUBLIC_API_URL` — Railway URL. Public by design.
- `API_URL` — server-side, same Railway URL. Public.

**No secrets** (Supabase service key, Stripe secret, Sentry DSN) are stored
on Vercel. Landing never needs them — it calls the Railway API which owns
those credentials.

Blast radius of this specific incident, worst case: someone reads/deploys
our public landing. Which is already public.

## Wider Vercel account risk (the real worry)

If an attacker got our Vercel **account** credentials, they could:

- Push a malicious landing build that pretends to be Cleanway and
  exfiltrates visitor input.
- Redirect `cleanway.ai` DNS from Vercel dashboard.
- Install a malicious Vercel-GitHub integration to read/write the repo.
- Access the payment + usage metadata Vercel records for the account.

## Action plan (what the operator has to do — cannot be automated)

### Immediate (do within 30 minutes)

1. **Vercel → Settings → Activity Log**
   - Filter last 30 days. Look for any login/deploy/token event not from
     your devices or IPs. If anything looks off, screenshot before you
     clear things.

2. **Vercel → Settings → Tokens** (https://vercel.com/account/tokens)
   - Delete every token. Create a new one only if something actively needs
     it (CI workflow, Railway integration, etc.).

3. **Vercel → Settings → Security → Password + 2FA**
   - Rotate the password. Use the password manager — don't reuse.
   - Enable TOTP 2FA. SMS is weak; Authy / 1Password / Yubikey-over-TOTP
     are all fine.

4. **Vercel → Integrations → GitHub App**
   - Confirm only `AlexMos555/cleanway` is installed (not "All repos").
   - If anything else is listed, remove it.

5. **GitHub → Settings → Security log**
   `https://github.com/settings/security-log`
   Look for Vercel OAuth authorizations in suspicious time windows.

### Hardening (do this week)

6. **Move sensitive env vars behind Vercel's "Sensitive" flag**. Even
   though our env vars are public, marking them Sensitive encrypts
   at rest and hides from dashboard views. Settings → Environment
   Variables → edit each → toggle "Sensitive".

7. **Pin CI Vercel tokens to least-privilege**. If any GH Action uses
   `VERCEL_TOKEN`, create a new token scoped to the one project only
   (Vercel lets you scope tokens to a team + project).

8. **Review recent landing deployments**
   https://vercel.com/dashboard → cleanway-landing → Deployments.
   Any deploy SHA not in our git log → rollback to last known-good.

9. **Lock Vercel domain DNS**
   - Settings → Domains → verify Nameservers are ours (Cloudflare
     or wherever) and Vercel only has the verification TXT + A/CNAME.
   - If Vercel has full nameserver control, move DNS to Cloudflare and
     keep only the CNAME to Vercel. Keeps nameserver control outside
     the incident blast.

### Monitoring (do monthly until Vercel publishes post-mortem)

10. **Check deploy history weekly** for the landing project — any
    deploy not from our commit SHA is suspicious.
11. **Check Vercel billing** — unexpected function invocations or edge
    requests can indicate abuse.
12. **Subscribe to Vercel's security advisories** and watch the
    security bulletin Vercel referenced in the email.

## What we do NOT need to do

- Rotate Supabase keys. They live on Railway, not Vercel.
- Rotate Railway tokens. Different provider, unaffected.
- Rotate mobile / extension signing keys. These aren't on Vercel.
- Panic. Vercel's statement was explicit that there's no evidence this
  account was in the compromised subset. The actions above are
  defense-in-depth, not emergency response.

## Post-incident review

After completing the actions, document outcome:

- Any unauthorized activity found? (Y/N + screenshot)
- Tokens rotated? (count)
- 2FA enabled? (Y/N)
- Password rotated? (Y/N + date)

File a copy in `.planning/INCIDENT_LOG.md` so the audit trail survives
Vercel account changes.
