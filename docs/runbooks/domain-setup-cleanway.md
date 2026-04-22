# Cleanway.ai Domain Setup Guide

**Domain**: `cleanway.ai` (purchased 2026-04-22)
**Scope**: Wire up DNS so `cleanway.ai` (landing) and `api.cleanway.ai` (backend) resolve to Vercel and Railway respectively.

---

## Part 1 — `cleanway.ai` → Vercel (landing)

1. Open Vercel dashboard → project `landing` (landing-pi-one-34) → **Settings** → **Domains**
2. Click **Add Domain** → enter `cleanway.ai` → **Add**
3. Vercel shows the required DNS records (usually one of):
   - **A record**: `@ → 76.76.21.21`
   - **Or CNAME**: `@ → cname.vercel-dns.com`
4. Also add `www.cleanway.ai`:
   - **CNAME**: `www → cname.vercel-dns.com`
5. Go to your domain registrar (where you bought cleanway.ai) → DNS settings → add the records Vercel requested
6. Wait 2–10 min for DNS propagation. Vercel page refreshes automatically when it detects the domain.
7. Vercel auto-issues SSL cert via Let's Encrypt

**Verify**: `curl -I https://cleanway.ai` should return `HTTP/2 200` (or 307 to localized path).

---

## Part 2 — `api.cleanway.ai` → Railway (backend)

1. Open Railway dashboard → project → `web` service → **Settings** → **Networking**
2. Click **Custom Domain** → enter `api.cleanway.ai` → **Add**
3. Railway shows a CNAME target, usually: `api.cleanway.ai → xxxxx.up.railway.app`
4. Go to registrar DNS → add:
   - **CNAME**: `api → xxxxx.up.railway.app` (whatever Railway gave you)
5. Wait for propagation. Railway auto-provisions SSL.

**Verify**: `curl https://api.cleanway.ai/health` should return `{"status":"ok",...}`.

---

## Part 3 — Update Railway env vars

After DNS is live:

1. Railway → `web` service → **Variables**
2. Update `ALLOWED_ORIGINS`. Current value likely includes `https://landing-pi-one-34.vercel.app`. Set to:
   ```
   ALLOWED_ORIGINS=https://cleanway.ai,https://www.cleanway.ai,https://landing-pi-one-34.vercel.app
   ```
   (Keep the Vercel URL as fallback until you're confident the new domain works.)
3. Railway auto-redeploys.

---

## Part 4 — Update Vercel env vars

1. Vercel → `landing` → **Settings** → **Environment Variables**
2. Update `NEXT_PUBLIC_API_URL` from the default Railway URL (e.g. `https://web-production-xxxx.up.railway.app`) to `https://api.cleanway.ai`
3. Redeploy latest production deployment (Deployments → ⋯ → Redeploy, **uncheck** "Use existing build cache")

---

## Part 5 — Post-verification

Run from any shell:

```bash
curl -I https://cleanway.ai
curl https://api.cleanway.ai/health
curl -I https://cleanway.ai/en/check/google.com
```

All should return 200 (or redirect 3xx). If `api.cleanway.ai/health` returns "ok" — backend is live on custom domain.

---

## Part 6 — Email setup (optional, downstream)

If you want `support@cleanway.ai`, `security@cleanway.ai`, etc:

- **Cheapest**: Zoho Mail (free tier, 5 users), add MX records at registrar
- **Best**: Google Workspace ($7/user/month)
- **Alternatives**: FastMail, ProtonMail Business, iCloud+ Custom Domain

References in codebase that assume email addresses exist (update these later):
- `SECURITY.md` — `security@cleanway.ai`
- `api/templates/welcome.html` — sender
- `api/services/email.py` — FROM address

---

## Part 7 — Social handles (grab ASAP — free)

- Twitter/X: **@cleanwayai** — [x.com/signup](https://x.com)
- Instagram: **@cleanwayai** — [instagram.com](https://instagram.com)
- TikTok: **@cleanwayai** — [tiktok.com](https://tiktok.com)
- LinkedIn Company: **cleanway-ai** — [linkedin.com/company/setup](https://linkedin.com/company/setup)
- YouTube: **@cleanwayai** — [youtube.com/create_channel](https://youtube.com)
- GitHub org: **cleanway-ai** — [github.com/organizations/new](https://github.com/organizations/new)

Fallbacks if taken: `@cleanway_ai`, `@getcleanway`, `@cleanwayhq`, `@cleanway_app`.

---

## Part 8 — USPTO Trademark filing (within 30 days)

1. Go to [USPTO TEAS Plus](https://www.uspto.gov/trademarks/apply/trademark-electronic-application-system-teas) ($250 per class)
2. File for **Class 9** (downloadable software) — cover browser extension + mobile app
3. File for **Class 42** (SaaS/web services) — cover the API service
4. Specimen: screenshot of product showing "Cleanway" brand
5. Attorney fee optional but recommended ($500–$1500 for solid filing)
6. Registration takes 8–12 months. "TM" symbol usable immediately after filing.
