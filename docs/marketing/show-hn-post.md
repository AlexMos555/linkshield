# Show HN — draft

> Read first: this is a draft. Numbers below are the validated baseline as of 2026-06-29. Re-run `scripts/eval_fresh_urls.py` the week of submission and update if recall has shifted by more than 2 percentage points. Do not post without re-verifying.

---

## Title (HN's 80-char field)

**Show HN: Cleanway — I open-sourced my anti-phishing engine after benchmarking it**

Alternative titles to A/B mentally before posting:
- `Show HN: Anti-phishing extension that publishes its own per-vendor benchmark`
- `Show HN: Cleanway – privacy-first anti-phishing with reproducible benchmark`

Pick the one that doesn't feel hype-y to you. HN downvotes hype fast.

---

## Body

Hi HN,

I'm Aleksandr, a solo dev. I built Cleanway because every anti-phishing extension I tried did one of two things: shipped my full URL to a server (Norton, McAfee), or had vague marketing copy with no verifiable detection numbers (everyone). I wanted both: real privacy AND defendable numbers.

So I built it differently:

**What runs on the server:** domain name only. Never the full URL. Never the page content. Never browsing history. The extension extracts the domain client-side and asks for a verdict.

**What runs on your machine:** everything else. Full URL inspection, page-DOM heuristics (BitB detection, credential-form mismatch, tab-napping guards), the warning UI.

**How we measure ourselves:** weekly benchmark cron pulls fresh URLs from URLhaus + PhishTank (~500 phishing + 1000 Tranco-legit), feeds them through the public `/api/v1/check` endpoint, AND through Cloudflare 1.1.1.1 for Families, Google Safe Browsing, PhishTank, and VirusTotal. Same script for all five resolvers. Raw output commits to `docs/benchmarks/`. Per-vendor recall, precision, and denominators (including our own "unknown" bucket when we rate-limit ourselves during a run) live at cleanway.ai/transparency/methodology — pull the current snapshot before posting rather than pasting a number from this draft. Static baseline: CatBoost ML model AUC 0.95 on a held-out test set of 24,000 verified domains; measured FPR on Tranco top 1M: 0.08%.

The script is at `scripts/eval_fresh_urls.py`. Two commands to clone and verify. You can run it against your own domains.

The engine is MIT. Stripe billing, Family Hub crypto, audit log, and the trained ML weights stay closed (operational moat, not algorithmic). The carve-out plan is in `docs/OPEN-SOURCE.md`. The detection algorithm is fully visible — the value is in the intel sources + ongoing operation, not algorithmic secrecy.

I'm honest about caveats:
- Mobile native apps aren't shipped yet. The mobile DoH profile (one-tap iOS install) needs `dns.cleanway.ai` CNAME — pending.
- Family Hub crypto hasn't been independently audited. It's reviewed by me + an adversarial Claude pass; that's not the same as a NCC Group audit.
- Hindi/Indonesian translations are AI-generated + adversarial-reviewed but not human-final. If you're a native speaker and find something off, PRs welcome.

Stack: FastAPI (Python 3.11) on Railway, Next.js 15 + next-intl (10 locales) on Vercel, Chrome MV3 + Firefox MV2 + Safari extensions, React Native (iOS/Android), CatBoost for ML, Redis for caching, Supabase for accounts + Family Hub.

Two links:
- The site (with live methodology page): https://cleanway.ai/transparency/methodology
- The engine: https://github.com/AlexMos555/linkshield

Happy to answer questions, especially about the privacy architecture, the benchmark methodology, or why I picked open source over freemium-with-secret-sauce.

---

## Top-comment prep

HN top comments on a Show HN are predictable. Have these ready as paste-able responses.

### Q: "Why should anyone trust your benchmark? You wrote it."
**A:** Right — that's exactly why the script is in the repo, the dataset is two public feeds (URLhaus + PhishTank), and the cron runs every Monday on a fresh sample. Anyone can clone and reproduce. The four competitor adapters are open too. If my numbers were juiced, you'd see it in your own run.

### Q: "What about Google Safe Browsing? Isn't it free + built into Chrome?"
**A:** Yes, and it catches a lot. But Safe Browsing only checks against its hash database — no per-page heuristics (BitB, credential form mismatch, tab-napping), no per-link warnings inside Gmail/Outlook, no honeypot password injection. We layer 15 other threat-intel signals on top of Safe Browsing (11 named blocklist feeds + Tranco popularity, favicon brand-clone, typosquat watchtower, ML model, LLM judge). Per-vendor recall — with per-vendor denominators, unknown-rates included — is at cleanway.ai/transparency/methodology; refresh the number from the current `latest.json` before posting. GSB comparison row: rerun the benchmark with `GOOGLE_SAFE_BROWSING_KEY` set first.

### Q: "Why MIT and not AGPL? You'll get forked."
**A:** The intel sources + curated brand data + trained ML weights stay closed (`docs/OPEN-SOURCE.md`). The detection algorithm is reverse-engineerable from extension traffic anyway. Forks won't have the operational moat. MIT maximises adoption + acquihire-friendly.

### Q: "Solo dev. What's your bus factor?"
**A:** Open source is part of the answer. The engine doesn't go away if I do. The intel-source operation (cron updates, brand favicon refreshes, Tranco resync) is the part that needs continuity, and that's documented in `docs/ARCHITECTURE.md` so a successor can pick it up.

### Q: "Why not a freemium with cloud-only premium tier?"
**A:** Pricing is $1.49–$5.99 PPP-adjusted across 4 tiers. Free tier blocks dangerous links forever — no nag screens, no time-bombed trials. The paid tiers add unlimited scans, cultural scam explanations, Family Hub (E2E encrypted across phones), and the parental dashboard. Blocking is free because phishing protection should be a baseline.

### Q: "How much money have you made?"
**A:** Pre-launch as of post-time. Today's goal is users + feedback. Revenue conversation is for Q3.

### Q: "What's the latency?"
**A:** First check on a domain: 1–3 seconds (cold cache, parallel fan-out across 11 blocklist feeds + ML scoring + brand favicon hash + Tranco rank + typosquat watchtower + LLM judge on caution-band verdicts). Repeat checks: <50ms (Redis cache, 24h TTL). Methodology page reports p50 measured from the CI runner.

### Q: "Wait, you're collecting domains. Isn't that PII-adjacent?"
**A:** Domains alone are not PII under GDPR — they don't identify a person. We don't link domain queries to your account or IP past the request lifetime. Sentry has PII redaction enabled. Server logs rotate. The methodology page has the full data-flow diagram if you want to verify.

### Q: "Why isn't [my favourite feature X] there?"
**A:** Genuinely interested — open an issue. The roadmap is at `[link to GitHub issues with `roadmap` label, once set up]`.

---

## What NOT to do

- Don't include screenshots until the Chrome Web Store listing is live (otherwise the install link goes to a dead URL on HN).
- Don't oversell the "open source" angle if billing + crypto stay closed — be upfront about the carve-out in the post.
- Don't post on a holiday in the US/EU. HN engagement collapses.
- Don't reply with anger to skeptical comments. The community rewards calm, specific answers.

## Posting timing

- **Best:** Tuesday 9–11 AM PT (the HN graveyard shift is over, US west wakes up).
- **Worst:** Friday afternoon, weekend, US holidays.
- **Track:** Open https://news.ycombinator.com/show after posting in incognito. Refresh every 15 min for the first 4 hours. Reply within 10 min of any comment.
