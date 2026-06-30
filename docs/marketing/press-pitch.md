# Press pitch — security journalists

> Cold email to 3-5 security journalists. Highly personalized — never bulk-send. Re-verify numbers the week of sending.

---

## Subject line options

Pick one. Order shows roughly best-to-okay:

1. `Anti-phishing extension publishes own benchmark — open source`
2. `Solo dev open-sources anti-phishing engine + reproducible per-vendor benchmark`
3. `Privacy-first anti-phishing with a recall number that updates weekly — measured, not marketed`
4. `Show: per-domain anti-phishing comparison vs Cloudflare 1.1.1.1 for Families`

Avoid hype words: "revolutionary", "game-changing", "unbeatable", "AI-powered". Journalists' spam filters trip on them.

---

## Body template

> Use the journalist's first name. Reference one of their pieces from the last 90 days. Specificity beats personalization tools that fake it.

```
Hi {{First name}},

I read your piece on {{recent specific article, e.g. "the Snowflake credentials leak post-mortem"}} last week and thought you might be interested in a small launch.

Short version: I'm a solo dev who built an anti-phishing browser extension and open-sourced the detection engine after benchmarking it. The thing that might be unusual: I publish the weekly per-vendor comparison openly. Same script runs against Cloudflare 1.1.1.1 for Families, Google Safe Browsing, PhishTank, VirusTotal, and us, on fresh URLhaus + PhishTank URLs. Latest snapshot (2026-06-30, sample = 24 phishing URLs): Cleanway recall 61.5% vs Cloudflare 1.1.1.1 for Families 54.2%, both at 100% precision. Numbers refresh every Monday at cleanway.ai/transparency/methodology — pull the live snapshot before publishing. AUC 0.9983 on a held-out 14,400-domain test set.

Why I think this might be a story:
- No other anti-phishing vendor (Norton, McAfee, Bitdefender) publishes recall numbers, and the few that publish anything publish AUC without a reproducible benchmark.
- The detection algorithm is MIT-licensed. The intel keys and trained model weights stay closed (operational moat, not algorithmic). The carve-out plan is at docs/OPEN-SOURCE.md.
- Privacy architecture is unusual: domain-only server scanning, not full URL. Even our server can't reconstruct browsing history. The Family Hub feature is end-to-end encrypted across phones.

Live links:
- Methodology + per-vendor comparison: https://cleanway.ai/transparency/methodology
- Detection engine source: https://github.com/cleanway-ai/engine
- Architecture: https://github.com/cleanway-ai/engine/blob/main/docs/ARCHITECTURE.md

Happy to share the underlying benchmark dataset, jump on a 15-minute call, or send raw numbers + per-vendor reasoning if you want to dig in.

Cheers,
Aleksandr Moskotin
hello@cleanway.ai
```

Character count: ~1,500 chars. Reading time: ~45 seconds. Long enough to be specific, short enough to skim.

---

## Target list (in priority order)

> Verify the journalist still covers security. Beats are volatile.

| Journalist | Outlet | Beat | Personalization angle |
|---|---|---|---|
| Lily Hay Newman | Wired | Phishing, account security, consumer security | Wrote landmark piece on phishing infrastructure |
| Andy Greenberg | Wired | Privacy, encryption, transparency | Cares deeply about reproducible claims |
| Catalin Cimpanu | RisingTongue (newsletter) | Daily security news | Loves operational specifics, NOT marketing fluff |
| Brian Krebs | KrebsOnSecurity | Cybercrime, scams | High bar for verifiability; pitch only after the benchmark has 2+ weeks of data |
| Joseph Cox | 404 Media | Privacy, surveillance | Cares about the "your data stays on your device" angle |
| Kim Zetter | Independent (Substack) | Long-form security | Slower pace but more impact when she picks something up |
| Joseph Menn | Reuters / The Cyber Wire | Industry, policy | Stretch — usually covers larger stories |

Skip if you have <100 GitHub stars or no public benchmark file. They'll Google-verify.

---

## Outreach cadence

- **Tuesday 9 AM PT** is the best universal time for security press.
- **One pitch per journalist.** Following up after 7 days is fine; following up before is rude.
- **No CC.** Send individual emails. Never mass-mail. Mailchimp / Substack-mail / mass tools = filtered to spam by default.
- **No attachments.** All links. Journalists open links, never attachments from cold emails.

---

## If they reply with interest

- Be ready to deliver the **dataset** (URLhaus + PhishTank dumps used in the last benchmark) within 1 hour.
- Be ready to deliver **per-vendor reasoning** for any flagged finding (why did Cleanway say "dangerous" on this specific URL?).
- Schedule a call same-day or next-day. Journalist enthusiasm is half-life ~24h.
- Mention you're solo so they don't expect a marketing team. Some prefer this; others won't.

## If they ignore

- One follow-up at day 7 with a single new data point ("Numbers updated, recall now X").
- Then drop them. Don't pester.
- Move down the list.

---

## What NOT to do

- Don't pitch with claims you can't immediately verify. They WILL ask for the script + dataset and they have 10 minutes to vet you.
- Don't compare yourself to a specific consumer brand (Norton/Avast/Bitdefender) in the pitch. Compare to defaults (Safe Browsing, 1.1.1.1) instead — those are reproducible.
- Don't pitch on a holiday or right before a big security conference (Black Hat, RSA, DEF CON). Journalists are buried.
- Don't pitch before the GitHub repo is public AND the Chrome Web Store extension is live. Press needs links that resolve.
