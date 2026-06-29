# Launch day — minute-by-minute checklist

> Read this fully BEFORE launch day. Print it. Cross off each item as you hit it. The first 4 hours are the only ones that matter.

---

## Pre-launch (the night before)

| Time | Action |
|---|---|
| T-12h | Final benchmark re-run: `python3 scripts/eval_fresh_urls.py` — verify recall ≥ 90% and FPR ≤ 0.5%. If shifted by >2pp, update copy on landing + Show HN draft + store listing before posting. |
| T-12h | Visual walkthrough of cleanway.ai in Chrome incognito on real iPhone + Android. Note any layout breaks. Fix or accept. |
| T-12h | Verify Chrome Web Store listing live. Try installing it on a clean Chrome profile. |
| T-12h | Verify Twitter handle `@cleanwayai` is yours and the avatar+banner are uploaded. |
| T-12h | Verify Discord / matrix room created for live questions. Pin a welcome message with FAQ links. |
| T-12h | Drafts loaded into clipboard manager: Show HN body, X/Twitter announcement thread, Reddit /r/privacy post, Mastodon post, LinkedIn post. |
| T-12h | Sleep. The first 4 hours need you sharp. |

---

## Launch day

### T-0: 9:00 AM PT Tuesday

| Time | Action | Channel |
|---|---|---|
| 9:00 AM PT | Post Show HN at `news.ycombinator.com/submit` | HN |
| 9:01 AM PT | Open Twitter/X. Post announcement thread (3-5 tweets). Pin top tweet to profile. | X |
| 9:02 AM PT | Post to `/r/privacy` with the methodology link as the headline. Body: short version of Show HN. | Reddit |
| 9:05 AM PT | Post to `lobste.rs` (security tag). | Lobsters |
| 9:08 AM PT | Send 3 personalized press emails (one at a time, no bulk). | Press |
| 9:10 AM PT | Post on Mastodon (infosec.exchange instance) + LinkedIn. | Mastodon / LinkedIn |

**That's the launch barrage. Do not send any more channels in the first 60 minutes.** Overdistribution feels like spam.

### T+15 min — Stabilization check

| Action |
|---|
| Refresh HN. If your post is on the front page or has >5 upvotes already, good signal. If 0 upvotes after 15 min — re-evaluate title and consider re-posting with a different angle (this is allowed once per topic). |
| Refresh Twitter. Reply to any RTs with a personal "thanks". |
| Check `cleanway.ai/transparency/methodology` is loading. If down → emergency fix. Cron benchmark runs every Monday — if it failed, you'll show stale data. |
| Check Railway / Vercel status pages. |

### T+30 min — First comment wave

| Action |
|---|
| Reply to first 3 HN comments within 10 minutes of each. Slower than that = HN reads it as "abandoned thread" and stops engaging. |
| Use the prepared top-comment responses from `docs/marketing/show-hn-post.md` "Top-comment prep" section. |
| Be calm on critical comments. Don't argue — answer with specifics. |

### T+1h — Sustain

| Action |
|---|
| Check API rate-limit cliff. If a sudden spike has overrun limits → bump and redeploy. |
| Reply to all unique HN comments. Don't reply with thanks-only messages. |
| Post one follow-up tweet with a concrete data point from the first hour (downloads, recall measurement, etc.). |

### T+2h — Watch competitor mentions

| Action |
|---|
| Search HN for "Cleanway" in case someone else posted. Reply to those threads with a single helpful message — don't promote. |
| Watch X for "@cleanwayai" mentions. |
| Reply to Reddit comments with your account flair as "Author — Cleanway". |

### T+3h — Sentiment check

| Action |
|---|
| If HN traction is good (50+ upvotes, on front page) → continue engaging until end of US business day. |
| If HN traction is weak (10 upvotes after 3h) → don't re-post same day. Try Wednesday with different angle. Wait at minimum 7 days before re-posting. |

### T+4h — Wrap

| Action |
|---|
| Stop new outreach. Continue replying to comments organically through the rest of the day. |
| Note down what worked (best title? best subreddit?). |
| Pull a fresh benchmark snapshot for the press follow-up if they reply. |

---

## Common day-of pitfalls

### Pitfall: Engagement spike crashes Railway

**Sign:** /api/v1/check rate-limit returning 429 to most users.
**Fix:** Bump rate limits in `api/config.py` (`burst_limit`, `public_check_per_min`) and redeploy. Railway autoscales but only within plan limits — check current quota.

### Pitfall: HN flagged

**Sign:** Post slides to /show page after 30 min despite upvotes.
**Possible causes:** Title too hype-y, account too new, posted from a brand-y subdomain. **Fix:** Don't re-post for 7 days. Try a different angle (e.g. lead with the open-source story instead of the product).

### Pitfall: Press email bounces

**Sign:** Permanent SMTP failure on `lily_newman@wired.com` etc.
**Fix:** Verify the email format via [Hunter.io](https://hunter.io) first. Don't ever guess; one wrong email kills the journalist's email server reputation toward you.

### Pitfall: Someone finds a phishing URL Cleanway misses

**Sign:** Top HN comment shows a screenshot.
**Fix:** Welcome it. Reply with: "Good catch — added to our fresh-URL benchmark. Let's see where this lands by next Monday. Source feeds and verdict reasoning are at [link]." Then actually add it.

### Pitfall: Someone questions the privacy architecture

**Sign:** Comment chain about "but you must be logging URLs somehow".
**Fix:** Link to the open-source engine and the privacy diagram. Specifics over claims. "Here's the exact request payload: `{ "domain": "example.com", "locale": "en" }`. No URL, no path. Verifiable in the network tab."

---

## Don't do these

- Don't pay for upvotes. HN will detect, ban, and tell every other dev forum.
- Don't astroturf. Same.
- Don't argue with bad-faith commenters. Save your energy for the curious ones.
- Don't drop product roadmap on launch day. Focus on what's shipped.
- Don't compare yourself to Norton/Bitdefender by name in copy. Stick to defaults (Cloudflare 1.1.1.1 for Families, Safe Browsing) — those are reproducible.

---

## After day 1

- Day 2: send press follow-ups to non-respondents only if your traction supports it (>500 GitHub stars, 1000+ extension installs).
- Day 3: post to /r/cybersecurity (different from /r/privacy).
- Day 7: re-run benchmark, post the week-over-week comparison on X.
- Week 2: Product Hunt launch (lower priority than HN; HN is technical, PH is product).
- Week 3: Reach out to security podcasts (Security Now, Risky Business) if you have momentum.

---

## Success metrics for day 1

- **HN:** ≥100 upvotes, ≥30 comments. Lower bar: ≥20 upvotes (not flagged).
- **X:** ≥50 RTs on the main tweet. Lower bar: ≥10.
- **Reddit /r/privacy:** ≥100 upvotes. Lower bar: ≥30.
- **Press:** 1 reply within 48h. (Most don't reply at all; getting 1 is a win.)
- **Chrome Web Store installs:** ≥50 by EOD. Lower bar: ≥20.

Don't compare to launches by VC-backed teams. They paid for that traffic. Solo open-source launches at these numbers are real wins.
