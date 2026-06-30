# Cleanway open-source carve-out plan

> **Status**: draft for review (2026-06-18). Not yet executed.
> See section "Decision required" at the bottom — the owner needs
> to make 3 explicit choices before any of this lands.

## Why open-source the engine

1. **Credibility moat for go-to-market.** No competitor's detection
   engine is auditable. We can be — and Hacker News / The Verge /
   security Twitter all reward that posture.
2. **Acquirer due-diligence shortcut.** When an acquihire conversation
   starts (Bitdefender / NordSecurity / Avast / 1Password), the first
   ask is "show us the engine." If it's already open, that's day-zero
   trust. If it's closed, it's weeks of legal + code review.
3. **Contributor pipeline.** Solo maintenance burden is the #1 risk
   to the product. A small contributor community (even 5-10 people)
   takes intel-source updates + favicon hash refreshes + locale
   translations off the founder's plate.
4. **Adversarial-review compounding.** Every adversarial workflow
   we've run found real bugs (see the 11 fixes from #17 Watchtower,
   the 5 fixes for #21 LLM Judge, etc.). Public eyes find more.

## What goes open vs closed

The split is by **business sensitivity**, not by code size or
craft. Open everything that could be reverse-engineered from the
extension binary anyway. Keep closed anything that's monetizable
or that could compromise users if its internals were public.

### OPEN — proposed `github.com/cleanway-ai/cleanway-engine`

| Module | Why open | Risk if open |
|---|---|---|
| `api/services/analyzer.py` | The 18-check fan-out. Reverse-engineerable from extension network traces anyway. | None — the value is integration + intel sources, not the algorithm. |
| `api/services/scoring.py` | Rule weights, threshold tiers. Already documented per-signal on the block page. | None — phishing kits can already test against the live API. |
| `api/services/llm_judge.py` (incl. system prompt) | LLM-as-judge pattern is the headline novelty. Worth showing off. | The system prompt is the secret sauce — but it's also a contributor moat. |
| `api/services/watchtower.py` | crt.sh-based typosquat detection. | None — fully derivable from public CT logs. |
| `api/services/favicon_hash.py` | Brand-clone detection via SHA-256 prefix. | None — but the **gallery** stays closed because curated brand-host lists are operationally valuable. |
| `api/services/tranco.py` + `scripts/refresh_tranco.py` | Tranco popularity wrapper. | None — wraps a public list. |
| `api/services/doh_gateway.py` | DoH gateway with phishing block. | None — same pattern as Cloudflare's families resolver. |
| `api/services/competitor_verdicts.py` | Cloudflare 1.1.1.1 for Families adapter. | None. |
| `scripts/eval_fresh_urls.py` | The reproducible benchmark itself. **This is the credibility moat — must be open.** | None. |
| `tests/test_*.py` for all of the above | Reproducibility + onboarding for contributors. | None. |
| `ml/train_model.py` + the 27-feature extractor | CatBoost training script. | The TRAINED model weights stay closed (operational moat, not algorithmic). |
| Block page UI (`packages/extension-core/src/content/block-page.js`) | Open-source UX. | None — UX is reverse-engineerable. |

**License recommendation: MIT.** Maximum adoption, no GPL contagion
into closed components, compatible with eventual acquirer integration.

### CLOSED — stays in `github.com/AlexMos555/linkshield` (private)

| Module | Why closed |
|---|---|
| Stripe wiring (`api/routers/payments.py`, `api/services/pricing.py`) | Pricing model + dunning + chargeback logic is competitive intelligence. |
| Family Hub crypto (`api/services/family_*.py`, `mobile/src/services/family-crypto.ts`) | E2E key management — security risk if openly reviewed before formal audit. |
| Audit log (`api/services/audit_log.py` + migration 014) | Compliance surface; opening it = roadmap for attackers to identify gaps. |
| Trained ML model (`data/phishing_model.cbm`) | Operational moat. The training SCRIPT stays open so anyone can train their own. |
| Brand favicon gallery hashes (`api/data/brand_favicons.json`) | Curated list — operationally valuable. The detection LOGIC is open; the curated DATA stays closed. |
| Intel-source API keys (`.env*`) | Obvious. |
| Customer-facing copy, brand assets | No reason to open; not where the value is. |

### License footnote

MIT-license **everything in the open repo**, with one carve-out:
the LLM Judge system prompt (in `llm_judge.py`) carries an
attribution-required notice in the docstring so derivative works
credit "Cleanway LLM-as-judge pattern (cleanway.ai)". Not legally
enforceable beyond MIT but socially compounds the credibility moat.

## Implementation roadmap (3 sprints)

### Sprint 1: Repo split (3-4 days solo work)

1. Create `github.com/cleanway-ai/cleanway-engine` (new public repo)
2. Extract the OPEN modules listed above. Use `git filter-repo` to
   preserve commit history per file — credibility-positive when
   contributors browse history.
3. Add `LICENSE` (MIT), `README.md` (positioning), `CONTRIBUTING.md`
   (we accept PRs, signed-DCO, no obligation to merge), `SECURITY.md`
   (report via security@cleanway.ai, 90-day disclosure).
4. Keep imports working in the private repo via a published Python
   package: `pip install cleanway-engine` from a private PyPI mirror
   (or just a git+https dependency).

### Sprint 2: Documentation & onboarding (2-3 days)

1. `README.md` runs through `eval_fresh_urls.py` in 60 seconds —
   "clone, install, run, see numbers". Anchor: developer can verify
   our claims in one minute.
2. Architecture diagram showing the OPEN + CLOSED boundary.
3. `docs/intel-sources.md` — the list of 16 sources we hit, with
   links and licensing terms (open + paid).
4. Contributor instincts: a `instincts.md` describing what we'd
   accept as a PR (new intel source, new locale, FP fix) vs not
   (new feature surface, new ML model architecture).

### Sprint 3: Marketing launch (1 day)

1. Show HN post: "I open-sourced my anti-phishing engine after
   measuring its recall weekly with the script in this repo". Link the benchmark.
2. Blog post on cleanway.ai/blog covering the why + the split.
3. Cross-post to /r/netsec, lobste.rs, Twitter security crowd.
4. Email 3 journalists who cover security:
   - Andy Greenberg (Wired) — covers privacy + transparency angles
   - Lily Hay Newman (Wired) — same beat
   - Catalin Cimpanu (RisingTongue) — security news heavy

## Risks + mitigations

| Risk | Mitigation |
|---|---|
| Closed-source value erosion | Pricing model, family-crypto, ML model weights stay closed. The engine being open does not commoditise our offering — we sell the *operated service* with intel keys + monitoring + family hub. |
| Phishing kits study the rules and evade | Already happens against any public detector. Our advantage is the breadth of intel sources + ML model + LLM judge, not algorithmic secrecy. |
| Acquirer thinks open-source devalues the deal | The OPPOSITE — acquirers pay more for engines that are auditable. Open == due-diligence shortcut. |
| Contributor adversarial commits | DCO + required CI green + 2-reviewer rule on first 50 contributions. After that case-by-case. |
| License confusion downstream | MIT is the simplest. We do not require contributor agreements (no CLA). All contributions vest under MIT and the original author keeps copyright. |

## Decision required (owner — before any of this lands)

Three explicit choices needed:

1. **Are we OK with MIT license?** (vs Apache 2.0, vs BSL with conversion clause).
   - Default recommendation: MIT.
2. **Brand: `cleanway-engine` or `cleanway-ai/engine`?** Affects future
   org expansion (cleanway-ai/mobile, cleanway-ai/extension, etc.).
   - Default recommendation: `cleanway-ai/engine` (sets up the org).
3. **GitHub Org under whose account?** AlexMos555 personal vs a new
   `cleanway-ai` org (which would require a verified email + payment
   for private repos if any stay private).
   - Default recommendation: new `cleanway-ai` org.

Once those three are decided, Sprint 1 starts. Total to launch: ~7 working days.

## Why this fits the exit-track strategy

From `~/.claude/plans/purring-watching-snowflake.md`:
> Solo + Exit + Unlimited runway. Without team, no credibility
> for serious M&A. Open-source is the cheapest credibility you can buy.

Open-sourcing the engine moves the exit-target acquihire price
from `$50-200k IP-only` to the `$300-700k MAU + open-source brand`
band, even before any user growth materializes. The compound on
the time investment (~7 days) is the highest-leverage move in the
12-month plan.
