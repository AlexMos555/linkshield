"""LLM Judge for ambiguous verdicts — Strategy #21.

When the rule-based scorer can't make up its mind — score lands in
the caution band (~30-70), no blocklist hit, no allowlist short-
circuit — Claude weighs in with a final verdict. The point isn't
to replace the heuristic; it's to break ties on the ~5% of domains
where 1,000-ish features point in different directions.

How it fits the existing pipeline:

  analyze_domain()
    → 18 parallel checks build `signals`
    → calculate_score() → (score, level, reasons)
    → if level == caution AND no blocklist AND LLM available:
        judge_ambiguous_verdict(signals, score) → optional shift
    → DomainResult ships with confidence_pct + an
      "llm_judge" DomainReason if the LLM weighed in.

Privacy invariants (load-bearing):

  1. The DOMAIN never reaches the LLM. We extract a FEATURE
     vector — the same factual extractions the scorer already
     made — and send those. Pattern-based reasoning beats
     name-based reasoning anyway: "this looks like a paypal
     typosquat" is the signal, not "paypal-secure-login.example".

  2. We cache by sha256 of (sorted feature set + score band).
     Two unrelated domains with the same fingerprint hit the
     same cache entry — that's correct, the answer is about the
     pattern, not the host.

  3. The LLM call has a hard 4-second budget. The analyzer is
     already in a parallel-gather hot path; the judge can never
     stretch the user's checkmark wait by more than its budget.

  4. On any LLM failure (network, schema mismatch, rate-limit,
     SDK exception) we silently fall back to the rule-based
     verdict. The user never sees a degraded experience.

  5. Cap on how far the LLM can shift the verdict: ±20 points.
     This prevents a hallucinated answer from single-handedly
     calling a clearly-safe page dangerous or vice versa.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Configuration — these knobs matter for cost AND safety.
#
# Model choice — this is the "is this site dangerous?" call. We're
# defaulting to Opus 4.8 (flagship reasoning model) because the
# question is high-stakes: a wrong "safe" call costs the user
# their credentials. Haiku 4.5 is the FALLBACK when Opus times
# out or errors. Both knobs are env-tunable for ops:
#
#   LLM_JUDGE_MODEL_PRIMARY=claude-opus-4-8
#   LLM_JUDGE_MODEL_FALLBACK=claude-haiku-4-5-20251001
#   LLM_JUDGE_TIMEOUT_S=10.0
#
# Cost at scale: Opus is ~$15/$75 per million in/out tokens vs
# Haiku $1/$5. We cache aggressively by feature fingerprint so
# the average user-visible call is a cache hit, not a fresh
# Opus run. Real spend depends on the unique-feature-set
# cardinality of caution-band traffic — typically small.
LLM_JUDGE_MODEL_PRIMARY = os.environ.get(
    "LLM_JUDGE_MODEL_PRIMARY", "claude-opus-4-8"
)
LLM_JUDGE_MODEL_FALLBACK = os.environ.get(
    "LLM_JUDGE_MODEL_FALLBACK", "claude-haiku-4-5-20251001"
)
LLM_TIMEOUT_S = float(os.environ.get("LLM_JUDGE_TIMEOUT_S", "10.0"))
LLM_MAX_SHIFT = 20            # max points the judge can move the score
LLM_MIN_CONFIDENCE = 0.6      # below this we ignore the LLM
LLM_CACHE_TTL_S = 7 * 24 * 3600

# Score bands. The judge fires ONLY when level == caution: outside
# this band the rule-based verdict has high-confidence evidence
# (blocklist hit, known-legit allowlist) and we shouldn't second-
# guess it.
CAUTION_LOWER = 30
CAUTION_UPPER = 70


def _llm_available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _extract_judge_features(signals: dict, score: int) -> dict:
    """Sanitize the signal dict into a domain-free feature vector.

    Every field that names the host, the path, or the user is
    dropped. What remains is the same factual extraction the
    scorer used (typosquat target, TLD class, popularity tier,
    SSL grade, etc.) — enough for the LLM to reason about the
    pattern without ever seeing the host.
    """
    # Whitelist of safe-to-share signal keys. Anything not in this
    # list NEVER reaches the LLM. Update with caution.
    SAFE_KEYS = {
        # Threat-intel aggregate (boolean / count form only)
        "blocklist_hits", "alienvault_pulse_count",
        "ipqs_risk_score", "ipqs_phishing",
        "tranco_ranked", "tranco_weight",
        # Brand / favicon (pattern, not host)
        "favicon_cloned", "favicon_brand",
        "typosquat_brand", "typosquat_distance",
        "homograph_detected",
        # Domain shape (no hostname)
        "domain_age_days", "is_ip_based", "registrar",
        "dns_has_mx", "dns_a_count", "dns_ttl",
        # TLS / hosting
        "no_https", "free_ssl", "cert_age_days",
        # HTTP / page features
        "missing_security_headers", "redirect_count",
        "redirect_cross_domain",
        # Credential / form signals
        "credential_form_mismatch", "credential_form_brand",
        # URL shape (no actual url)
        "url_path_depth", "url_length_bucket", "url_pii_leak",
        # Subdomain / structure
        "subdomain_count", "tld_class",
        # Risk meta
        "checks_succeeded", "total_checks",
    }
    out: dict = {}
    for k, v in (signals or {}).items():
        if k not in SAFE_KEYS:
            continue
        # Coerce to JSON-serialisable primitives.
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, (list, tuple)):
            # Lists of primitives only — drop nested objects.
            out[k] = [x for x in v if isinstance(x, (str, int, float, bool))]
        # Everything else (dicts, custom objects) is silently dropped.
    out["heuristic_score"] = max(0, min(int(score), 100))
    return out


def _score_band(score: int) -> str:
    """Discretise the score into a 3-bucket band so cache hits
    work across small score differences."""
    if score < CAUTION_LOWER:
        return "safe"
    if score >= CAUTION_UPPER:
        return "dangerous"
    return "caution"


def _cache_key(features: dict) -> str:
    """Sha256 over a canonical JSON of the feature dict. Domain-
    free by construction (we extracted it ourselves)."""
    payload = json.dumps(features, sort_keys=True)
    return "llm_judge:v1:" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:24]


_SYSTEM_PROMPT = """You are a senior phishing-detection analyst reviewing automated
URL-scanner features. You NEVER see the actual URL or domain —
only the technical feature vector the scanner already extracted.

Your decision affects whether a real user types their password
into a possibly-fake login page. False-safe verdicts cost
credentials. False-dangerous verdicts cost user trust. Optimise
for both, with a small bias toward caution when in doubt.

# ── ANALYSIS PROTOCOL ──

Walk through each signal CATEGORY in order. For each, decide if
it leans safe / dangerous / inconclusive. Then synthesise:

1. THREAT INTEL — `blocklist_hits`, `alienvault_pulse_count`,
   `ipqs_risk_score`, `ipqs_phishing`. If any of these are
   non-zero / True → dangerous is the only correct verdict.

2. POPULARITY — `tranco_ranked`, `tranco_weight`. Top-100k
   domains (`tranco_weight ≤ -10`) are statistically
   unlikely to be fresh phishing kits. But established
   domains CAN be compromised — popularity is a Bayesian
   prior, not a free pass.

3. BRAND IDENTITY — `favicon_cloned`, `favicon_brand`,
   `typosquat_brand`, `typosquat_distance`, `homograph_detected`.
   These are very-high-confidence phishing signatures.
   `favicon_cloned=true` + `tranco_weight≥0` is a near-certain
   credential-theft attempt.

4. DOMAIN AGE & HOSTING — `domain_age_days`, `registrar`,
   `is_ip_based`, `no_https`, `free_ssl`, `cert_age_days`,
   `tld_class`. Fresh domain (<30 days) + free TLD + Let's
   Encrypt + IP-based access is the classic phishing-kit
   fingerprint.

5. CONTENT / FORM SIGNALS — `credential_form_mismatch`,
   `credential_form_brand`, `url_pii_leak`, `redirect_count`,
   `redirect_cross_domain`. `credential_form_mismatch=true`
   is dispositive — that's a form actively pointing the
   user's password at a non-matching host.

6. STRUCTURE — `subdomain_count`, `url_path_depth`,
   `url_length_bucket`, `missing_security_headers`. Soft
   signals — useful as confirmation, not as primary evidence.

# ── DECISION HEURISTICS ──

* If ANY of these are true, verdict is **dangerous**:
  - blocklist_hits > 0
  - credential_form_mismatch = true
  - favicon_cloned = true with off-brand host
  - homograph_detected = true
  - typosquat_distance ≤ 2 AND domain_age_days < 90

* If ALL of these are true, verdict is **safe**:
  - tranco_ranked = true AND tranco_weight ≤ -10
  - No brand-identity red flags
  - No content red flags
  - Domain age unknown OR > 1 year

* Otherwise → **caution**, with confidence reflecting how
  many signals you weighed.

# ── CONFIDENCE RUBRIC ──

* 0.90-1.00 — Multiple independent strong signals agree.
* 0.75-0.89 — One strong signal, consistent context.
* 0.60-0.74 — Reasoned inference, no single strong signal.
* below 0.60 — Genuinely uncertain. (We DROP such verdicts;
  the rule-based score wins. So if you'd output <0.6, you
  may say "caution" with 0.55 — it'll be ignored, which is
  correct.)

# ── SELF-CRITIQUE ──

Before committing your verdict, ask yourself: "what is the
SINGLE strongest counter-argument someone could make?" If
the counter-argument changes your verdict, lower the
confidence. If it doesn't, you're done.

# ── EXAMPLES ──

INPUT:
  blocklist_hits=0, tranco_ranked=true, tranco_weight=-25,
  favicon_cloned=false, typosquat_brand=null,
  domain_age_days=4200, no_https=false, free_ssl=false,
  credential_form_mismatch=false, heuristic_score=35

REASONING (your private chain of thought — do NOT output):
  Threat intel: clean. Popularity: top-1k. Brand identity:
  no red flags. Domain age: 11 years. No content red flags.
  Heuristic at 35 likely reflects long URL or many headers
  missing. Counter-argument: compromise of established sites
  is real but rare. Verdict: safe, 0.88.

OUTPUT (this is what you produce, strict JSON):
{"verdict":"safe","confidence":0.88,
 "one_line_reason":"Established top-ranked domain with no brand-clone or credential signals."}

INPUT:
  blocklist_hits=0, tranco_ranked=false, favicon_cloned=true,
  favicon_brand="paypal", typosquat_brand=null,
  domain_age_days=3, free_ssl=true, no_https=false,
  credential_form_mismatch=true, heuristic_score=58

REASONING (private):
  No blocklist hit yet (kit is fresh). Brand identity: paypal
  favicon on a 3-day-old free-SSL domain → classic kit.
  Form mismatch confirms credential theft. Counter-argument:
  is the form a legitimate federated SSO redirect? But the
  favicon clone + 3-day age rules that out. Verdict:
  dangerous, 0.95.

OUTPUT:
{"verdict":"dangerous","confidence":0.95,
 "one_line_reason":"Brand-clone favicon + form posts to mismatched host on a 3-day-old free-SSL domain — classic kit signature."}

INPUT:
  blocklist_hits=0, tranco_ranked=false,
  favicon_cloned=false, typosquat_brand=null,
  domain_age_days=180, no_https=false, free_ssl=true,
  redirect_count=2, credential_form_mismatch=false,
  heuristic_score=48

REASONING (private):
  Threat intel clean. No popularity signal. No brand red
  flags. Six months old — not fresh. Let's Encrypt is now
  the majority issuer, not a danger signal by itself. A
  couple of redirects — could be A/B testing or analytics.
  Heuristic landed at 48 from many soft signals. Counter-
  argument: is this a known-good corporate redirect chain?
  We can't tell. Genuinely ambiguous. Verdict: caution,
  0.55. (This will be IGNORED by the caller — correct.)

OUTPUT:
{"verdict":"caution","confidence":0.55,
 "one_line_reason":"Soft signals only; insufficient evidence for a confident shift either direction."}

# ── OUTPUT CONTRACT ──

Output STRICT JSON with EXACTLY three fields, no markdown,
no preamble, no chain-of-thought:

  {"verdict":"safe"|"caution"|"dangerous",
   "confidence":0.0-1.0,
   "one_line_reason":"..."}

`one_line_reason` ≤ 130 characters, plain English, no domain
names (you don't see any), no markdown, no quotes inside.
"""


def _parse_judge_output(raw_text: str) -> Optional[dict]:
    """Strict JSON parser for the judge's output. Strips ```fences,
    validates the three-field contract, normalises bounds.

    Returns None on any malformed output so the caller can either
    retry with the fallback model or fall through to template.
    """
    text = (raw_text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.split("```", 2)[-1]
        if text.startswith("json"):
            text = text[4:]
        text = text.rsplit("```", 1)[0].strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    verdict = parsed.get("verdict")
    confidence = parsed.get("confidence")
    reason = parsed.get("one_line_reason")
    if verdict not in ("safe", "caution", "dangerous"):
        return None
    if not isinstance(confidence, (int, float)):
        return None
    if not isinstance(reason, str) or not reason:
        return None
    return {
        "verdict": verdict,
        "confidence": max(0.0, min(float(confidence), 1.0)),
        "one_line_reason": reason[:140],
    }


async def _call_one_model(model: str, features: dict, *, max_tokens: int = 280) -> Optional[dict]:
    """Single call against a specific Claude model. Returns parsed
    verdict dict or None on any failure (network, schema mismatch,
    timeout). Never raises."""
    try:
        import anthropic  # late import — optional dependency
    except ImportError:
        return None

    try:
        # ASYNC client + await — a synchronous anthropic.Anthropic().messages
        # .create() is a blocking network call, and calling it inside this
        # async function (no await / no to_thread) froze the single uvicorn
        # event loop for up to LLM_TIMEOUT_S, stalling EVERY concurrent
        # request while one caution-band verdict waited on Opus. AsyncAnthropic
        # yields to the loop for the duration. (2026-07-04 audit CRITICAL.)
        client = anthropic.AsyncAnthropic(timeout=LLM_TIMEOUT_S)
        resp = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": json.dumps(features, ensure_ascii=False),
            }],
        )
        for block in resp.content:
            if getattr(block, "type", None) != "text":
                continue
            parsed = _parse_judge_output(block.text or "")
            if parsed:
                parsed["model"] = model
                return parsed
    except Exception as exc:
        logger.warning("LLM judge call to %s failed: %s", model, exc)
    return None


async def _call_claude(features: dict) -> Optional[dict]:
    """Tiered Claude call: PRIMARY model (Opus 4.8 by default), with
    Haiku fallback if Opus times out / errors / returns malformed
    JSON. The fallback exists for hot-path resilience — a Claude
    capacity event shouldn't take the judge entirely offline.

    Both models share the same system prompt + few-shot examples.
    Haiku is fast enough to follow the chain-of-thought protocol
    when Opus is unavailable — we just take its verdict with the
    same confidence floor.
    """
    # PRIMARY: Opus 4.8 — flagship reasoner. Worth the latency
    # for the question 'is this site dangerous?'.
    primary = await _call_one_model(LLM_JUDGE_MODEL_PRIMARY, features)
    if primary is not None:
        return primary

    # FALLBACK: Haiku 4.5 — fast, cheap, still a real reasoner.
    # Only fires when primary is unavailable.
    if LLM_JUDGE_MODEL_FALLBACK and LLM_JUDGE_MODEL_FALLBACK != LLM_JUDGE_MODEL_PRIMARY:
        logger.info(
            "LLM judge falling back from %s to %s",
            LLM_JUDGE_MODEL_PRIMARY, LLM_JUDGE_MODEL_FALLBACK,
        )
        return await _call_one_model(LLM_JUDGE_MODEL_FALLBACK, features)
    return None


async def judge_ambiguous_verdict(
    signals: dict, score: int, level: str,
) -> Optional[dict]:
    """Public entry-point — runs the judge when applicable.

    Returns a dict with the LLM's verdict OR None if the judge
    did not run (out of band, no LLM, cache miss + LLM failure).

    Response shape:
      {
        "verdict": "safe"|"caution"|"dangerous",
        "confidence": float,
        "one_line_reason": str,
        "score_shift": int,           # signed delta to apply
        "source": "llm" | "cache",
      }

    The caller decides whether to APPLY the shift; this function
    only proposes.
    """
    # Gate 1: rule-based level already certain → skip.
    if level != "caution":
        return None

    # Gate 2: blocklist hits make the verdict for us already.
    if (signals or {}).get("blocklist_hits", 0) > 0:
        return None

    # Gate 3: LLM availability.
    if not _llm_available():
        return None

    features = _extract_judge_features(signals, score)

    # L1: Redis cache. The same feature pattern across domains
    # hits the same cache entry.
    cache_key = _cache_key(features)
    redis_client = None
    try:
        from api.services.cache import get_redis
        redis_client = await get_redis()
        cached_raw = await redis_client.get(cache_key)
        if cached_raw:
            try:
                cached = json.loads(cached_raw)
                cached["source"] = "cache"
                return _apply_shift_cap(cached, score)
            except Exception:
                pass  # poisoned cache entry — re-call the LLM
    except Exception:
        pass

    # L2: live LLM call. Catch every exception — a crashing SDK
    # release MUST NOT take down the analyzer hot path.
    try:
        llm_out = await _call_claude(features)
    except Exception as exc:
        logger.warning("LLM judge wrapper caught: %s", exc)
        llm_out = None
    if llm_out is None:
        return None

    if llm_out["confidence"] < LLM_MIN_CONFIDENCE:
        # The model itself is uncertain — don't shift the rule
        # verdict in any direction.
        return None

    result = {
        "verdict": llm_out["verdict"],
        "confidence": llm_out["confidence"],
        "one_line_reason": llm_out["one_line_reason"],
        "score_shift": _shift_for_verdict(llm_out["verdict"], score),
        "source": "llm",
    }

    # Write to cache for future identical-pattern hits.
    if redis_client is not None:
        try:
            await redis_client.setex(
                cache_key, LLM_CACHE_TTL_S,
                json.dumps({
                    "verdict": result["verdict"],
                    "confidence": result["confidence"],
                    "one_line_reason": result["one_line_reason"],
                    "score_shift": result["score_shift"],
                }),
            )
        except Exception:
            pass
    return _apply_shift_cap(result, score)


def _shift_for_verdict(verdict: str, score: int) -> int:
    """Translate the LLM's discrete verdict into a signed delta.

    The shift is hard-capped at ±LLM_MAX_SHIFT, so the model can
    move the needle but never overpower hard rule-based evidence.
    """
    if verdict == "dangerous":
        # Target the lower edge of dangerous (70).
        target = 70
        return max(0, min(target - score, LLM_MAX_SHIFT))
    if verdict == "safe":
        # Target the upper edge of safe (29).
        target = 29
        return -min(LLM_MAX_SHIFT, score - target) if score > target else 0
    # "caution" — confirm the rule verdict, no shift.
    return 0


def _apply_shift_cap(result: dict, current_score: int) -> dict:
    """Re-enforce the shift cap on cache-loaded results, in case
    LLM_MAX_SHIFT was lowered between the cache write and read."""
    shift = result.get("score_shift", 0)
    if shift > LLM_MAX_SHIFT:
        result["score_shift"] = LLM_MAX_SHIFT
    elif shift < -LLM_MAX_SHIFT:
        result["score_shift"] = -LLM_MAX_SHIFT
    return result
