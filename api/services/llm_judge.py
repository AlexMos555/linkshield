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
LLM_TIMEOUT_S = 4.0
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


_SYSTEM_PROMPT = (
    "You are a phishing-detection expert reviewing TECHNICAL SIGNALS "
    "from an automated URL scanner. You will NEVER receive the actual "
    "URL or domain — only the feature vector the scanner already "
    "extracted.\n\n"
    "Decide one of: safe / caution / dangerous. Output STRICT JSON "
    "with three fields:\n"
    '  { "verdict": "safe"|"caution"|"dangerous", '
    '"confidence": 0.0-1.0, "one_line_reason": "..." }\n\n'
    "Rules:\n"
    "  * Default to caution if uncertain. NEVER guess safe when "
    "high-risk features are present (typosquat, off-brand favicon, "
    "credential_form_mismatch, free TLD on a young domain with "
    "Let's Encrypt).\n"
    "  * NEVER invent features that aren't in the input.\n"
    "  * one_line_reason must be ≤120 chars, plain English, no "
    "markdown, no domain names (you don't see any).\n"
    "  * If the scanner already saw blocklist_hits > 0, the verdict "
    "MUST be dangerous.\n"
    "  * If tranco_ranked is true with tranco_weight ≤ -10 AND no "
    "credential_form_mismatch / favicon_cloned / typosquat_brand: "
    "lean safe.\n"
)


async def _call_claude(features: dict) -> Optional[dict]:
    """Call Claude with the feature payload. Returns parsed dict or
    None on any failure. Never raises into the caller's hot path."""
    try:
        import anthropic  # late import — optional dependency
    except ImportError:
        return None

    try:
        client = anthropic.Anthropic(timeout=LLM_TIMEOUT_S)
        resp = client.messages.create(
            # Haiku is the right tool here: low latency, cheap,
            # plenty of reasoning for a 3-class classification.
            model="claude-haiku-4-5-20251001",
            max_tokens=200,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": json.dumps(features, ensure_ascii=False),
            }],
        )
        for block in resp.content:
            if getattr(block, "type", None) != "text":
                continue
            text = (block.text or "").strip()
            if not text:
                continue
            # Strip ```json ... ``` fences the model sometimes adds.
            if text.startswith("```"):
                text = text.split("```", 2)[-1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.rsplit("```", 1)[0].strip()
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            verdict = parsed.get("verdict")
            confidence = parsed.get("confidence")
            reason = parsed.get("one_line_reason")
            if verdict not in ("safe", "caution", "dangerous"):
                continue
            if not isinstance(confidence, (int, float)):
                continue
            if not isinstance(reason, str) or not reason:
                continue
            return {
                "verdict": verdict,
                "confidence": max(0.0, min(float(confidence), 1.0)),
                "one_line_reason": reason[:140],
            }
    except Exception as exc:
        logger.warning("LLM judge call failed: %s", exc)
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
