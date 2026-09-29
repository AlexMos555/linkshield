"""
Pure-feature extraction for the CatBoost phishing scorer.

Moved out of ``ml/train_model.py`` because that module imports sklearn for
training — which we don't ship on the production image. Inference needs
only catboost + numpy, and the shared feature extractor here has no
third-party imports beyond our own utilities in ``api.services``.

Both inference (``ml_scorer.ml_predict``) and training
(``ml/train_model.py``) import ``extract_ml_features`` + ``FEATURE_NAMES``
from here, guaranteeing the feature contract stays in sync.
"""
from __future__ import annotations

from api.services.scoring import (
    _check_brand_in_subdomain,
    _check_homograph,
    _check_typosquatting_v2,
    _digit_ratio,
    _extract_tld,
    _has_fake_tld_in_subdomain,
    _is_url_shortener,
    _shannon_entropy,
    _special_char_count,
    _subdomain_labels,
    registrable_domain,
    _SUSPICIOUS_KEYWORDS,
    HIGH_RISK_TLDS,
    MEDIUM_RISK_TLDS,
    TOP_DOMAINS,
)
from api.services.url_features import (
    _max_brand_similarity,
    bigram_score,
    char_diversity,
    consecutive_consonants_max,
    trigram_uniqueness,
    vowel_consonant_ratio,
)

# Known hosting platforms where subdomains can be anyone's — kept in sync
# with ml/train_model.py's HOSTING_PLATFORMS so training and inference agree.
HOSTING_PLATFORMS: frozenset[str] = frozenset(
    {
        "pages.dev", "workers.dev", "netlify.app", "vercel.app",
        "herokuapp.com", "github.io", "gitlab.io", "web.app",
        "firebaseapp.com", "appspot.com", "azurewebsites.net",
        "cloudfront.net", "s3.amazonaws.com", "blob.core.windows.net",
        "onrender.com", "fly.dev", "railway.app", "deno.dev",
        "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com",
        "myshopify.com", "square.site", "carrd.co", "notion.site",
    }
)


def host_shape(domain: str) -> tuple[str, str, list[str]]:
    """(registrable domain, registered name, labels left of it) — PSL-aware.

    The name is judged where it was registered, not by its last two labels:
    kvs.gov.spb.ru is ('gov.spb.ru', 'gov', ['kvs']) — one subdomain of the
    St Petersburg government's name — where the last two labels made it
    three levels under 'spb', the same name as every other *.spb.ru host.
    bbc.co.uk is ('bbc.co.uk', 'bbc', []), not a subdomain of 'co'. Shared
    by the model's features and the logged ones (url_features), so a name
    means one thing in both.
    """
    base = registrable_domain(domain)
    name = base.split(".")[0] if "." in base else base
    return base, name, _subdomain_labels(domain)


def has_suspicious_keyword(name: str) -> bool:
    """scoring._check_suspicious_keywords' test, on the registered name.

    That rule reads the name from the last two labels, so paypal-login.spb.ru
    and vk-login.nov.ru were 'spb' and 'nov' to it and had no keyword; the
    scorer's own signal is left as it is.
    """
    return any(part in _SUSPICIOUS_KEYWORDS for part in name.lower().replace("_", "-").split("-"))


def extract_ml_features(domain: str) -> dict[str, float]:
    """Extract features for the ML model — domain string only, no API calls.

    Structure is read against the public suffix list (host_shape):
    dot_count, subdomain_depth, name_length, in_top_domains,
    has_suspicious_keyword and the name the lexical features read
    (user_part) count from the registrable domain.
    features_version 4 (api.services.url_features.FEATURES_VERSION).
    """
    base, name, sub_labels = host_shape(domain)
    tld = _extract_tld(domain)

    # Check if this is a subdomain on a hosting platform
    is_hosting_subdomain = base in HOSTING_PLATFORMS
    parts = domain.split(".")
    user_part = parts[0] if len(parts) > 2 and is_hosting_subdomain else name

    f: dict[str, float] = {}

    # ── Length features ──
    f["domain_length"] = len(domain)
    f["name_length"] = len(name)
    f["user_part_length"] = len(user_part)
    # Dots with the public suffix counted as one label: example.com and
    # herzen.spb.ru are 1, www.example.com and kvs.gov.spb.ru are 2.
    f["dot_count"] = len(sub_labels) + (1 if "." in base else 0)
    f["hyphen_count"] = domain.count("-")

    # ── Character ratio features ──
    f["digit_count"] = sum(c.isdigit() for c in user_part)
    f["digit_ratio"] = _digit_ratio(user_part)
    f["special_char_count"] = _special_char_count(domain)
    f["alpha_count"] = sum(c.isalpha() for c in user_part)

    # ── Entropy & randomness ──
    f["shannon_entropy"] = _shannon_entropy(user_part)
    f["bigram_score"] = bigram_score(user_part)
    f["trigram_uniqueness"] = trigram_uniqueness(user_part)
    f["vowel_consonant_ratio"] = vowel_consonant_ratio(user_part)
    f["max_consecutive_consonants"] = consecutive_consonants_max(user_part)
    f["char_diversity"] = char_diversity(user_part)

    # ── Structural ──
    f["subdomain_depth"] = len(sub_labels)
    f["is_hosting_subdomain"] = 1.0 if is_hosting_subdomain else 0.0
    f["has_fake_tld_subdomain"] = 1.0 if _has_fake_tld_in_subdomain(domain) else 0.0

    # ── TLD risk ──
    f["tld_high_risk"] = 1.0 if tld in HIGH_RISK_TLDS else 0.0
    f["tld_medium_risk"] = 1.0 if tld in MEDIUM_RISK_TLDS else 0.0
    f["in_top_domains"] = 1.0 if base in TOP_DOMAINS and not is_hosting_subdomain else 0.0

    # ── Brand impersonation ──
    typo = _check_typosquatting_v2(domain)
    f["is_typosquat"] = 1.0 if typo else 0.0
    f["brand_in_subdomain"] = 1.0 if _check_brand_in_subdomain(domain) else 0.0
    f["is_homograph"] = 1.0 if _check_homograph(domain) else 0.0
    f["has_suspicious_keyword"] = 1.0 if has_suspicious_keyword(name) else 0.0
    f["is_url_shortener"] = 1.0 if _is_url_shortener(domain) else 0.0

    # ── Max brand similarity (global and Russian brands) ──
    f["max_brand_similarity"] = _max_brand_similarity(user_part)

    return f


# Order-preserving canonical list of feature names. Model training + inference
# must index features by the SAME order, so derive once at import time.
FEATURE_NAMES: list[str] = list(extract_ml_features("example.com").keys())
