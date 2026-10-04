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

from typing import Optional

from api.services.hosting_platforms import tenant_suffix_of
from api.services.scoring import (
    _SCORER_SHARED_SUFFIXES,
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


def shared_tenant(domain: str) -> tuple[Optional[str], Optional[str]]:
    """(the shared suffix `domain` is a tenant of, the tenant's own label),
    or (None, None) when the host is a registered name or a subdomain of one.

    The suffixes are every one the scorer itself knows to be shared
    (scoring._SCORER_SHARED_SUFFIXES: the hand list, the curated
    data/hosting_platforms.json and the public suffixes found in the Tranco
    top-100k), so ledgerlogin-home.wasmer.app, x.webador.com, foo.work.gd
    and evil.s3.amazonaws.com are tenants, not subdomains of the platform's
    own name — features_version 4 knew 26 platforms and read 'wasmer' as the
    name of every site on wasmer.app. The tenant's label is the one directly
    left of the suffix: www.robinhoodlogin.webador.com is 'robinhoodlogin'.

    A suffix that registrable_domain() already reads as public is a
    REGISTRY, not a platform: kvs.gov.spb.ru is a name under the spb.ru
    zone and bbc.co.uk is a name under co.uk, and both stay what host_shape
    says they are. The platform's own hosts (github.io, www.github.io,
    app.netlify.com — hosting_platforms.OPERATOR_HOSTS) are not tenants.
    """
    dom = (domain or "").lower().strip(".")
    suffix = tenant_suffix_of(dom, _SCORER_SHARED_SUFFIXES)
    if suffix is None or registrable_domain(dom).endswith("." + suffix):
        return None, None
    return suffix, dom[: -(len(suffix) + 1)].split(".")[-1]


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
    (user_part) count from the registrable domain. On a shared hosting
    suffix (shared_tenant) the lexical features read the tenant's label and
    the suffix's popularity is not the tenant's.
    features_version 5 (api.services.url_features.FEATURES_VERSION).
    """
    base, name, sub_labels = host_shape(domain)
    tld = _extract_tld(domain)

    # A tenant's site on a hosting platform: the name someone chose is the
    # label under the shared suffix, and the platform's rank says nothing
    # about it.
    tenant_suffix, tenant = shared_tenant(domain)
    is_hosting_subdomain = tenant_suffix is not None
    user_part = tenant if is_hosting_subdomain else name

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
    f["has_suspicious_keyword"] = 1.0 if has_suspicious_keyword(user_part) else 0.0
    f["is_url_shortener"] = 1.0 if _is_url_shortener(domain) else 0.0

    # ── Max brand similarity (global and Russian brands) ──
    f["max_brand_similarity"] = _max_brand_similarity(user_part)

    return f


# Order-preserving canonical list of feature names. Model training + inference
# must index features by the SAME order, so derive once at import time.
FEATURE_NAMES: list[str] = list(extract_ml_features("example.com").keys())
