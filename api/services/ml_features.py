"""
Pure-feature extraction for the CatBoost phishing scorer.

Moved out of ``ml/train_model.py`` because that module imports sklearn for
training — which we don't ship on the production image. Inference needs
only catboost + numpy, and the shared feature extractor here has no
third-party imports beyond our own utilities in ``api.services``.

Both inference (``ml_scorer.ml_predict``) and training
(``ml/train_model.py``) import ``extract_ml_features`` + ``FEATURE_NAMES``
from here, guaranteeing the feature contract stays in sync.

Two data files are features too: data/top_100k.json (in_top_domains,
is_homograph) and data/public_suffixes_in_top.json (which hosts are tenants:
is_hosting_subdomain, and the label every lexical feature reads). A model is
served the copies it was trained on (FeatureData, resolve_feature_data): the
popularity list can change in one commit and the model in a later one. So is
is_typosquat: the scorer's typosquat rule widens between retrains, and a
model is given the answer of the definition it learned
(scoring.TYPOSQUAT_RULE_VERSION, recorded as feature_data.typosquat_rule).
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import AbstractSet, NamedTuple, Optional

from api.services.hosting_platforms import tenant_suffix_of
from api.services.scoring import (
    _DATA_DIR,
    _SCORER_SHARED_SUFFIXES,
    HOSTING_PLATFORMS,
    TYPOSQUAT_RULE_VERSION,
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
    legacy_registrable_domain,
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


class FeatureData(NamedTuple):
    """The data files a model reads as features, loaded, and the typosquat
    rule it learned.

    top_domains      data/top_100k.json: in_top_domains, is_homograph
    shared_suffixes  data/public_suffixes_in_top.json plus the scorer's hand
                     list (scoring._SCORER_SHARED_SUFFIXES): shared_tenant()
    typosquat_rule   the definition is_typosquat reads
                     (scoring.TYPOSQUAT_RULE_VERSION; 1 for a model trained
                     before 2026-10-23)
    """
    top_domains: AbstractSet[str]
    shared_suffixes: AbstractSet[str]
    typosquat_rule: int = TYPOSQUAT_RULE_VERSION


# What the scorer's rules read today — and what a model is trained on
# (ml/train_model.py), so a freshly trained model is served exactly these.
LIVE_FEATURE_DATA = FeatureData(TOP_DOMAINS, _SCORER_SHARED_SUFFIXES, TYPOSQUAT_RULE_VERSION)

# model_meta.json["feature_data"] key → the file in data/ it records.
FEATURE_DATA_FILES = {
    "top_domains": "top_100k.json",
    "public_suffixes_in_top": "public_suffixes_in_top.json",
}
# Copies of feature files a served model still reads after data/ moved on,
# named <stem>.<first 12 hex of sha256><ext> (scripts/build_top_domains.py
# writes and prunes them).
FEATURE_ARCHIVE_DIR = "feature_data"


def file_sha256(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def archive_path(data_dir: str, file: str, sha256: str) -> str:
    stem, ext = os.path.splitext(file)
    return os.path.join(data_dir, FEATURE_ARCHIVE_DIR, f"{stem}.{sha256[:12]}{ext}")


def feature_data_record(data_dir: str = _DATA_DIR, source: str = "") -> dict:
    """What ml/train_model.py writes into model_meta.json["feature_data"]: the
    live files a model is being trained on, by hash, and the typosquat rule
    its is_typosquat reads (typosquat_rule)."""
    record: dict = {}
    for key, file in FEATURE_DATA_FILES.items():
        path = os.path.join(data_dir, file)
        with open(path, encoding="utf-8") as f:
            entries = len(json.load(f))
        record[key] = {"file": file, "sha256": file_sha256(path), "entries": entries}
        if source:
            record[key]["source"] = source
    record["typosquat_rule"] = TYPOSQUAT_RULE_VERSION
    return record


def resolve_feature_data(meta: dict, data_dir: str = _DATA_DIR) -> tuple[Optional[FeatureData], str]:
    """(the feature data `meta` was trained on, where it was found) — or
    (None, why not). Each file is matched by its sha256: the live one in
    data/ first, then its archived copy (FEATURE_ARCHIVE_DIR). No match
    means the model would be fed inputs it never saw: the caller serves no
    model at all (rules only) rather than a wrong one."""
    record = meta.get("feature_data")
    if not isinstance(record, dict):
        return None, "model_meta.json records no feature_data (which top_100k / public-suffix files the model learned)"
    # No record: the model was trained before the rule was versioned, on
    # rule 1. A rule this code does not have: no model, as for a file.
    rule = record.get("typosquat_rule", 1)
    if type(rule) is not int or not 1 <= rule <= TYPOSQUAT_RULE_VERSION:
        return None, (f"model_meta.json feature_data.typosquat_rule is {rule!r}; this code has typosquat rules "
                      f"1..{TYPOSQUAT_RULE_VERSION} (scoring.TYPOSQUAT_RULE_VERSION)")
    rule_note = "" if rule == TYPOSQUAT_RULE_VERSION else f"; is_typosquat rule {rule}"
    paths: dict[str, str] = {}
    for key, file in FEATURE_DATA_FILES.items():
        entry = record.get(key)
        sha = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(sha, str) or entry.get("file") != file:
            return None, f"model_meta.json feature_data.{key} is missing or names another file"
        live, archived = os.path.join(data_dir, file), archive_path(data_dir, file, sha)
        if file_sha256(live) == sha:
            paths[key] = live
        elif file_sha256(archived) == sha:
            paths[key] = archived
        else:
            return None, (f"no {file} with sha256 {sha[:12]}: data/{file} changed and neither a model "
                          f"trained on it nor {os.path.relpath(archived, data_dir)} is there")
    live_dir = os.path.realpath(data_dir) == os.path.realpath(_DATA_DIR)
    if live_dir and all(p == os.path.join(data_dir, FEATURE_DATA_FILES[k]) for k, p in paths.items()):
        live = LIVE_FEATURE_DATA if rule == TYPOSQUAT_RULE_VERSION else LIVE_FEATURE_DATA._replace(typosquat_rule=rule)
        return live, "live" + rule_note
    with open(paths["top_domains"], encoding="utf-8") as f:
        top = frozenset(d.lower() for d in json.load(f))
    with open(paths["public_suffixes_in_top"], encoding="utf-8") as f:
        suffixes = frozenset(d.lower() for d in json.load(f)) | HOSTING_PLATFORMS
    where = ", ".join(sorted({os.path.relpath(p, data_dir) for p in paths.values()}))
    return FeatureData(top, suffixes, rule), where + rule_note


def host_shape(domain: str) -> tuple[str, str, list[str]]:
    """(registrable domain, registered name, labels left of it) — PSL-aware.

    The name is judged where it was registered, not by its last two labels:
    kvs.gov.spb.ru is ('gov.spb.ru', 'gov', ['kvs']) — one subdomain of the
    St Petersburg government's name — where the last two labels made it
    three levels under 'spb', the same name as every other *.spb.ru host.
    bbc.co.uk is ('bbc.co.uk', 'bbc', []), not a subdomain of 'co'. Shared
    by the model's features and the logged ones (url_features), so a name
    means one thing in both.

    Read with scoring.legacy_registrable_domain (the Russian zones, else the
    compound-ccTLD heuristic), not the Public Suffix List the scorer's rules
    read since 2026-10-28: these are the inputs the served model was trained
    on. paypal-secure.my.id is still ('my.id', 'my', ['paypal-secure']) here
    until a retrain moves the features with the model.
    """
    base = legacy_registrable_domain(domain)
    name = base.split(".")[0] if "." in base else base
    return base, name, _subdomain_labels(domain)


def shared_tenant(domain: str,
                  suffixes: Optional[AbstractSet[str]] = None) -> tuple[Optional[str], Optional[str]]:
    """(the shared suffix `domain` is a tenant of, the tenant's own label),
    or (None, None) when the host is a registered name or a subdomain of one.

    The suffixes are every one the scorer itself knows to be shared
    (scoring._SCORER_SHARED_SUFFIXES: the hand list, the curated
    data/hosting_platforms.json and the public suffixes found in the top
    100k — or `suffixes`, a served model's own copy, FeatureData), so
    ledgerlogin-home.wasmer.app, x.webador.com, foo.work.gd
    and evil.s3.amazonaws.com are tenants, not subdomains of the platform's
    own name — features_version 4 knew 26 platforms and read 'wasmer' as the
    name of every site on wasmer.app. The tenant's label is the one directly
    left of the suffix: www.robinhoodlogin.webador.com is 'robinhoodlogin'.

    A suffix that the registrable domain host_shape reads
    (legacy_registrable_domain) already treats as public is a REGISTRY, not
    a platform: kvs.gov.spb.ru is a name under the spb.ru zone and bbc.co.uk
    is a name under co.uk, and both stay what host_shape says they are. The
    platform's own hosts (github.io, www.github.io, app.netlify.com —
    hosting_platforms.OPERATOR_HOSTS) are not tenants.
    """
    dom = (domain or "").lower().strip(".")
    suffix = tenant_suffix_of(dom, _SCORER_SHARED_SUFFIXES if suffixes is None else suffixes)
    if suffix is None or legacy_registrable_domain(dom).endswith("." + suffix):
        return None, None
    return suffix, dom[: -(len(suffix) + 1)].split(".")[-1]


def has_suspicious_keyword(name: str) -> bool:
    """scoring._check_suspicious_keywords' test, on the registered name.

    That rule read the name from the last two labels until 2026-10-27, so
    paypal-login.spb.ru and vk-login.nov.ru were 'spb' and 'nov' to it and
    had no keyword; it reads the registered name now, as this feature always
    has.
    """
    return any(part in _SUSPICIOUS_KEYWORDS for part in name.lower().replace("_", "-").split("-"))


def extract_ml_features(domain: str, data: Optional[FeatureData] = None) -> dict[str, float]:
    """Extract features for the ML model — domain string only, no API calls.

    `data`: the popularity files to read (default LIVE_FEATURE_DATA, what a
    model is trained on); ml_scorer passes the served model's own.

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
    data = LIVE_FEATURE_DATA if data is None else data
    tenant_suffix, tenant = shared_tenant(domain, data.shared_suffixes)
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
    f["has_fake_tld_subdomain"] = 1.0 if _has_fake_tld_in_subdomain(domain, legacy=True) else 0.0

    # ── TLD risk ──
    f["tld_high_risk"] = 1.0 if tld in HIGH_RISK_TLDS else 0.0
    f["tld_medium_risk"] = 1.0 if tld in MEDIUM_RISK_TLDS else 0.0
    f["in_top_domains"] = 1.0 if base in data.top_domains and not is_hosting_subdomain else 0.0

    # ── Brand impersonation ──
    # The typosquat rule the model learned (FeatureData.typosquat_rule): the
    # live one for a model being trained, an older one for a served model
    # trained before the rule last widened.
    typo = _check_typosquatting_v2(domain, data.typosquat_rule)
    f["is_typosquat"] = 1.0 if typo else 0.0
    f["brand_in_subdomain"] = 1.0 if _check_brand_in_subdomain(domain) else 0.0
    f["is_homograph"] = 1.0 if _check_homograph(domain, data.top_domains) else 0.0
    f["has_suspicious_keyword"] = 1.0 if has_suspicious_keyword(user_part) else 0.0
    f["is_url_shortener"] = 1.0 if _is_url_shortener(domain) else 0.0

    # ── Max brand similarity (global and Russian brands) ──
    f["max_brand_similarity"] = _max_brand_similarity(user_part)

    return f


# Order-preserving canonical list of feature names. Model training + inference
# must index features by the SAME order, so derive once at import time.
FEATURE_NAMES: list[str] = list(extract_ml_features("example.com").keys())
