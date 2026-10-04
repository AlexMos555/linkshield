"""
Train CatBoost ML model for phishing URL detection.

Data sources (refreshed by scripts/refresh_training_feeds.py, weekly in
.github/workflows/retrain-ml.yml; all three files are gitignored):
  - Positive (phishing): data/phishtank.csv — URLhaus full dump + OpenPhish
  - Negative (benign):   data/top-1m.csv — Tranco top-1M registrable domains
                         data/top-1m-subdomains.csv — Tranco top-1M with
                         subdomains, for the host-shape stratum: names under
                         Russian zones, subdomains of registered sites and
                         tenants of the curated hosting platforms (see
                         load_benign_domains)
  - Held out: every host in HELD_OUT_FILES, by registrable domain, is kept
    out of BOTH classes, so those sets stay an honest evaluation.

Features: 27 numeric features extracted from the domain only
  (api/services/ml_features.py, shared with inference — no API calls, the
  model runs locally in <1ms per URL).

catboost and scikit-learn are imported inside train(): the loaders and
build_feature_matrix() are importable without them, which is how the test
suite checks that training and serving build the same vector.
"""

import csv
import ipaddress
import json
import os
import random
import sys
import time
from typing import Iterable, Optional
from urllib.parse import urlparse

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Feature extraction is shared with inference — single source of truth.
# See api/services/ml_features.py. Training-only code below adds sklearn
# bits; inference never has to import sklearn.
from api.services.hosting_platforms import TENANT_SUFFIXES, is_user_content_host  # noqa: E402
from api.services.ml_features import (  # noqa: E402
    extract_ml_features,
    shared_tenant,
    FEATURE_NAMES,
)
from api.services.scoring import (  # noqa: E402
    _SCORER_SHARED_SUFFIXES,
    _is_under_shared_suffix,
    _ru_registrable_domain,
    _subdomain_labels,
    is_hosting_platform_site,
    registrable_domain,
)
from api.services.url_features import FEATURES_VERSION  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(ROOT, "data")
MODEL_DIR = os.path.join(ROOT, "data")

# Evaluation sets that must never be trained on: the Russian false-positive
# and look-alike sets (scripts/eval_ru_heuristics.py) and the weekly
# benchmark's legitimate-site sample (scripts/eval_fresh_urls.py). Matched by
# registrable domain, so kvs.gov.spb.ru in a set also keeps every other
# *.gov.spb.ru host out of training — near-duplicates would leak the answer.
# 96 of the LEGIT hosts and 106 of the benchmark's are in the Tranco top-1M,
# 161 LEGIT hosts in its subdomain list.
HELD_OUT_FILES = (
    os.path.join(ROOT, "tests", "data", "ru_heuristics_legit.txt"),
    os.path.join(ROOT, "tests", "data", "ru_heuristics_phish.txt"),
    os.path.join(ROOT, "data", "benchmark_legit_ru.txt"),
)

# Share of the benign class drawn from Tranco's subdomain list (see
# load_benign_domains), and of that stratum at most this much from names
# under Russian public suffixes.
SHAPE_SHARE = 0.25
RU_ZONE_SHARE_OF_SHAPES = 0.25
# Share of the benign class that is tenants of the curated hosting
# platforms — on top of the shape stratum, out of the registrable-domain
# strata, which have 9,000 samples to spare: taken out of the shapes, the
# subdomain stratum lost a third and the model flagged twice as many
# www.<site> hosts.
TENANT_SHARE = 0.05
# Tenants per platform in the pool the tenant stratum is drawn from. Of the
# 4,895 tenants of the curated platforms in the 2026-10-04 list, 2,280 were
# CloudFront distributions and 1,046 SharePoint hosts, machine-named
# (d25mc9onekmja4.cloudfront.net); a plain sample would teach the model that
# a random label under a platform is benign and never show it the 71 GitHub
# Pages sites, 88 Blogspot blogs or 40 pages.dev sites, which carry the
# names people give their sites.
TENANTS_PER_PLATFORM = 20
# Subdomain levels (left of the registrable domain, or of the shared suffix
# for a tenant) a host-shape sample may have: www.example.com,
# kvs.gov.spb.ru and foo.github.io are 1, zenit.kfis.gov.spb.ru 2.
MAX_SHAPE_DEPTH = 2


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _hosts_in_file(lines: Iterable[str]) -> list[str]:
    """First part of a '<host> | …' line, '#' comments and blanks skipped."""
    out = []
    for raw in lines:
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.split(" | ")[0].strip().lower())
    return out


def load_held_out(paths: Iterable[str] = HELD_OUT_FILES) -> frozenset[str]:
    """Registrable domains of every evaluation host. A missing file is an
    error: training on a set it is later scored against would pass silently."""
    regs = set()
    for path in paths:
        with open(path, encoding="utf-8") as f:
            regs.update(registrable_domain(h) for h in _hosts_in_file(f))
    return frozenset(regs)


def _read_tranco(path: str) -> list[tuple[int, str]]:
    ranked = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) != 2:
                continue
            try:
                ranked.append((int(parts[0]), parts[1].lower()))
            except ValueError:
                continue
    return ranked


def load_phishing_domains(max_n: int = 12000, held_out: frozenset[str] = frozenset()) -> list[str]:
    """Unique hosts of the phishing feed: every NAME first, IP literals after.

    URLhaus is mostly malware served from bare IPs. Taken in file order, the
    first 12,000 hosts of the 2026-09-29 feed were 10,961 IPs and 1,039
    names, while the feed held 3,753 names: the model that scores domain
    names saw 28% of the phishing names there were, and its held-out AUC was
    mostly an IP-versus-name score. IPs still fill the class, since they are
    what the analyzer passes for an IP-based URL.
    """
    csv_path = os.path.join(DATA_DIR, "phishtank.csv")
    seen: set[str] = set()
    names: list[str] = []
    ips: list[str] = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            try:
                host = urlparse(row.get("url", "")).hostname
            except ValueError:
                continue
            if not host:
                continue
            host = host.lower()
            if host in seen or registrable_domain(host) in held_out:
                continue
            seen.add(host)
            (ips if _is_ip_literal(host) else names).append(host)
    return (names + ips)[:max_n]


def _tenant_depth(host: str, suffix: str) -> int:
    """Labels between the tenant's host and its shared suffix: foo.github.io
    is 1, www.foo.github.io 2."""
    return len(host[: -(len(suffix) + 1)].split("."))


def _shape_pool(ranked: list[tuple[int, str]], exclude: set[str],
                held_out: frozenset[str]) -> tuple[list[str], list[str], list[str]]:
    """(names under a Russian public suffix, subdomains of registered sites,
    tenants of the curated hosting platforms)."""
    ru_zone: list[str] = []
    subdomains: list[str] = []
    tenants: list[str] = []
    for _, host in ranked:
        if host in exclude or host.endswith(".arpa") or registrable_domain(host) in held_out:
            continue
        # A hosting tenant (foo.github.io, bar.tw1.ru) is someone's own NAME
        # under a shared suffix, not a subdomain of a registered site: its
        # popularity says nothing about the next tenant's, so it is its own
        # stratum, from the curated platforms only (is_hosting_platform_site),
        # never a page on a user-content host (forms.yandex.ru).
        if is_hosting_platform_site(host):
            suffix, _ = shared_tenant(host)
            if suffix and not is_user_content_host(host) and _tenant_depth(host, suffix) <= MAX_SHAPE_DEPTH:
                tenants.append(host)
            continue
        depth = len(_subdomain_labels(host))
        if _ru_registrable_domain(host):
            if depth <= MAX_SHAPE_DEPTH:
                ru_zone.append(host)
        elif 1 <= depth <= MAX_SHAPE_DEPTH and not _is_under_shared_suffix(host):
            subdomains.append(host)
    return ru_zone, subdomains, tenants


def _cap_per_platform(tenants: list[str], rng: random.Random) -> list[str]:
    """At most TENANTS_PER_PLATFORM tenants of each suffix, platforms in a
    fixed order so the pool is reproducible for a seed."""
    by_suffix: dict[str, list[str]] = {}
    for host in tenants:
        by_suffix.setdefault(shared_tenant(host)[0] or "", []).append(host)
    pool: list[str] = []
    for suffix in sorted(by_suffix):
        hosts = by_suffix[suffix]
        pool += rng.sample(hosts, min(len(hosts), TENANTS_PER_PLATFORM))
    return pool


def load_benign_domains(max_n: int = 12000, exclude: Iterable[str] = (),
                        held_out: frozenset[str] = frozenset()) -> list[str]:
    """Benign negatives from Tranco: famous, long tail, and host shapes.

    CRITICAL (2026-07-06 fix): the previous version sampled benign ONLY from
    top_10k.json. Training benign purely on famous domains taught the model
    "not-famous => phishing", which flagged ~58% of real legit long-tail domains
    (klar.mx, konfio.mx, gob.mx, ...) as phishing at serving time. AUC on the
    balanced test set looked great (0.9983) only because the test's legit half
    was ALSO top-10k — a distribution the model never has to face in production.

    Fix: stratified sample — a slice of top-10k (famous domains stay negatives so
    `in_top_domains` remains a valid signal) + a large uniform sample of rank
    10k-1M so the model learns legitimate domains exist across the whole
    popularity spectrum and must use real lexical/structural signals to separate
    them from phishing.

    Host shapes (2026-09-29): Tranco's default list holds registrable
    domains only, so no benign sample ever had a subdomain, while the
    phishing feed is full hostnames. The model learned "has a subdomain =>
    phishing": it scored 92% of the real hosts in Tranco's subdomain list
    above 0.6 (www.example.com 0.98, docs.google.com 0.91) and every
    kvs.gov.spb.ru-shaped government host 0.92-0.99. And Tranco folds every
    name under a Russian regional zone into the zone (spb.ru ranks, not
    herzen.spb.ru). So SHAPE_SHARE of the class comes from the same
    provider's list WITH subdomains: names under Russian public suffixes
    (up to RU_ZONE_SHARE_OF_SHAPES of the stratum) and hosts one or two
    levels under a registered site; and, on top of it, TENANT_SHARE of the
    class from tenants of the curated hosting platforms (at most
    TENANTS_PER_PLATFORM of each). Reverse-DNS names and tenants of suffixes
    outside the curated lists are left out, and so is every host whose
    registrable domain is held out (HELD_OUT_FILES) — the shapes, never the
    evaluation hosts themselves.

    Tenants (2026-10-04): the 2026-09-29 model had no benign tenant at all
    (the stratum excluded them), so is_hosting_subdomain was a phishing-only
    feature and it scored facebook.github.io 0.98, blog.wordpress.com 0.98
    and tailwindcss.netlify.app 1.00. Popular tenants are real sites with
    the names real people give them (malsup.github.io, canoninc-my.sharepoint.com).
    """
    rng = random.Random(42)
    exclude = set(exclude)

    head: list[str] = []  # rank <= 10k (famous)
    tail: list[str] = []  # rank 10k-1M (long tail)
    for rank, domain in _read_tranco(os.path.join(DATA_DIR, "top-1m.csv")):
        if domain in exclude or registrable_domain(domain) in held_out:
            continue
        (head if rank <= 10000 else tail).append(domain)

    subdomain_path = os.path.join(DATA_DIR, "top-1m-subdomains.csv")
    if not os.path.exists(subdomain_path):
        raise FileNotFoundError(
            f"{subdomain_path} is missing — run scripts/refresh_training_feeds.py. "
            "Without it the benign class has no subdomain shapes and the model "
            "flags almost every host with a subdomain."
        )
    ru_zone, subdomains, tenants = _shape_pool(_read_tranco(subdomain_path), exclude, held_out)
    n_shape = int(max_n * SHAPE_SHARE)
    n_ru = min(len(ru_zone), int(n_shape * RU_ZONE_SHARE_OF_SHAPES))
    shapes = rng.sample(ru_zone, n_ru)
    shapes += rng.sample(subdomains, min(len(subdomains), n_shape - n_ru))
    tenant_pool = _cap_per_platform(tenants, rng)
    shapes += rng.sample(tenant_pool, min(len(tenant_pool), int(max_n * TENANT_SHARE)))
    taken = set(shapes)
    head = [d for d in head if d not in taken]
    tail = [d for d in tail if d not in taken]

    n_pld = max_n - len(shapes)
    n_head = min(len(head), n_pld // 4)  # ~25% famous
    n_tail = min(len(tail), n_pld - n_head)  # ~75% long tail
    benign = rng.sample(head, n_head) + rng.sample(tail, n_tail) + shapes
    rng.shuffle(benign)
    return benign


def build_feature_matrix(domains: Iterable[str]) -> tuple[list[str], list[list[float]]]:
    """Rows in FEATURE_NAMES order — the vector ml_scorer.ml_predict() feeds
    the served model for the same domain (tests/test_ml_feature_parity.py)."""
    kept, rows = [], []
    for domain in domains:
        try:
            features = extract_ml_features(domain)
        except Exception:
            continue
        kept.append(domain)
        rows.append([features[k] for k in FEATURE_NAMES])
    return kept, rows


def _names_only_metrics(hosts: list[str], y_true: np.ndarray, y_proba: np.ndarray) -> Optional[dict]:
    """The same held-out split without IP literals: how the model does on
    the domain names it is there to judge (IPs separate trivially)."""
    mask = np.array([not _is_ip_literal(h) for h in hosts])
    yt, yp = y_true[mask], y_proba[mask]
    if len(set(yt.tolist())) < 2:
        return None
    from sklearn.metrics import roc_auc_score

    phish, benign = yp[yt == 1], yp[yt == 0]
    return {
        "n_phishing": int(len(phish)),
        "n_benign": int(len(benign)),
        "auc": round(float(roc_auc_score(yt, yp)), 4),
        "recall_at_0.6": round(float((phish > 0.6).mean()), 4),
        "recall_at_0.85": round(float((phish > 0.85).mean()), 4),
        "benign_flagged_at_0.6": round(float((benign > 0.6).mean()), 4),
    }


def train():
    from catboost import CatBoostClassifier
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.model_selection import train_test_split

    print("=" * 60)
    print("Cleanway ML Model Training — CatBoost")
    print("=" * 60)

    # ── Load data ──
    print("\nLoading data...")
    held_out = load_held_out()
    phishing = load_phishing_domains(12000, held_out)
    # Exclude any benign that also appears in the phishing feed (compromised-legit
    # domains show up in both) so labels stay clean.
    benign = load_benign_domains(12000, exclude=phishing, held_out=held_out)
    n_ips = sum(_is_ip_literal(d) for d in phishing)
    n_shapes = sum(bool(_subdomain_labels(d)) or bool(_ru_registrable_domain(d)) for d in benign)
    n_tenants = sum(shared_tenant(d)[0] is not None for d in benign)
    print(f"  Held out:         {len(held_out)} registrable domains (evaluation sets)")
    print(f"  Phishing domains: {len(phishing)} ({len(phishing) - n_ips} names, {n_ips} IPs)")
    print(f"  Benign domains:   {len(benign)} ({n_shapes} host shapes, {n_tenants} of them hosting tenants)")

    # ── Extract features ──
    print("\nExtracting features...")
    start = time.time()
    phishing, X_phish = build_feature_matrix(phishing)
    benign, X_benign = build_feature_matrix(benign)
    hosts = phishing + benign
    X = np.array(X_phish + X_benign)
    y = np.array([1] * len(phishing) + [0] * len(benign))
    print(f"  Features extracted: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"  Time: {time.time() - start:.1f}s")
    print(f"  Class balance: {sum(y)} phishing / {len(y) - sum(y)} benign")

    # ── Split ──
    idx_train, idx_test = train_test_split(
        np.arange(len(y)), test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_test, y_train, y_test = X[idx_train], X[idx_test], y[idx_train], y[idx_test]
    print(f"\n  Train: {len(X_train)}, Test: {len(X_test)}")

    # ── Train CatBoost ──
    print("\nTraining CatBoost model...")
    start = time.time()

    model = CatBoostClassifier(
        iterations=500,
        depth=6,
        learning_rate=0.1,
        l2_leaf_reg=3,
        auto_class_weights="Balanced",
        random_seed=42,
        verbose=100,
    )
    model.fit(X_train, y_train, eval_set=(X_test, y_test), early_stopping_rounds=50)

    train_time = time.time() - start
    print(f"  Training time: {train_time:.1f}s")

    # ── Evaluate ──
    print("\n" + "=" * 60)
    print("EVALUATION")
    print("=" * 60)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["benign", "phishing"]))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]:>5}  FP={cm[0][1]:>5}")
    print(f"  FN={cm[1][0]:>5}  TP={cm[1][1]:>5}")

    auc = roc_auc_score(y_test, y_proba)
    print(f"\nROC AUC: {auc:.4f}")
    names_only = _names_only_metrics([hosts[i] for i in idx_test], y_test, y_proba)
    print(f"Names only (no IP literals): {names_only}")

    # ── Feature importance ──
    print("\nTop 15 Feature Importances:")
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for i in range(min(15, len(FEATURE_NAMES))):
        idx = sorted_idx[i]
        print(f"  {FEATURE_NAMES[idx]:<30} {importances[idx]:.2f}")

    # ── Inference speed ──
    print("\nInference speed:")
    start = time.time()
    for _ in range(1000):
        model.predict(X_test[:1])
    elapsed = time.time() - start
    print(f"  {elapsed/1000*1000:.2f}ms per prediction (1K iterations)")

    # ── Save model ──
    model_path = os.path.join(MODEL_DIR, "phishing_model.cbm")
    model.save_model(model_path)
    print(f"\nModel saved to: {model_path}")

    # ── Export ONNX for lean production inference ──
    # Prod runs onnxruntime (~40 MB RSS) instead of catboost (~400 MB deps) so
    # the model fits Railway's 512 MB plan. Keep BOTH artifacts in sync: the
    # .cbm is authoritative for retraining, the .onnx is what ships. See
    # api/services/ml_scorer.py (onnxruntime-first, catboost fallback).
    onnx_path = os.path.join(MODEL_DIR, "phishing_model.onnx")
    model.save_model(onnx_path, format="onnx")
    print(f"ONNX model saved to: {onnx_path}")

    # Save feature names
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump({
            "feature_names": FEATURE_NAMES,
            "n_features": len(FEATURE_NAMES),
            "features_version": FEATURES_VERSION,
            "train_samples": len(X_train),   # 80% split actually fit
            "total_samples": len(X),         # full labeled corpus (what copy cites)
            "test_auc": round(auc, 4),
            "test_names_only": names_only,
            "phishing_names": len(phishing) - n_ips,
            "phishing_ips": n_ips,
            "benign_host_shapes": n_shapes,
            "benign_tenants": n_tenants,
            "held_out_registrable_domains": len(held_out),
            # The suffixes the tenant feature knows (ml_features.shared_tenant).
            "shared_suffixes": len(_SCORER_SHARED_SUFFIXES | TENANT_SUFFIXES),
        }, f, indent=2)
    print(f"Metadata saved to: {meta_path}")

    print("\n" + "=" * 60)
    print("DONE. Model ready for integration.")


if __name__ == "__main__":
    train()
