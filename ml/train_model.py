"""
Train CatBoost ML model for phishing URL detection.

Data sources:
  - Positive (phishing): PhishTank verified CSV
  - Negative (benign): Tranco Top 10K domains

Features: 30+ numeric features extracted from URL/domain only
  (no API calls needed — model runs locally in <1ms per URL)
"""

import csv
import json
import os
import sys
import time
from urllib.parse import urlparse

import numpy as np
from catboost import CatBoostClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Feature extraction is shared with inference — single source of truth.
# See api/services/ml_features.py. Training-only code below adds sklearn
# bits; inference never has to import sklearn.
from api.services.ml_features import (  # noqa: F401 — re-exported for back-compat
    HOSTING_PLATFORMS,
    extract_ml_features,
    FEATURE_NAMES,
)

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "data")





def load_phishing_domains(max_n: int = 10000) -> list[str]:
    csv_path = os.path.join(DATA_DIR, "phishtank.csv")
    domains = set()
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "")
            try:
                host = urlparse(url).hostname
                if host:
                    domains.add(host.lower())
            except Exception:
                continue
            if len(domains) >= max_n:
                break
    return list(domains)


def load_benign_domains(max_n: int = 12000) -> list[str]:
    """Benign negatives sampled from the Tranco top-1M — LONG TAIL included.

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
    """
    import random

    rng = random.Random(42)
    csv_path = os.path.join(DATA_DIR, "top-1m.csv")
    head: list[str] = []  # rank <= 10k (famous)
    tail: list[str] = []  # rank 10k-1M (long tail)
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) != 2:
                continue
            try:
                rank = int(parts[0])
            except ValueError:
                continue
            (head if rank <= 10000 else tail).append(parts[1].lower())

    n_head = min(len(head), max_n // 4)  # ~25% famous
    n_tail = min(len(tail), max_n - n_head)  # ~75% long tail
    benign = rng.sample(head, n_head) + rng.sample(tail, n_tail)
    rng.shuffle(benign)
    return benign


def train():
    print("=" * 60)
    print("Cleanway ML Model Training — CatBoost")
    print("=" * 60)

    # ── Load data ──
    print("\nLoading data...")
    phishing = load_phishing_domains(12000)
    phish_set = set(phishing)
    # Exclude any benign that also appears in the phishing feed (compromised-legit
    # domains show up in both) so labels stay clean.
    benign = [d for d in load_benign_domains(15000) if d not in phish_set][:12000]
    print(f"  Phishing domains: {len(phishing)}")
    print(f"  Benign domains:   {len(benign)}")

    # ── Extract features ──
    print("\nExtracting features...")
    start = time.time()

    X_rows = []
    y_labels = []

    for domain in phishing:
        try:
            features = extract_ml_features(domain)
            X_rows.append([features[k] for k in FEATURE_NAMES])
            y_labels.append(1)  # phishing
        except Exception:
            continue

    for domain in benign:
        try:
            features = extract_ml_features(domain)
            X_rows.append([features[k] for k in FEATURE_NAMES])
            y_labels.append(0)  # benign
        except Exception:
            continue

    X = np.array(X_rows)
    y = np.array(y_labels)
    print(f"  Features extracted: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"  Time: {time.time() - start:.1f}s")
    print(f"  Class balance: {sum(y)} phishing / {len(y) - sum(y)} benign")

    # ── Split ──
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
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
            "train_samples": len(X_train),   # 80% split actually fit
            "total_samples": len(X),         # full labeled corpus (what copy cites)
            "test_auc": round(auc, 4),
            "hosting_platforms": list(HOSTING_PLATFORMS),
        }, f, indent=2)
    print(f"Metadata saved to: {meta_path}")

    print("\n" + "=" * 60)
    print("DONE. Model ready for integration.")


if __name__ == "__main__":
    train()
