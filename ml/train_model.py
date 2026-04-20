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


def load_benign_domains(max_n: int = 10000) -> list[str]:
    json_path = os.path.join(DATA_DIR, "top_10k.json")
    with open(json_path, "r") as f:
        data = json.load(f)
    return list(data.keys())[:max_n]


def train():
    print("=" * 60)
    print("LinkShield ML Model Training — CatBoost")
    print("=" * 60)

    # ── Load data ──
    print("\nLoading data...")
    phishing = load_phishing_domains(10000)
    benign = load_benign_domains(8000)
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

    # Save feature names
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump({
            "feature_names": FEATURE_NAMES,
            "n_features": len(FEATURE_NAMES),
            "train_samples": len(X_train),
            "test_auc": round(auc, 4),
            "hosting_platforms": list(HOSTING_PLATFORMS),
        }, f, indent=2)
    print(f"Metadata saved to: {meta_path}")

    print("\n" + "=" * 60)
    print("DONE. Model ready for integration.")


if __name__ == "__main__":
    train()
