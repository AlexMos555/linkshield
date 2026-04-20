"""
ML-based phishing scoring.

Loads pre-trained CatBoost model and provides fast (<1ms) predictions.
Used as a signal in the hybrid scoring pipeline (rules + ML).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger("linkshield.ml_scorer")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
_model = None
_feature_names: list[str] = []
_model_loaded = False


def _load_model():
    """Lazy-load CatBoost model on first call."""
    global _model, _feature_names, _model_loaded

    if _model_loaded:
        return _model is not None

    _model_loaded = True

    model_path = os.path.join(_DATA_DIR, "phishing_model.cbm")
    meta_path = os.path.join(_DATA_DIR, "model_meta.json")

    try:
        from catboost import CatBoostClassifier

        _model = CatBoostClassifier()
        _model.load_model(model_path)

        with open(meta_path, "r") as f:
            meta = json.load(f)
            _feature_names = meta["feature_names"]

        logger.info("ML model loaded: %d features, AUC=%s",
                     len(_feature_names), meta.get("test_auc"))
        return True

    except FileNotFoundError:
        logger.warning("ML model not found at %s — ML scoring disabled", model_path)
        return False
    except ImportError:
        logger.warning("catboost not installed — ML scoring disabled")
        return False
    except Exception as e:
        logger.error("Failed to load ML model: %s", e)
        return False


def ml_predict(domain: str) -> Optional[dict]:
    """
    Run ML model on a domain. Returns:
      {
        "phishing_probability": 0.0-1.0,
        "prediction": "phishing" | "benign",
        "confidence": 0.0-1.0,
      }
    Returns None if model not available.
    """
    if not _load_model() or _model is None:
        return None

    try:
        # Shared feature extractor — lives in api.services.ml_features so
        # inference doesn't drag sklearn (training-only) into the image.
        from api.services.ml_features import extract_ml_features, FEATURE_NAMES

        features = extract_ml_features(domain)
        feature_vector = [features[k] for k in FEATURE_NAMES]

        proba = _model.predict_proba([feature_vector])[0]
        phishing_prob = float(proba[1])

        return {
            "phishing_probability": round(phishing_prob, 4),
            "prediction": "phishing" if phishing_prob > 0.5 else "benign",
            "confidence": round(abs(phishing_prob - 0.5) * 2, 4),  # 0-1 scale
        }

    except Exception as e:
        logger.warning("ML prediction failed for %s: %s", domain, e)
        return None
