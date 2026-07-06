"""
ML-based phishing scoring.

Loads the pre-trained CatBoost phishing model and provides fast (<1 ms)
predictions. Used as a signal in the hybrid scoring pipeline (rules + ML).

Two inference backends, tried in order:

  1. **onnxruntime + phishing_model.onnx** — what PRODUCTION runs. ~40 MB RSS,
     ~15 MB wheel, no scipy/pandas/plotly. Fits Railway's 512 MB plan (catboost's
     ~400 MB dependency tree OOM-killed it, so ML used to be silently disabled).
  2. **catboost + phishing_model.cbm** — fallback for local/dev where catboost is
     installed. Authoritative for retraining.

Both backends consume the SAME 27-feature vector (order = model_meta feature_names,
which equals ml_features.FEATURE_NAMES) and are numerically identical
(verified parity: max |Δ| < 1e-7 across a diverse domain set).

If neither backend is available, ml_predict() returns None and the caller
gracefully degrades to rule-based-only scoring.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Optional

logger = logging.getLogger("cleanway.ml_scorer")

# Guards the one-time lazy load so a concurrent caller (e.g. if inference is ever
# moved to a threadpool) can't observe a half-initialised session.
_load_lock = threading.Lock()

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
_ONNX_PATH = os.path.join(_DATA_DIR, "phishing_model.onnx")
_CBM_PATH = os.path.join(_DATA_DIR, "phishing_model.cbm")
_META_PATH = os.path.join(_DATA_DIR, "model_meta.json")

# Module-level lazy-loaded state.
_backend: Optional[str] = None  # "onnx" | "catboost" | None
_onnx_session = None
_onnx_input_name: Optional[str] = None
_cb_model = None
_feature_names: list[str] = []
_model_loaded = False


def _load_meta() -> None:
    """Load the canonical feature-name order the model was trained on."""
    global _feature_names
    with open(_META_PATH, "r") as f:
        meta = json.load(f)
    _feature_names = meta["feature_names"]
    logger.info("ML model meta: %d features, AUC=%s",
                len(_feature_names), meta.get("test_auc"))


def _try_load_onnx() -> bool:
    """Preferred prod path: onnxruntime + phishing_model.onnx."""
    global _onnx_session, _onnx_input_name, _backend
    try:
        import onnxruntime as ort
    except ImportError:
        return False
    if not os.path.exists(_ONNX_PATH):
        return False
    try:
        _onnx_session = ort.InferenceSession(
            _ONNX_PATH, providers=["CPUExecutionProvider"]
        )
        _onnx_input_name = _onnx_session.get_inputs()[0].name
        _load_meta()
        _backend = "onnx"
        logger.info("ML scoring enabled (onnxruntime backend)")
        return True
    except Exception as e:  # pragma: no cover - defensive
        logger.error("Failed to load ONNX model: %s", e)
        return False


def _try_load_catboost() -> bool:
    """Fallback for local/dev: catboost + phishing_model.cbm."""
    global _cb_model, _backend
    try:
        from catboost import CatBoostClassifier
    except ImportError:
        return False
    if not os.path.exists(_CBM_PATH):
        return False
    try:
        _cb_model = CatBoostClassifier()
        _cb_model.load_model(_CBM_PATH)
        _load_meta()
        _backend = "catboost"
        logger.info("ML scoring enabled (catboost fallback backend)")
        return True
    except Exception as e:  # pragma: no cover - defensive
        logger.error("Failed to load CatBoost model: %s", e)
        return False


def _load_model() -> bool:
    """Lazy-load the model on first call. onnxruntime first, catboost fallback.

    Double-checked locking under `_load_lock`: `_model_loaded` is set True only
    AFTER a backend is (or fails to be) populated, so a concurrent caller never
    observes `_model_loaded=True` with a half-initialised session.
    """
    global _model_loaded
    if _model_loaded:
        return _backend is not None

    with _load_lock:
        if _model_loaded:  # another thread finished while we waited
            return _backend is not None
        try:
            if not (_try_load_onnx() or _try_load_catboost()):
                logger.warning(
                    "ML scoring disabled — neither onnxruntime+%s nor catboost+%s available",
                    os.path.basename(_ONNX_PATH), os.path.basename(_CBM_PATH),
                )
        finally:
            _model_loaded = True

    return _backend is not None


def _predict_proba_onnx(feature_vector: list[float]) -> float:
    """Phishing probability via onnxruntime.

    CatBoost's ONNX export emits `probabilities` as a ZipMap —
    seq(map(int64, tensor(float))) — which onnxruntime returns as
    ``[{0: p_benign, 1: p_phishing}]``.
    """
    import numpy as np

    x = np.array([feature_vector], dtype=np.float32)
    outputs = _onnx_session.run(None, {_onnx_input_name: x})
    for out in outputs:
        if isinstance(out, list) and out and isinstance(out[0], dict):
            return float(out[0][1])
        arr = np.asarray(out)
        if arr.ndim == 2 and arr.shape[1] == 2:
            return float(arr[0, 1])
    raise RuntimeError("unexpected ONNX output shape")


def _predict_proba_catboost(feature_vector: list[float]) -> float:
    """Phishing probability via catboost."""
    return float(_cb_model.predict_proba([feature_vector])[0][1])


def ml_predict(domain: str) -> Optional[dict]:
    """
    Run the ML model on a domain. Returns:
      {
        "phishing_probability": 0.0-1.0,
        "prediction": "phishing" | "benign",
        "confidence": 0.0-1.0,
        "backend": "onnx" | "catboost",
      }
    Returns None if no backend is available (graceful degradation to rules).
    """
    if not _load_model():
        return None

    try:
        # Shared feature extractor — lives in api.services.ml_features so
        # inference doesn't drag sklearn (training-only) into the image.
        from api.services.ml_features import extract_ml_features, FEATURE_NAMES

        features = extract_ml_features(domain)
        feature_vector = [features[k] for k in FEATURE_NAMES]

        if _backend == "onnx":
            phishing_prob = _predict_proba_onnx(feature_vector)
        else:
            phishing_prob = _predict_proba_catboost(feature_vector)

        return {
            "phishing_probability": round(phishing_prob, 4),
            "prediction": "phishing" if phishing_prob > 0.5 else "benign",
            "confidence": round(abs(phishing_prob - 0.5) * 2, 4),  # 0-1 scale
            "backend": _backend,
        }

    except Exception as e:
        logger.warning("ML prediction failed for %s: %s", domain, e)
        return None
