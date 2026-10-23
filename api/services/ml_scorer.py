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

Feature data: two features are read from data files, not from the name —
in_top_domains / is_homograph from data/top_100k.json and the tenant
features from data/public_suffixes_in_top.json. model_meta.json records the
sha256 of the copies the model was trained on (feature_data), and the model
is served exactly those (ml_features.resolve_feature_data): the live files,
or the archived ones in data/feature_data/ after the list moved on without a
new model. When neither is there the model is NOT served — ml_predict()
returns None (rules only), backend_status() says 'feature_data_mismatch' and
the error is logged — because a model fed a popularity list it never saw
scores real sites as phishing without any visible failure.
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
# The data files the model was trained on (ml_features.FeatureData), or None
# with the reason in _feature_data_problem; _feature_data_source says where
# they were found ('live', or the archive path).
_feature_data = None
_feature_data_problem: Optional[str] = None
_feature_data_source: Optional[str] = None


def _load_meta() -> None:
    """Load the canonical feature-name order the model was trained on, and
    the feature data files it was trained on."""
    global _feature_names, _feature_data, _feature_data_problem, _feature_data_source
    with open(_META_PATH, "r") as f:
        meta = json.load(f)
    _feature_names = meta["feature_names"]
    logger.info("ML model meta: %d features, AUC=%s",
                len(_feature_names), meta.get("test_auc"))
    from api.services.ml_features import resolve_feature_data

    data, where = resolve_feature_data(meta, _DATA_DIR)
    _feature_data = data
    _feature_data_source = where if data is not None else None
    _feature_data_problem = None if data is not None else where
    if data is None:
        logger.error("ML scoring disabled — %s. Rules-only scoring until the model and data/ agree "
                     "(train a model on data/, or bring back the archived feature files).", where)
    elif where != "live":
        logger.warning("ML model served from archived feature data (%s): data/ has a newer popularity "
                       "list than the model was trained on; the next model trained on data/ retires it", where)


def onnx_session_options(ort):
    """One thread, no spinning. Every call scores ONE row of 27 features — a
    sub-millisecond tree walk. onnxruntime's default pool has a thread per
    core the container can SEE (the whole Railway host) and spin-waits after
    each run: measured 41 ms of CPU per prediction against 0.2 ms with one
    thread, and 3.5 ms of wall time on the event loop against 1 ms. Same
    model, same outputs. See docs/runbooks/capacity.md."""
    opts = ort.SessionOptions()
    opts.intra_op_num_threads = 1
    opts.inter_op_num_threads = 1
    opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    opts.add_session_config_entry("session.intra_op.allow_spinning", "0")
    return opts


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
            _ONNX_PATH, sess_options=onnx_session_options(ort), providers=["CPUExecutionProvider"]
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
    if not _load_model() or _feature_data is None:
        return None

    try:
        # Shared feature extractor — lives in api.services.ml_features so
        # inference doesn't drag sklearn (training-only) into the image.
        from api.services.ml_features import extract_ml_features, FEATURE_NAMES

        features = extract_ml_features(domain, _feature_data)
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


def backend_status() -> str:
    """Which ML backend is actually live right now: 'onnx' | 'catboost' |
    'feature_data_mismatch' (a model loaded, but not the data files it was
    trained on — so it is not served) | 'disabled'.

    Loads lazily and is cheap to call repeatedly — used by the /stats endpoint so
    we can VERIFY from prod whether ML is firing, instead of silently degrading to
    rule-based scoring with no visibility (the fail-soft path returns None quietly).
    """
    _load_model()
    if _backend and _feature_data is None:
        return "feature_data_mismatch"
    return _backend or "disabled"


def is_serving() -> bool:
    """Does ml_predict() score anything in this process?"""
    return backend_status() in ("onnx", "catboost")


def model_status() -> dict:
    """Is the ML model actually usable in THIS process?

    scoring.py calls ml_predict() for every domain but only emits a reason
    when the probability clears 0.6, so a missing "ML model:" reason proves
    nothing about whether the model loaded. Without this, the only way to
    know the container shipped a working model was to read its logs.

    Triggers the same lazy load as a real prediction (idempotent), so a
    /health/deep hit after a deploy is a genuine end-to-end check.
    """
    loaded = _load_model() and _feature_data is not None
    return {
        "loaded": loaded,
        "backend": _backend,
        "model_file": os.path.exists(_ONNX_PATH),
        # 'live', the archived feature files the model is served from, or
        # None with `feature_data_problem` saying why the model is not served.
        "feature_data": _feature_data_source,
        "feature_data_problem": _feature_data_problem,
    }
