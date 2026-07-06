"""ML scorer tests — ONNX inference + regression guards.

These lock in two things that broke in prod before 2026-07-06:
  1. The model must actually LOAD and score (it was silently disabled when
     catboost was absent — now served via onnxruntime).
  2. The model must NOT flag legit long-tail domains as phishing (the old model,
     trained on top-10k-only benign, gave klar.mx/konfio.mx/gob.mx ~0.99 → a
     ~58% false-positive rate on real legit domains).
"""
from __future__ import annotations

import pytest

from api.services.ml_scorer import ml_predict, _load_model
import api.services.ml_scorer as ml_scorer


def test_model_loads_and_reports_backend():
    assert _load_model() is True, "ML model must load (onnxruntime or catboost)"
    assert ml_scorer._backend in ("onnx", "catboost")


def test_ml_predict_shape():
    r = ml_predict("google.com")
    assert r is not None
    assert set(r) >= {"phishing_probability", "prediction", "confidence", "backend"}
    assert 0.0 <= r["phishing_probability"] <= 1.0


def test_famous_domain_is_benign():
    assert ml_predict("google.com")["phishing_probability"] < 0.1
    assert ml_predict("wikipedia.org")["phishing_probability"] < 0.1


@pytest.mark.parametrize("domain", ["klar.mx", "konfio.mx", "clip.mx", "gob.mx",
                                    "cornershopapp.com", "leadgid.com"])
def test_legit_longtail_not_flagged(domain):
    """Regression guard for the 2026-07-06 retrain. The OLD (top-10k-only) model
    scored all of these ~0.99 phishing. The retrained model must keep them well
    under the ml_high_risk (>0.85) and ml_suspicious (>0.6) firing thresholds."""
    prob = ml_predict(domain)["phishing_probability"]
    assert prob < 0.6, f"{domain} should read benign, got {prob:.3f}"


@pytest.mark.parametrize("domain", ["paypal.account-verify.tk", "track.safeinflow.com"])
def test_obvious_phish_flagged(domain):
    assert ml_predict(domain)["phishing_probability"] > 0.8


def test_onnx_matches_catboost_when_both_present():
    """If catboost is installed (dev), onnxruntime output must match it — this is
    the contract that lets prod drop the 400 MB catboost dep."""
    try:
        from catboost import CatBoostClassifier
    except ImportError:
        pytest.skip("catboost not installed (prod image) — parity checked in dev/CI-dev")
    import os
    from api.services.ml_features import extract_ml_features, FEATURE_NAMES

    cbm = os.path.join(os.path.dirname(ml_scorer.__file__), "..", "..", "data",
                       "phishing_model.cbm")
    if not os.path.exists(cbm):
        pytest.skip("no .cbm artifact")
    cb = CatBoostClassifier()
    cb.load_model(cbm)
    for d in ["google.com", "klar.mx", "track.safeinflow.com", "paypal.account-verify.tk"]:
        vec = [extract_ml_features(d)[k] for k in FEATURE_NAMES]
        cb_p = float(cb.predict_proba([vec])[0][1])
        our_p = ml_predict(d)["phishing_probability"]
        assert abs(cb_p - our_p) < 1e-3, f"{d}: catboost {cb_p} vs served {our_p}"
