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


@pytest.mark.parametrize("domain", ["paypal.account-verify.tk", "apple-id-locked-verify.xyz",
                                    "gosuslugi-vhod.netlify.app"])
def test_obvious_phish_flagged(domain):
    assert ml_predict(domain)["phishing_probability"] > 0.8


def test_a_subdomain_of_an_unknown_name_is_suspicious_not_obvious():
    """track.safeinflow.com was in the list above with > 0.8. The model of
    2026-09-28 gave it 0.96 and its apex safeinflow.com 0.09: the whole margin
    was 'has a subdomain', the shortcut that also scored www.dropbox.com 0.98
    and every *.gov.spb.ru host 0.92-0.99. The name itself has no lure in it,
    so since features_version 5 it clears the ml_suspicious threshold, not
    the ml_high_risk one."""
    assert 0.6 < ml_predict("track.safeinflow.com")["phishing_probability"] < 0.9


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


@pytest.mark.parametrize("domain", ["bit.ly", "t.co", "tinyurl.com", "tiny.cc", "clck.ru"])
def test_a_url_shortener_is_judged_by_the_shortener_rule_not_the_model(domain):
    """A shortener's name says nothing about where the link goes, and the
    url_shortener rule already says so. features_version 5 learned "shortener =
    phishing" from the feeds (they are full of shortened lures), which turned
    every bit.ly / t.co link into "caution" and tiny.cc into "dangerous". The
    model must not add its weight on top of the rule for a known shortener."""
    from api.services.scoring import calculate_score

    _, level, reasons = calculate_score({"domain": domain})
    signals = {r.signal for r in reasons}
    assert "url_shortener" in signals
    assert not signals & {"ml_high_risk", "ml_suspicious", "ml_safe_override"}, signals
    assert level.value != "dangerous"
