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


# Constructed brand + lure-word names on cheap TLDs: what the model is there
# to catch from the name alone. None is in a feed, so none is a training row.
OBVIOUS_LURES = (
    "paypal.account-verify.tk", "apple-id-locked-verify.xyz",
    "paypal-secure-login.top", "appleid-verify-account.xyz", "amazon-account-suspended.top",
    "netflix-billing-update.xyz", "microsoft-login-verify.online", "chase-secure-verify.top",
    "wellsfargo-account-locked.xyz", "coinbase-login-secure.xyz", "binance-wallet-verify.top",
    "facebook-security-check.xyz", "instagram-verify-badge.top", "sberbank-online-verify.top",
    "gosuslugi-login-verify.xyz", "tinkoff-secure-login.top",
)


def test_obvious_phish_flagged():
    """The model scores obvious lures as phishing — measured on a set, not
    on one host. This was `> 0.8` for paypal.account-verify.tk and
    apple-id-locked-verify.xyz alone. On the 2026-10-21 feeds five retrains
    (seeds 42/7/123, two 85% feed subsamples) gave apple-id-locked-verify.xyz
    0.42-0.82, under 0.8 in four, while the median of this set was 0.82-0.90
    in the four that pass below. One host's number is a draw from the
    seed; the set's median is the model. The seed-7 model really was worse
    (median 0.60, 8 of 16 over 0.6) and fails here as it should."""
    probs = sorted(ml_predict(d)["phishing_probability"] for d in OBVIOUS_LURES)
    median = (probs[7] + probs[8]) / 2
    over_suspicious = sum(p > 0.6 for p in probs)
    assert median > 0.8, f"median {median:.3f} over {len(probs)} obvious lures"
    assert over_suspicious >= 12, f"only {over_suspicious}/{len(probs)} lures clear ml_suspicious: {probs}"


@pytest.mark.parametrize("domain", OBVIOUS_LURES)
def test_an_obvious_lure_is_never_safe(domain):
    """What a person gets is the verdict: every lure in the set is at least
    'caution' from the name alone, with the model on."""
    from api.services import scoring

    assert scoring.calculate_score({"domain": domain})[1].value != "safe"


@pytest.mark.parametrize("domain", ["gosuslugi-vhod.netlify.app", "sberbank-online.pages.dev"])
def test_a_brand_lure_on_a_hosting_platform_is_never_safe(domain):
    """Since #80 the name rules flag these (brand_subdomain_abuse), so what
    a retrain must keep is the verdict, as the retrain gate checks: the
    model's number for them moved 0.70-0.88 between weekly retrains, and a
    fixed 0.8 here turned main red after the 2026-10-05 retrain."""
    from api.services import scoring

    assert scoring.calculate_score({"domain": domain})[1].value != "safe"


def test_a_subdomain_of_an_unknown_name_is_suspicious_not_obvious():
    """track.safeinflow.com was in the list above with > 0.8. The model of
    2026-09-28 gave it 0.96 and its apex safeinflow.com 0.09: the whole margin
    was 'has a subdomain', the shortcut that also scored www.dropbox.com 0.98
    and every *.gov.spb.ru host 0.92-0.99. The name itself has no lure in it,
    so since features_version 5 it stays under the ml_high_risk threshold.

    It also had to clear 0.6 (ml_suspicious), and that half asked for the
    shortcut back. The model that gave it 0.77 (2026-10-05) scored 64% of
    track.<site> for 500 Tranco rank-100k-1M .com sites over 0.6 too, and
    8% of Tranco's subdomain hosts; track.safeinflow.com sat at its peers'
    78th percentile, so nothing but the shape put it there. Every retrain on
    the 2026-10-21 feeds (five: three seeds, two feed subsamples) puts it at
    0.30-0.48 and the same legit peers 3-8% over 0.6. What "suspicious"
    can mean for a name with no lure is relative: it ranks above its own
    apex and above famous sites' hosts of the same shape. (Benign lists
    from Majestic + CrUX, 2026-10-22: 0.13-0.17 over an apex at 0.10-0.11,
    peers 0.6-1.4% over 0.6. With CrUX subdomains of every rank it sat at
    0.099 under its apex's 0.102 — train_model.SHAPE_MAX_RANK.)"""
    p = ml_predict("track.safeinflow.com")["phishing_probability"]
    assert p < 0.85, f"track.safeinflow.com={p:.3f} is ml_high_risk: the subdomain shortcut is back"
    for control in ("safeinflow.com", "www.example.com", "docs.google.com", "mail.yandex.ru"):
        c = ml_predict(control)["phishing_probability"]
        assert p > c, f"track.safeinflow.com={p:.3f} does not rank above {control}={c:.3f}"


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
    assert ml_scorer.is_serving()
    for d in ["google.com", "klar.mx", "track.safeinflow.com", "paypal.account-verify.tk"]:
        # The feature data the served model was trained on (live, or archived
        # while data/ already holds a newer popularity list).
        vec = [extract_ml_features(d, ml_scorer._feature_data)[k] for k in FEATURE_NAMES]
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
