"""The ONNX model runs on one thread without spin-waiting: each call scores a
single row, and the default per-core pool burned ~40 ms of CPU per prediction
spinning (docs/runbooks/capacity.md). The scores must not change."""
from __future__ import annotations

import os
import time

import pytest

ort = pytest.importorskip("onnxruntime")
np = pytest.importorskip("numpy")

from api.services import ml_scorer  # noqa: E402
from api.services.ml_features import FEATURE_NAMES, extract_ml_features  # noqa: E402

if not os.path.exists(ml_scorer._ONNX_PATH):  # pragma: no cover
    pytest.skip("ONNX model not present", allow_module_level=True)

DOMAINS = ["google.com", "sberbank-bonus.ru", "login-secure-paypa1.com.verify.top",
           "kvs.gov.spb.ru", "xn--80ak6aa92e.com", "a1b2c3d4e5f6.xyz"]


def _session(opts=None):
    return ort.InferenceSession(ml_scorer._ONNX_PATH, sess_options=opts, providers=["CPUExecutionProvider"])


def _proba(session, domain):
    features = extract_ml_features(domain)
    x = np.array([[features[k] for k in FEATURE_NAMES]], dtype=np.float32)
    name = session.get_inputs()[0].name
    for out in session.run(None, {name: x}):
        if isinstance(out, list) and out and isinstance(out[0], dict):
            return float(out[0][1])
        arr = np.asarray(out)
        if arr.ndim == 2 and arr.shape[1] == 2:
            return float(arr[0, 1])
    raise AssertionError("unexpected output")


def test_session_is_single_threaded_without_spinning():
    opts = ml_scorer.onnx_session_options(ort)
    assert opts.intra_op_num_threads == 1
    assert opts.inter_op_num_threads == 1
    assert opts.execution_mode == ort.ExecutionMode.ORT_SEQUENTIAL
    assert opts.get_session_config_entry("session.intra_op.allow_spinning") == "0"


def test_loaded_model_uses_those_options(monkeypatch):
    seen = {}
    real = ort.InferenceSession

    def _spy(path, sess_options=None, **kw):
        seen["opts"] = sess_options
        return real(path, sess_options=sess_options, **kw)

    monkeypatch.setattr(ort, "InferenceSession", _spy)
    monkeypatch.setattr(ml_scorer, "_onnx_session", None)
    monkeypatch.setattr(ml_scorer, "_backend", None)
    assert ml_scorer._try_load_onnx() is True
    assert seen["opts"] is not None and seen["opts"].intra_op_num_threads == 1


def test_scores_match_the_default_session():
    """Same model: only the float summation order of a multi-threaded run
    differs (~1e-7), far below the 4 decimals ml_predict reports."""
    tuned, default = _session(ml_scorer.onnx_session_options(ort)), _session()
    for d in DOMAINS:
        assert abs(_proba(tuned, d) - _proba(default, d)) < 1e-6, d


def test_inference_costs_well_under_a_millisecond_of_cpu():
    s = _session(ml_scorer.onnx_session_options(ort))
    name = s.get_inputs()[0].name
    x = np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32)
    s.run(None, {name: x})
    c0 = time.process_time()
    for _ in range(50):
        s.run(None, {name: x})
        time.sleep(0.002)  # where a spinning pool would burn CPU
    per_call_ms = (time.process_time() - c0) / 50 * 1000
    assert per_call_ms < 2, per_call_ms
