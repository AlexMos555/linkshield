"""The phishing class must not teach "a site on a hosting platform is phishing".

With URLhaus gone (2026-10-21) the corpus is all names from domain feeds,
and a quarter of them are tenants of hosting platforms (pages.dev,
vercel.app, blogspot.com …) against 5% tenants in the benign class
(ml/train_model.TENANT_SHARE). A model trained on that scored
official-shop.myshopify.com 0.59 and myshop.tw1.ru 0.66 — every shop and
blog on a platform 'ml_suspicious'. load_phishing_domains caps tenants the
way load_benign_domains does, so the tenant's own label decides.
"""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ml.train_model as tm  # noqa: E402
from api.services.ml_features import shared_tenant  # noqa: E402
from api.services.scoring import registrable_domain  # noqa: E402


def _write_feed(path, hosts):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "source"])
        for h in hosts:
            w.writerow([f"https://{h}/", "Test"])


def test_tenants_are_capped_in_share_and_per_platform(tmp_path, monkeypatch):
    names = [f"evil-{i}.example" for i in range(900)]
    pages = [f"login-{i}.pages.dev" for i in range(500)]
    vercel = [f"wallet-{i}.vercel.app" for i in range(50)]
    hosts = [h for trio in zip(pages[:50], vercel, names[:50]) for h in trio] + pages[50:] + names[50:]
    _write_feed(tmp_path / "phishtank.csv", hosts)
    monkeypatch.setattr(tm, "DATA_DIR", str(tmp_path))
    out = tm.load_phishing_domains(1200)
    tenants = [h for h in out if shared_tenant(h)[0]]
    assert len(tenants) <= int(1200 * tm.PHISH_TENANT_SHARE)
    per_platform = {}
    for h in tenants:
        per_platform[shared_tenant(h)[0]] = per_platform.get(shared_tenant(h)[0], 0) + 1
    assert max(per_platform.values()) <= tm.PHISH_TENANTS_PER_PLATFORM
    assert set(per_platform) == {"pages.dev", "vercel.app"}
    # The names the cap frees room for are all kept.
    assert set(names) <= set(out)


def test_the_benign_class_holds_at_least_as_many_tenants():
    """Phishing does live on platforms, but "is a tenant" must not be a
    phishing signal: the benign class (real + synthetic tenants, four times
    the size) carries at least as many tenants as the phishing class."""
    benign = (tm.TENANT_SHARE + tm.SYNTHETIC_TENANT_SHARE) * tm.N_BENIGN
    assert tm.PHISH_TENANT_SHARE * tm.N_PHISHING <= benign


# ── The replacement guard: never overwrite the served model with one that
# flags more real sites ──
#
# 2026-10-21: a model trained on the commercially clean corpus passed every
# gate in retrain-ml.yml (AUC 0.90, regression hosts, <= 3 held-out RU sites
# flagged by the verdict) and still put 41 of the 270 real Russian sites in
# data/benchmark_legit_ru.txt over 0.6 — the served model puts 0 there.

def test_held_out_legit_hosts_are_the_real_site_sets():
    hosts = tm.load_held_out_legit()
    assert len(hosts) >= 500
    assert len(set(hosts)) == len(hosts)
    with open(tm.HELD_OUT_FILES[1], encoding="utf-8") as f:
        phish = set(tm._hosts_in_file(f))
    assert not set(hosts) & phish


def test_replace_when_no_worse():
    ok, why = tm.replacement_decision(candidate_flagged=2, committed_flagged=0, n=570)
    assert ok, why


def test_keep_the_served_model_when_the_candidate_flags_more_real_sites():
    ok, why = tm.replacement_decision(candidate_flagged=64, committed_flagged=0, n=570)
    assert not ok
    assert "64" in why and "570" in why


def test_no_comparison_possible_means_replace():
    """A feature-schema change (features_version) makes the committed model
    unreadable against the new vectors; the other gates still judge it."""
    ok, _ = tm.replacement_decision(candidate_flagged=10, committed_flagged=None, n=570)
    assert ok


# ── The clean-corpus strata (2026-10-22) ──
#
# On the CC0 feeds alone the 12,000-sample benign class (6% Russian, 12 IDN
# names, weighted 1:1) gave a model that scored 69 of the 539 held-out real
# Russian sites above 0.6. These strata are what fixed it.

def _write_tranco(path, head, tail=()):
    """`head` ranked 1.., `tail` from 10,001 (the long tail)."""
    rows = [f"{i},{d}" for i, d in enumerate(head, start=1)]
    rows += [f"{i},{d}" for i, d in enumerate(tail, start=10001)]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_synthetic_tenants_follow_the_phishing_platform_mix():
    import random

    tail = [f"realsite{i}.com" for i in range(200)] + ["toolongforalabelbecauseitgoesonandonandon.com", "ab.com"]
    phishing = ["login-1.pages.dev", "login-2.pages.dev", "login-3.pages.dev", "wallet.vercel.app",
                "paypal.account-verify.tk"]
    out = tm.synthetic_tenants(tail, phishing, 150, random.Random(0))
    assert len(out) == 150
    assert all(shared_tenant(h)[0] for h in out)
    assert all(h.split(".")[0].startswith("realsite") for h in out)   # real long-tail names only
    phishing_mix = [h for h in out if shared_tenant(h)[0] in {"pages.dev", "vercel.app"}]
    assert len(phishing_mix) >= 150 * (1 - tm.SYNTHETIC_UNIFORM_SHARE) * 0.8
    assert sum(h.endswith(".pages.dev") for h in out) > sum(h.endswith(".vercel.app") for h in out)
    # the rest spread over the site platforms, which the feeds may not report at all
    assert {shared_tenant(h)[0] for h in out} - {"pages.dev", "vercel.app"} <= set(tm._site_platform_suffixes())
    assert len({shared_tenant(h)[0] for h in out}) > 20
    assert {"myshopify.com", "tw1.ru"} <= set(tm._site_platform_suffixes())
    assert out == tm.synthetic_tenants(tail, phishing, 150, random.Random(0))   # reproducible


def test_no_phishing_tenants_means_no_synthetic_ones():
    import random

    assert tm.synthetic_tenants(["realsite.com"], ["paypal.account-verify.tk"], 10, random.Random(0)) == []


def test_brand_named_sites_are_real_names_carrying_a_brand():
    out = tm.brand_named_sites(["vkgosuslugi.ru", "gosuslugi.ru", "sberbank-ast.ru", "example.org", "kvartira.ru"])
    assert "vkgosuslugi.ru" in out and "sberbank-ast.ru" in out
    assert "gosuslugi.ru" not in out   # the brand itself is not a look-alike
    assert "example.org" not in out and "kvartira.ru" not in out


def test_only_generic_lure_words_make_the_lure_word_stratum():
    """sncf-connect.com teaches that "connect" is not proof; login.gov would
    teach that "login" is not either, and the obvious lures need it to be."""
    assert tm._has_generic_lure_word("sncf-connect.com")
    assert tm._has_generic_lure_word("aami-rewards.com.au")
    assert not tm._has_generic_lure_word("secure-booker.com")
    assert not tm._has_generic_lure_word("my-account-connect.com")
    assert not tm._has_generic_lure_word("example.org")


def test_the_verified_brand_file_feeds_the_benign_class_minus_the_held_out_sites():
    verified = tm.load_verified_brand_sites()
    assert {"gosuslugi29.ru", "sberbank1.ru"} <= set(verified)
    held_out = tm.load_held_out()
    # The regional portals in the held-out LEGIT set stay out of training.
    assert sum(registrable_domain(h) in held_out for h in verified) >= 14


def test_the_new_strata_reach_the_benign_class(tmp_path, monkeypatch):
    monkeypatch.setattr(tm, "DATA_DIR", str(tmp_path))
    _write_tranco(tmp_path / "top-1m.csv",
                  [f"famous{i}.com" for i in range(100)],
                  [f"tail{i}.org" for i in range(300)]
                  + [f"russkiy{i}.ru" for i in range(100)]
                  + ["xn--80aswg.xn--p1ai", "xn--e1afmkfd.xn--p1ai", "vkgosuslugi.ru", "gosuslugi92.ru",
                     "leadgid.com", "klar.mx"])
    _write_tranco(tmp_path / "top-1m-subdomains.csv", [f"www.site{i}.com" for i in range(60)])
    held_out = frozenset({"gosuslugi92.ru"})
    phishing = ["login-1.pages.dev", "login-2.pages.dev", "evil.example"]
    benign = tm.load_benign_domains(400, exclude=phishing, held_out=held_out)
    assert len(benign) == 400
    assert {"xn--80aswg.xn--p1ai", "xn--e1afmkfd.xn--p1ai"} <= set(benign)   # every IDN name
    assert sum(d.startswith("russkiy") for d in benign) >= int(400 * tm.RU_PLD_SHARE)
    assert "vkgosuslugi.ru" in benign   # a brand-named real site
    assert sum(bool(shared_tenant(d)[0]) for d in benign) == int(400 * tm.SYNTHETIC_TENANT_SHARE)
    assert any(d.endswith(".pages.dev") for d in benign)
    verified = [d for d in set(benign) if d in set(tm.load_verified_brand_sites())]
    assert verified and all(benign.count(d) == tm.VERIFIED_REPEAT for d in verified)
    assert "gosuslugi92.ru" not in benign   # held out: in Tranco and in the verified file
    assert not set(benign) & tm.GATE_HOSTS
    assert not set(benign) & set(phishing)


def test_gate_hosts_never_reach_the_phishing_class(tmp_path, monkeypatch):
    _write_feed(tmp_path / "phishtank.csv", ["secure-login.wasmer.app", "sberbank-online.pages.dev", "evil.example"])
    monkeypatch.setattr(tm, "DATA_DIR", str(tmp_path))
    assert tm.load_phishing_domains(10) == ["evil.example"]


def test_the_split_keeps_a_domain_and_its_subdomains_together():
    assert tm.split_group("a.evil.com") == tm.split_group("b.evil.com") == "evil.com"
    assert tm.split_group("one.pages.dev") != tm.split_group("two.pages.dev")


def test_the_averaged_ensemble_exports_a_classifier_onnx(tmp_path):
    """catboost.sum_models drops the top-level loss, and the ONNX export of
    such a model is a regressor with one raw 'predictions' output that
    ml_scorer._predict_proba_onnx refuses ("unexpected ONNX output shape").
    The averaged model must export label + probabilities like a member."""
    import pytest

    catboost = pytest.importorskip("catboost")
    ort = pytest.importorskip("onnxruntime")
    import numpy as np

    rng = np.random.default_rng(0)
    X = rng.normal(size=(300, 4))
    y = (X[:, 0] + rng.normal(size=300) > 0).astype(int)
    members = [catboost.CatBoostClassifier(iterations=20, verbose=0, random_seed=s, class_weights=[2.0, 1.0])
               .fit(X, y) for s in range(3)]
    model = tm.average_members(members)
    path = str(tmp_path / "ensemble.onnx")
    model.save_model(path, format="onnx")
    session = ort.InferenceSession(path)
    out = session.run(None, {session.get_inputs()[0].name: X[:1].astype(np.float32)})
    assert isinstance(out[1], list) and set(out[1][0]) == {0, 1}
    assert abs(out[1][0][1] - model.predict_proba(X[:1])[0, 1]) < 1e-4
    mean = np.mean([m.predict_proba(X[:5])[:, 1] for m in members], axis=0)
    assert np.allclose(model.predict_proba(X[:5])[:, 1], mean, atol=0.02)   # the members' mean
