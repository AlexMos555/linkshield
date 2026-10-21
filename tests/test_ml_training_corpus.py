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
    out = tm.load_phishing_domains(1000)
    tenants = [h for h in out if shared_tenant(h)[0]]
    assert len(tenants) <= int(1000 * tm.PHISH_TENANT_SHARE)
    per_platform = {}
    for h in tenants:
        per_platform[shared_tenant(h)[0]] = per_platform.get(shared_tenant(h)[0], 0) + 1
    assert max(per_platform.values()) <= tm.PHISH_TENANTS_PER_PLATFORM
    assert set(per_platform) == {"pages.dev", "vercel.app"}
    # The names the cap frees room for are all kept.
    assert set(names) <= set(out)


def test_the_tenant_share_is_close_to_the_benign_one():
    """Not equal — phishing does live on platforms — but no longer a
    five-to-one signal."""
    assert tm.PHISH_TENANT_SHARE <= 2 * tm.TENANT_SHARE


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
