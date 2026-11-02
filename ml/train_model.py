"""
Train CatBoost ML model for phishing URL detection.

Data sources (refreshed by scripts/refresh_training_feeds.py, weekly in
.github/workflows/retrain-ml.yml; all three files are gitignored):
  - Positive (phishing): data/phishtank.csv — PhishDestroy, CERT Polska,
                         TweetFeed and Phishunt, capped per feed (until
                         2026-10-21 URLhaus + OpenPhish, both non-commercial)
  - Negative (benign):   data/benign-domains.csv — ranked registrable
                         domains: the Majestic Million (CC BY 3.0) and those
                         of the global Chrome UX Report list (CC BY 4.0)
                         data/benign-hosts.csv — Chrome UX Report top
                         origins, global and Russia (CC BY 4.0), for the
                         host-shape stratum: names under Russian zones,
                         subdomains of registered sites and tenants of the
                         curated hosting platforms (see load_benign_domains).
                         Tranco until 2026-10-22: its default list averages
                         Cloudflare Radar, CC BY-NC 4.0
                         data/typosquat_targets_ru.json — the hand-verified
                         brand-owned and look-alike-but-unrelated real sites
                         (load_verified_brand_sites)
                         Since 2026-10-22 2.4 times the phishing class, with
                         Russian, IDN, brand-named, lure-word and tenant
                         strata (clean-corpus fix, see N_BENIGN)
  - Held out: every host in HELD_OUT_FILES, by registrable domain, is kept
    out of BOTH classes, so those sets stay an honest evaluation; so is
    every host the workflow's gates name (GATE_HOSTS), exactly.
  - Model: the mean of ENSEMBLE_MEMBERS CatBoost models (one file), split
    by registrable domain for the test AUC (split_group).
  - Replacement guard: the committed model is overwritten only when the
    candidate flags no more held-out real sites than it does (see
    REPLACE_TOLERANCE); otherwise train() prints a ::warning:: and leaves
    data/ as it was. `--replace-anyway` overrides. The committed model is
    scored on the feature data IT was trained on (model_meta.json
    feature_data), the candidate on today's files.
  - Feature data: data/top_100k.json and data/public_suffixes_in_top.json
    are model inputs (in_top_domains, is_homograph, the tenant features).
    model_meta.json records their sha256 (feature_data) and ml_scorer serves
    the model those exact copies (ml_features.resolve_feature_data).

Features: 27 numeric features extracted from the domain only
  (api/services/ml_features.py, shared with inference — no API calls, the
  model runs locally in <1ms per URL).

catboost and scikit-learn are imported inside train(): the loaders and
build_feature_matrix() are importable without them, which is how the test
suite checks that training and serving build the same vector.
"""

import collections
import csv
import ipaddress
import json
import os
import random
import re
import sys
import time
from typing import TYPE_CHECKING, Iterable, Optional
from urllib.parse import urlparse

import numpy as np

if TYPE_CHECKING:  # catboost is imported inside train() at run time
    from catboost import CatBoostClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Feature extraction is shared with inference — single source of truth.
# See api/services/ml_features.py. Training-only code below adds sklearn
# bits; inference never has to import sklearn.
from api.services.hosting_platforms import TENANT_SUFFIXES, is_user_content_host  # noqa: E402
from api.services.ml_features import (  # noqa: E402
    FeatureData,
    extract_ml_features,
    feature_data_record,
    has_suspicious_keyword,
    host_shape,
    resolve_feature_data,
    shared_tenant,
    FEATURE_NAMES,
)
from api.services.scoring import (  # noqa: E402
    _SCORER_SHARED_SUFFIXES,
    _is_under_shared_suffix,
    _ru_registrable_domain,
    _subdomain_labels,
    is_hosting_platform_site,
    legacy_registrable_domain,
)
from api.services.url_features import FEATURES_VERSION  # noqa: E402

# The corpus, the held-out matching and the split groups read the registrable
# domain the features do (scoring.legacy_registrable_domain), not the Public
# Suffix List the scorer's rules read since 2026-10-28: the weekly retrain
# must build the same corpus from the same inputs until the features move.

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(ROOT, "data")
MODEL_DIR = os.path.join(ROOT, "data")
# The benign lists scripts/refresh_training_feeds.py writes into DATA_DIR,
# `rank,name` per line: registrable domains (Majestic Million + CrUX
# global) and hosts with subdomains (CrUX top origins, global + Russia).
BENIGN_DOMAINS_CSV = "benign-domains.csv"
BENIGN_HOSTS_CSV = "benign-hosts.csv"
# Written with them: the CrUX month, rows per list, licences (provenance for
# model_meta.json).
BENIGN_SOURCES_JSON = "benign-sources.json"

# Evaluation sets that must never be trained on: the Russian false-positive
# and look-alike sets (scripts/eval_ru_heuristics.py) and the weekly
# benchmark's legitimate-site sample (scripts/eval_fresh_urls.py). Matched by
# registrable domain, so kvs.gov.spb.ru in a set also keeps every other
# *.gov.spb.ru host out of training — near-duplicates would leak the answer.
# 139 of the LEGIT hosts and 109 of the benchmark's are in the Majestic
# Million, 186 and 162 in the CrUX host list (2026-10-22; Tranco top-1M: 96
# and 106).
HELD_OUT_FILES = (
    os.path.join(ROOT, "tests", "data", "ru_heuristics_legit.txt"),
    os.path.join(ROOT, "tests", "data", "ru_heuristics_phish.txt"),
    os.path.join(ROOT, "data", "benchmark_legit_ru.txt"),
)

# Share of the benign class drawn from the host list (BENIGN_HOSTS_CSV, see
# load_benign_domains), and of that stratum at most this much from names
# under Russian public suffixes. 2026-10-22: 0.25 → 0.15 of a 48,000
# larger class (7,200 shapes, was 3,000): at 0.25 a weighted benign class
# made "has a subdomain" a benign trait and track.safeinflow.com ranked
# under its own apex (tests/test_ml_scorer.py).
SHAPE_SHARE = 0.15
RU_ZONE_SHARE_OF_SHAPES = 0.25
# Share of the benign class that is tenants of the curated hosting
# platforms — on top of the shape stratum, out of the registrable-domain
# strata, which have 9,000 samples to spare: taken out of the shapes, the
# subdomain stratum lost a third and the model flagged twice as many
# www.<site> hosts.
TENANT_SHARE = 0.05
# Tenants per platform in the pool the tenant stratum is drawn from. Of the
# 4,895 tenants of the curated platforms in the 2026-10-04 list, 2,280 were
# CloudFront distributions and 1,046 SharePoint hosts, machine-named
# (d25mc9onekmja4.cloudfront.net); a plain sample would teach the model that
# a random label under a platform is benign and never show it the 71 GitHub
# Pages sites, 88 Blogspot blogs or 40 pages.dev sites, which carry the
# names people give their sites.
TENANTS_PER_PLATFORM = 20
# The same cap on the phishing side. The domain feeds the corpus has come
# from since 2026-10-21 (scripts/refresh_training_feeds.py) are a quarter
# hosting tenants (pages.dev, vercel.app, blogspot.com …): against 5% in the
# benign class that made "is a tenant" a phishing feature, and the model
# scored official-shop.myshopify.com 0.59 and myshop.tw1.ru 0.66. Capped
# near the benign share, the tenant's own label decides — which is what the
# tenant guard in retrain-ml.yml checks.
# 2026-10-22: 0.08 / 60 → 0.20 / 200. With the synthetic tenants
# (SYNTHETIC_TENANT_SHARE of the 48,000-sample benign class) the benign
# class holds more tenants than the phishing one, so the cap no longer has
# to hide phishing tenants to keep "is a tenant" neutral — and 27% of the
# fresh PhishTank sample is tenants.
PHISH_TENANT_SHARE = 0.20
PHISH_TENANTS_PER_PLATFORM = 200
# Subdomain levels (left of the registrable domain, or of the shared suffix
# for a tenant) a host-shape sample may have: www.example.com,
# kvs.gov.spb.ru and foo.github.io are 1, zenit.kfis.gov.spb.ru 2.
MAX_SHAPE_DEPTH = 2
# Subdomains of registered sites come from the hosts ranked this high (CrUX
# buckets: the 100k origins people open most, globally or in Russia). CrUX
# ranks origins down to 1M, and 67% of its subdomain hosts sit under names
# outside the ranked top 100k: drawn from all of them (2026-10-22) the model
# learned that a subdomain of an unknown name is as ordinary as the name
# (track.safeinflow.com 0.099 under its apex's 0.102, tests/test_ml_scorer.py;
# the served model adds +0.24 for a subdomain). Of the subdomain hosts in
# CrUX's top 100k, 76% have their parent in the ranked list's top 100k.
# Names under Russian zones and tenants keep every rank: they are their own
# names, not a site's subdomain.
SHAPE_MAX_RANK = 100_000

# ── The commercially clean corpus (2026-10-22) ──
#
# The four CC0 / unrestricted feeds (refresh_training_feeds.PHISHING_SOURCES)
# are all domain names, where URLhaus was 80% bare IPs. On 2026-10-21 a model
# trained on them with the benign class above (12,000 Tranco samples, 6%
# Russian, 12 IDN names, Balanced weights) scored 69 of the 539 held-out real
# Russian sites and 15% of random long-tail Tranco sites above 0.6; the
# served model (URLhaus + OpenPhish) 0 and 0.5%. What was wrong was the
# benign class, not the feeds:
#   * Russian sites were 6% of it and IDN (.рф) names 0.1%, so every
#     xn--…xn--p1ai host was out of distribution — and its 'xn--' counted as
#     hyphens, a phishing trait (8 of the top 10 flagged were .рф);
#   * 12,000 benign names against 10,500 phishing names, weighted 1:1, put the
#     0.6 bar inside the long tail: at 0.6 the model was a coin toss there;
#   * real tenants on most platforms are a handful in Tranco (7 myshopify.com
#     shops) against hundreds in the feeds, so "is a tenant" stayed phishing;
#   * no real site that carries a brand's name (gosuslugi29.ru, sberbank1.ru,
#     vkgosuslugi.ru) was ever a negative, so brand-plus-anything was phishing.
# Each stratum below answers one of these; the class weight moves the bar
# back to where the served model has it (docs/THIRD_PARTY_FEEDS.md §3 has the
# before/after numbers).
# scripts/refresh_training_feeds.py writes this many (DEFAULT_CAP per feed).
N_PHISHING = 20000
N_BENIGN = 48000
# Benign rows count this much in the loss (CatBoost class_weights [w, 1]):
# with ~18,000 phishing names against 48,000, phishing is ~1/9 of the
# weighted data. It sets where the scorer's fixed 0.6 / 0.85 bars fall:
# 1:1 put 15% of the long tail over 0.6, 2.0 put 1.3%, 3.0 puts 0.8% (the
# served URLhaus model 0.5%) while every gate keeps its margin.
BENIGN_CLASS_WEIGHT = 3.0
# Registrable domains under .ru / .su / .рф from the ranked list — on top of
# the Russian-zone host shapes (regional zones such as spb.ru) — and every
# IDN name in it (2026-10-22: 2,749, .рф 1,175 — Majestic 1,315 of them;
# Tranco had ~1,400 and ~500).
RU_TLDS = (".ru", ".su", ".xn--p1ai")
RU_PLD_SHARE = 0.10
# Synthetic tenants: real long-tail names (the label of a ranked registrable
# domain) under the curated platforms, in the mix of platforms the phishing
# class has tenants on. A real site's name on pages.dev is what a real
# tenant looks like; what the model must learn is the tenant's own label.
SYNTHETIC_TENANT_SHARE = 0.042
# Of those, this share spread evenly over the site platforms
# (_site_platform_suffixes), the rest in the phishing class's platform mix.
SYNTHETIC_UNIFORM_SHARE = 0.5
# Ranked registrable domains whose name contains a brand the brand features
# know (TYPOSQUAT_TARGETS, 4+ letters): vkgosuslugi.ru, sberbank-ast.ru,
# 9to5google.com — real sites that look like a brand to the model.
BRAND_NAME_SHARE = 0.031
BRAND_MIN_LEN = 4
# Ranked registrable domains whose name has a GENERIC lure word part and no
# classic one (_has_generic_lure_word: sncf-connect.com, home-connect.com,
# aami-rewards.com.au) — ~300 in Tranco's 1M list, all of them. The Majestic
# Million alone has 110 (51 with "connect"), and with them the model scored
# shopify-connect.com 0.87 (dangerous, tests/test_scoring.py); with the
# global CrUX domains the ranked list has 226, and lure_word_domains adds
# those of the Russian CrUX hosts: ~300 again (2026-10-22), 177 with
# "connect". A random 48,000
# of the list held ~15, while the phishing class has hundreds: "connect" or
# "rewards" in a name had become proof, and the model scored
# shopify-connect.com 0.97 (tests/test_scoring.py's brand partner names).
# Real names with classic words (login.gov, secure-booker.com) are left to
# the random strata: with them in, the obvious lures' median fell under 0.8
# (tests/test_ml_scorer.py) and secure-login.<platform> under 0.6. Names
# that carry a brand too are left out entirely (noise).
LURE_WORD_SHARE = 0.01
LURE_WORD_REPEAT = 2
# The hand-verified real sites in data/typosquat_targets_ru.json, each
# repeated this many times (they are ~380 rows in 48,000).
VERIFIED_REPEAT = 3
# The hosts the heredoc gates of .github/workflows/retrain-ml.yml judge,
# exact names: a gate must measure what the model learned, not recall a
# training row. (The 2026-10-04 note on facebook.github.io: whether that
# day's Tranco list carried the host decided the gate.)
GATE_HOSTS = frozenset({
    "klar.mx", "konfio.mx", "gob.mx", "mercadolibre.com.mx", "leadgid.com", "banorte.com", "google.com",
    "wikipedia.org", "www.example.com", "docs.google.com", "mail.yandex.ru", "online.sberbank.ru",
    "malsup.github.io", "blog.wordpress.com", "official-shop.myshopify.com", "myshop.tw1.ru",
    "facebook.github.io", "metamask.github.io", "paypal.account-verify.tk", "apple-id-locked-verify.xyz",
    "gosuslugi-vhod.netlify.app", "secure-login.wasmer.app", "sberbank-online.pages.dev",
})
# The served model is the mean of this many CatBoost models, each on its own
# draw of the benign strata (catboost.sum_models: one .cbm / .onnx). One
# model's score on a single gate host swung 0.32-0.93 with the seed; the
# mean of three is the model, not the draw.
ENSEMBLE_MEMBERS = 3
SEED = 42


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _hosts_in_file(lines: Iterable[str]) -> list[str]:
    """First part of a '<host> | …' line, '#' comments and blanks skipped."""
    out = []
    for raw in lines:
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.split(" | ")[0].strip().lower())
    return out


def load_held_out(paths: Iterable[str] = HELD_OUT_FILES) -> frozenset[str]:
    """Registrable domains of every evaluation host. A missing file is an
    error: training on a set it is later scored against would pass silently."""
    regs = set()
    for path in paths:
        with open(path, encoding="utf-8") as f:
            regs.update(legacy_registrable_domain(h) for h in _hosts_in_file(f))
    return frozenset(regs)


# ── Replacement guard ──
#
# The gates in retrain-ml.yml judge a few named hosts and the VERDICT on the
# held-out Russian sets, where the name rules mask most of what the model
# does. On 2026-10-21 a model trained on the commercially clean corpus
# (refresh_training_feeds.PHISHING_SOURCES) passed all of them and still
# scored 41 of the 270 real Russian sites in data/benchmark_legit_ru.txt
# and 23 of the 300 in ru_heuristics_legit.txt above 0.6; the served model
# scores none of them there. So train() compares the candidate's own
# probabilities on those held-out real sites with the committed model's and
# leaves the committed files alone when the candidate flags more than
# REPLACE_TOLERANCE extra — the gates then re-check the served model and the
# commit step finds nothing to commit. `--replace-anyway` overrides.
LEGIT_FLAG_THRESHOLD = 0.6  # scoring's ml_suspicious bar
REPLACE_TOLERANCE = 3


def load_held_out_legit() -> list[str]:
    """The real sites among the held-out sets (ru_heuristics_legit and the
    weekly benchmark's RU sample), deduplicated, in file order."""
    out: list[str] = []
    for path in (HELD_OUT_FILES[0], HELD_OUT_FILES[2]):
        with open(path, encoding="utf-8") as f:
            for host in _hosts_in_file(f):
                if host not in out:
                    out.append(host)
    return out


def replacement_decision(candidate_flagged: int, committed_flagged: Optional[int], n: int) -> tuple[bool, str]:
    """(replace the committed model?, why). None for the committed count
    means it could not be scored on today's features — nothing to compare."""
    if committed_flagged is None:
        return True, "no comparable committed model (feature schema changed) — the gates judge the candidate"
    if candidate_flagged > committed_flagged + REPLACE_TOLERANCE:
        return False, (f"candidate scores {candidate_flagged} of {n} held-out real sites above "
                       f"{LEGIT_FLAG_THRESHOLD}, the served model {committed_flagged} — keeping the served model")
    return True, (f"candidate {candidate_flagged} / served {committed_flagged} of {n} held-out real sites "
                  f"above {LEGIT_FLAG_THRESHOLD}")


def _committed_flagged(hosts: list[str]) -> Optional[int]:
    """How many of `hosts` (held-out real sites) the committed .cbm scores
    above the bar — on the feature data it was trained on, which after a
    popularity-list change is the archived copy, not today's files — or None
    when it was trained on another feature schema, its feature data is gone,
    or it is unreadable."""
    from catboost import CatBoostClassifier
    try:
        with open(os.path.join(MODEL_DIR, "model_meta.json")) as f:
            meta = json.load(f)
        if meta.get("features_version") != FEATURES_VERSION or meta.get("n_features") != len(FEATURE_NAMES):
            return None
        data, where = resolve_feature_data(meta, DATA_DIR)
        if data is None:
            print(f"  committed model not comparable: {where}")
            return None
        print(f"  committed model scored on its own feature data ({where})")
        _, rows = build_feature_matrix(hosts, data=data)
        committed = CatBoostClassifier()
        committed.load_model(os.path.join(MODEL_DIR, "phishing_model.cbm"))
        return int((committed.predict_proba(np.array(rows))[:, 1] > LEGIT_FLAG_THRESHOLD).sum())
    except Exception as e:  # noqa: BLE001 — no committed model to compare with is not a failure
        print(f"  committed model not comparable ({type(e).__name__}: {e})")
        return None


def top_domains_provenance() -> str:
    """One line on where data/top_100k.json came from
    (data/top_domains_sources.json, scripts/build_top_domains.py), or ''."""
    try:
        with open(os.path.join(DATA_DIR, "top_domains_sources.json"), encoding="utf-8") as f:
            record = json.load(f)
        months = record["sources"]["crux"]["months"]
        return (f"Majestic Million + Chrome UX Report {', '.join(f'{k} {v}' for k, v in sorted(months.items()))}, "
                f"built {record['built']} (data/top_domains_sources.json)")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return ""


def _read_ranked(path: str) -> list[tuple[int, str]]:
    ranked = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) != 2:
                continue
            try:
                ranked.append((int(parts[0]), parts[1].lower()))
            except ValueError:
                continue
    return ranked


def load_phishing_domains(max_n: int = 12000, held_out: frozenset[str] = frozenset()) -> list[str]:
    """Unique hosts of the phishing feed: every NAME first, IP literals after.

    URLhaus is mostly malware served from bare IPs. Taken in file order, the
    first 12,000 hosts of the 2026-09-29 feed were 10,961 IPs and 1,039
    names, while the feed held 3,753 names: the model that scores domain
    names saw 28% of the phishing names there were, and its held-out AUC was
    mostly an IP-versus-name score. IPs still fill the class, since they are
    what the analyzer passes for an IP-based URL.

    Hosting tenants beyond PHISH_TENANT_SHARE of the class, or beyond
    PHISH_TENANTS_PER_PLATFORM on one platform, are left out (in file order,
    which refresh_training_feeds interleaves by source).
    """
    csv_path = os.path.join(DATA_DIR, "phishtank.csv")
    seen: set[str] = set()
    names: list[str] = []
    ips: list[str] = []
    max_tenants = int(max_n * PHISH_TENANT_SHARE)
    tenants = 0
    per_platform: dict[str, int] = {}
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            try:
                host = urlparse(row.get("url", "")).hostname
            except ValueError:
                continue
            if not host:
                continue
            host = host.lower()
            if host in seen or host in GATE_HOSTS or legacy_registrable_domain(host) in held_out:
                continue
            seen.add(host)
            platform = shared_tenant(host)[0]
            if platform:
                if tenants >= max_tenants or per_platform.get(platform, 0) >= PHISH_TENANTS_PER_PLATFORM:
                    continue
                tenants += 1
                per_platform[platform] = per_platform.get(platform, 0) + 1
            (ips if _is_ip_literal(host) else names).append(host)
    return (names + ips)[:max_n]


def _tenant_depth(host: str, suffix: str) -> int:
    """Labels between the tenant's host and its shared suffix: foo.github.io
    is 1, www.foo.github.io 2."""
    return len(host[: -(len(suffix) + 1)].split("."))


def _shape_pool(ranked: list[tuple[int, str]], exclude: set[str],
                held_out: frozenset[str]) -> tuple[list[str], list[str], list[str]]:
    """(names under a Russian public suffix, subdomains of registered sites
    ranked SHAPE_MAX_RANK or better, tenants of the curated hosting platforms)."""
    ru_zone: list[str] = []
    subdomains: list[str] = []
    tenants: list[str] = []
    for rank, host in ranked:
        if host in exclude or host.endswith(".arpa") or legacy_registrable_domain(host) in held_out:
            continue
        # A hosting tenant (foo.github.io, bar.tw1.ru) is someone's own NAME
        # under a shared suffix, not a subdomain of a registered site: its
        # popularity says nothing about the next tenant's, so it is its own
        # stratum, from the curated platforms only (is_hosting_platform_site),
        # never a page on a user-content host (forms.yandex.ru).
        if is_hosting_platform_site(host):
            suffix, _ = shared_tenant(host)
            if suffix and not is_user_content_host(host) and _tenant_depth(host, suffix) <= MAX_SHAPE_DEPTH:
                tenants.append(host)
            continue
        depth = len(_subdomain_labels(host))
        if _ru_registrable_domain(host):
            if depth <= MAX_SHAPE_DEPTH:
                ru_zone.append(host)
        elif 1 <= depth <= MAX_SHAPE_DEPTH and not _is_under_shared_suffix(host) and rank <= SHAPE_MAX_RANK:
            subdomains.append(host)
    return ru_zone, subdomains, tenants


def _cap_per_platform(tenants: list[str], rng: random.Random) -> list[str]:
    """At most TENANTS_PER_PLATFORM tenants of each suffix, platforms in a
    fixed order so the pool is reproducible for a seed."""
    by_suffix: dict[str, list[str]] = {}
    for host in tenants:
        by_suffix.setdefault(shared_tenant(host)[0] or "", []).append(host)
    pool: list[str] = []
    for suffix in sorted(by_suffix):
        hosts = by_suffix[suffix]
        pool += rng.sample(hosts, min(len(hosts), TENANTS_PER_PLATFORM))
    return pool


def load_benign_domains(max_n: int = N_BENIGN, exclude: Iterable[str] = (),
                        held_out: frozenset[str] = frozenset(), seed: int = SEED) -> list[str]:
    """Benign negatives: famous, long tail (BENIGN_DOMAINS_CSV, the
    Majestic Million and the global CrUX list's registrable domains) and
    host shapes (BENIGN_HOSTS_CSV, CrUX top origins, global and Russia),
    plus the clean-corpus strata (2026-10-22, see N_BENIGN): every IDN
    name, RU_PLD_SHARE Russian registrable domains, synthetic tenants,
    brand-named and generic-lure-word real sites and the hand-verified
    brand file. `exclude` is
    the phishing class (its tenants set the synthetic tenants' platform
    mix); GATE_HOSTS are always left out.

    Until 2026-10-22 both lists were Tranco's (top-1M, and top-1M with
    subdomains); the history below names it where it happened. Its default
    list averages Cloudflare Radar, CC BY-NC 4.0, so a paid product could
    not train on it (docs/THIRD_PARTY_FEEDS.md §3).

    CRITICAL (2026-07-06 fix): the previous version sampled benign ONLY from
    top_10k.json. Training benign purely on famous domains taught the model
    "not-famous => phishing", which flagged ~58% of real legit long-tail domains
    (klar.mx, konfio.mx, gob.mx, ...) as phishing at serving time. AUC on the
    balanced test set looked great (0.9983) only because the test's legit half
    was ALSO top-10k — a distribution the model never has to face in production.

    Fix: stratified sample — a slice of top-10k (famous domains stay negatives so
    `in_top_domains` remains a valid signal) + a large uniform sample of rank
    10k-1M so the model learns legitimate domains exist across the whole
    popularity spectrum and must use real lexical/structural signals to separate
    them from phishing.

    Host shapes (2026-09-29): Tranco's default list holds registrable
    domains only, so no benign sample ever had a subdomain, while the
    phishing feed is full hostnames. The model learned "has a subdomain =>
    phishing": it scored 92% of the real hosts in Tranco's subdomain list
    above 0.6 (www.example.com 0.98, docs.google.com 0.91) and every
    kvs.gov.spb.ru-shaped government host 0.92-0.99. And Tranco folds every
    name under a Russian regional zone into the zone (spb.ru ranks, not
    herzen.spb.ru). So SHAPE_SHARE of the class comes from a list WITH
    subdomains (CrUX names origins; its Russian list is where the regional
    zones are — the global one had 139 such names on 2026-10-22, Russia's
    3,584): names under Russian public suffixes
    (up to RU_ZONE_SHARE_OF_SHAPES of the stratum) and hosts one or two
    levels under a registered site; and, on top of it, TENANT_SHARE of the
    class from tenants of the curated hosting platforms (at most
    TENANTS_PER_PLATFORM of each). Reverse-DNS names and tenants of suffixes
    outside the curated lists are left out, and so is every host whose
    registrable domain is held out (HELD_OUT_FILES) — the shapes, never the
    evaluation hosts themselves.

    Tenants (2026-10-04): the 2026-09-29 model had no benign tenant at all
    (the stratum excluded them), so is_hosting_subdomain was a phishing-only
    feature and it scored facebook.github.io 0.98, blog.wordpress.com 0.98
    and tailwindcss.netlify.app 1.00. Popular tenants are real sites with
    the names real people give them (malsup.github.io, canoninc-my.sharepoint.com).
    """
    rng = random.Random(seed)
    exclude = set(exclude)
    phishing_tenants = sorted(h for h in exclude if shared_tenant(h)[0])
    exclude |= GATE_HOSTS

    head: list[str] = []  # rank <= 10k (famous)
    tail: list[str] = []  # rank 10k-1M (long tail)
    ru_pld: list[str] = []  # under .ru / .su / .рф (any rank)
    idn: list[str] = []  # any IDN name
    for rank, domain in _read_ranked(os.path.join(DATA_DIR, BENIGN_DOMAINS_CSV)):
        if domain in exclude or legacy_registrable_domain(domain) in held_out:
            continue
        if "xn--" in domain:
            idn.append(domain)
        elif domain.endswith(RU_TLDS):
            ru_pld.append(domain)
        (head if rank <= 10000 else tail).append(domain)

    hosts_path = os.path.join(DATA_DIR, BENIGN_HOSTS_CSV)
    if not os.path.exists(hosts_path):
        raise FileNotFoundError(
            f"{hosts_path} is missing — run scripts/refresh_training_feeds.py. "
            "Without it the benign class has no subdomain shapes and the model "
            "flags almost every host with a subdomain."
        )
    ranked_hosts = _read_ranked(hosts_path)
    ru_zone, subdomains, tenants = _shape_pool(ranked_hosts, exclude, held_out)
    n_shape = int(max_n * SHAPE_SHARE)
    n_ru = min(len(ru_zone), int(n_shape * RU_ZONE_SHARE_OF_SHAPES))
    shapes = rng.sample(ru_zone, n_ru)
    shapes += rng.sample(subdomains, min(len(subdomains), n_shape - n_ru))
    tenant_pool = _cap_per_platform(tenants, rng)
    shapes += rng.sample(tenant_pool, min(len(tenant_pool), int(max_n * TENANT_SHARE)))
    taken = set(shapes)

    # The clean-corpus strata (see N_BENIGN): Russian and IDN names, real
    # names as tenants, brand-named real sites, the hand-verified ones.
    extra = [d for d in idn if d not in taken]
    pool = [d for d in ru_pld if d not in taken]
    extra += rng.sample(pool, min(len(pool), int(max_n * RU_PLD_SHARE)))
    extra += synthetic_tenants(tail, phishing_tenants, int(max_n * SYNTHETIC_TENANT_SHARE), rng,
                               exclude, held_out)
    taken |= set(extra)
    pool = brand_named_sites(d for d in tail + head if d not in taken)
    # A brand AND a lure word in a ranked list is paypal-login.us or
    # account-paypal.info: label noise, never a negative.
    noise = {d for d in pool if _has_lure_word(d)}
    pool = [d for d in pool if d not in noise]
    head = [d for d in head if d not in noise]
    tail = [d for d in tail if d not in noise]
    extra += rng.sample(pool, min(len(pool), int(max_n * BRAND_NAME_SHARE)))
    taken |= set(extra)
    # The lure-word names of both lists: the ranked domains and the
    # registrable domains of the host list (see LURE_WORD_SHARE).
    lure = {d for d in tail + head if _has_generic_lure_word(d)}
    lure |= {d for d in lure_word_domains(h for _, h in ranked_hosts)
             if d not in exclude and legacy_registrable_domain(d) not in held_out}
    lure = sorted(lure - set(brand_named_sites(lure)) - taken)
    extra += rng.sample(lure, min(len(lure), int(max_n * LURE_WORD_SHARE))) * LURE_WORD_REPEAT
    taken |= set(extra)
    verified = [h for h in load_verified_brand_sites()
                if h not in exclude and h not in taken and legacy_registrable_domain(h) not in held_out]
    # At most 5% of the class, so a small run (the tests' 40) stays mostly ranked-list names.
    verified = rng.sample(verified, min(len(verified), int(max_n * 0.05) // VERIFIED_REPEAT))
    extra += verified * VERIFIED_REPEAT
    taken |= set(extra)
    head = [d for d in head if d not in taken]
    tail = [d for d in tail if d not in taken]

    n_pld = max_n - len(shapes) - len(extra)
    n_head = min(len(head), n_pld // 4)  # ~25% famous
    n_tail = min(len(tail), n_pld - n_head)  # ~75% long tail
    benign = rng.sample(head, n_head) + rng.sample(tail, n_tail) + shapes + extra
    rng.shuffle(benign)
    return benign


def synthetic_tenants(tail: list[str], phishing_tenants: Iterable[str], n: int, rng: random.Random,
                      exclude: Iterable[str] = (), held_out: frozenset[str] = frozenset()) -> list[str]:
    """`n` real long-tail names grafted onto hosting platforms:
    <label of a ranked .com/.net/... site>.<platform>. Half in the mix of
    platforms the phishing class has tenants on (domain_length counts the
    suffix), half spread evenly over the site platforms
    (SYNTHETIC_UNIFORM_SHARE, _site_platform_suffixes).

    Tranco carried a handful of real tenants per platform (7 myshopify.com
    shops in the 2026-10-21 list; CrUX 120, of which TENANTS_PER_PLATFORM
    reach the pool) where the feeds carry hundreds, so with
    real tenants alone "is a tenant on pages.dev" stayed a phishing trait
    and official-shop.myshopify.com scored 0.51-0.59. No phishing tenants
    (a test, an empty feed) means no synthetic ones."""
    plat = collections.Counter(shared_tenant(h)[0] for h in phishing_tenants)
    plat.pop(None, None)
    if not plat or n <= 0:
        return []
    # SYNTHETIC_UNIFORM_SHARE of them spread evenly over the site platforms:
    # the feeds report no myshopify.com tenant at all, so by their mix alone
    # a shop there was a platform the benign class had never seen.
    total = sum(plat.values())
    sites = _site_platform_suffixes()
    share = SYNTHETIC_UNIFORM_SHARE if sites else 0.0
    prob = {s: (1 - share) * c / total for s, c in plat.items()}
    for s in sites:
        prob[s] = prob.get(s, 0.0) + share / len(sites)
    suffixes = sorted(prob)
    weights = [prob[s] for s in suffixes]
    labels = sorted({d.split(".")[0] for d in tail if d.count(".") == 1 and 3 <= len(d.split(".")[0]) <= 30})
    if not labels:
        return []
    exclude = set(exclude)
    out: set[str] = set()
    for _ in range(n * 20):  # bounded: a tiny label pool cannot loop forever
        if len(out) >= n:
            break
        host = f"{rng.choice(labels)}.{rng.choices(suffixes, weights)[0]}"
        if host not in exclude and not is_user_content_host(host) and legacy_registrable_domain(host) not in held_out:
            out.add(host)
    return sorted(out)


def _site_platform_suffixes() -> list[str]:
    """Platforms people build sites and shops on: the scorer's hand list
    (scoring.HOSTING_PLATFORMS, without the Google user-content hosts) and
    the curated hosting / site-builder groups of data/hosting_platforms.json
    (not dynamic DNS, not the blogspot ccTLD mirrors). Sorted."""
    from api.services.scoring import GOOGLE_ABUSED_SUBDOMAINS, HOSTING_PLATFORMS

    try:
        with open(os.path.join(ROOT, "data", "hosting_platforms.json"), encoding="utf-8") as f:
            groups = json.load(f).get("tenant_suffixes", {})
    except (OSError, ValueError):
        groups = {}
    curated = {s for g in ("ru_hosting", "ru_site_builders", "site_builders") for s in groups.get(g, [])}
    return sorted(s for s in (set(HOSTING_PLATFORMS) | curated) - GOOGLE_ABUSED_SUBDOMAINS
                  if not is_user_content_host("x." + s))


def _has_lure_word(domain: str) -> bool:
    """The model's has_suspicious_keyword, on the registered name."""
    return has_suspicious_keyword(host_shape(domain)[1])


def _has_generic_lure_word(domain: str) -> bool:
    """A lure word that is one of the generic / crypto ones (connect, sync,
    rewards, mint, claim …) and no classic phishing action word
    (scoring._COMBOSQUAT_KEYWORDS: login, verify, account, secure …) — the
    split the scorer itself makes for combosquats."""
    from api.services.scoring import _COMBOSQUAT_KEYWORDS

    name = host_shape(domain)[1]
    return has_suspicious_keyword(name) and not (
        set(name.lower().replace("_", "-").split("-")) & _COMBOSQUAT_KEYWORDS)


def lure_word_domains(hosts: Iterable[str]) -> set[str]:
    """Registrable domains of `hosts` (not hosting tenants) whose name has a
    generic lure word only (_has_generic_lure_word): www.sncf-connect.com
    gives sncf-connect.com. A substring pass first, so 1.5M hosts cost
    seconds, not a legacy_registrable_domain() each."""
    from api.services.scoring import _SUSPICIOUS_KEYWORDS

    words = re.compile("|".join(sorted(map(re.escape, _SUSPICIOUS_KEYWORDS), key=len, reverse=True)))
    out = set()
    for host in hosts:
        if words.search(host) and not shared_tenant(host)[0]:
            domain = legacy_registrable_domain(host)
            if _has_generic_lure_word(domain):
                out.add(domain)
    return out


def brand_named_sites(domains: Iterable[str]) -> list[str]:
    """Ranked registrable domains whose name contains a brand the brand
    features compare against (TYPOSQUAT_TARGETS minus the not-yet-trained
    names, BRAND_MIN_LEN letters or more) without being the brand itself:
    vkgosuslugi.ru, sberbank-ast.ru, 9to5google.com. Sorted, unique."""
    from api.services.scoring import _NOT_IN_MODEL, TYPOSQUAT_TARGETS, _decode_idn

    brands = [b for b in TYPOSQUAT_TARGETS if b not in _NOT_IN_MODEL and len(b) >= BRAND_MIN_LEN]
    pattern = re.compile("|".join(sorted(map(re.escape, brands), key=len, reverse=True)))
    out = set()
    for d in domains:
        name = d.split(".")[0]
        if name.startswith("xn--"):
            name = _decode_idn(name).lower()
        if name not in TYPOSQUAT_TARGETS and pattern.search(name):
            out.add(d)
    return sorted(out)


def load_verified_brand_sites(path: str = os.path.join(DATA_DIR, "typosquat_targets_ru.json")) -> list[str]:
    """Every 'official' (the brand's own: sberbank1.ru, gosuslugi29.ru) and
    'unrelated' (a look-alike name that is someone else's real site:
    sberbank.cz) domain in the hand-verified Russian brand file — the
    hardest true negatives there are. Sorted, unique, lowercase."""
    with open(path, encoding="utf-8") as f:
        brands = json.load(f)["brands"]
    return sorted({h.lower() for b in brands.values() for k in ("official", "unrelated") for h in b.get(k, {})})


def build_feature_matrix(domains: Iterable[str],
                         cache: Optional[dict[str, list[float]]] = None,
                         data: Optional[FeatureData] = None) -> tuple[list[str], list[list[float]]]:
    """Rows in FEATURE_NAMES order — the vector ml_scorer.ml_predict() feeds
    the served model for the same domain (tests/test_ml_feature_parity.py).
    `cache` (host → row) spares the ensemble members re-extracting the hosts
    their benign samples share. `data`: the feature data files to read
    (default today's, which is what a model is trained on)."""
    kept, rows = [], []
    for domain in domains:
        row = cache.get(domain) if cache is not None else None
        if row is None:
            try:
                features = extract_ml_features(domain, data)
            except Exception:
                continue
            row = [features[k] for k in FEATURE_NAMES]
            if cache is not None:
                cache[domain] = row
        kept.append(domain)
        rows.append(row)
    return kept, rows


def _names_only_metrics(hosts: list[str], y_true: np.ndarray, y_proba: np.ndarray) -> Optional[dict]:
    """The same held-out split without IP literals: how the model does on
    the domain names it is there to judge (IPs separate trivially)."""
    mask = np.array([not _is_ip_literal(h) for h in hosts])
    yt, yp = y_true[mask], y_proba[mask]
    if len(set(yt.tolist())) < 2:
        return None
    from sklearn.metrics import roc_auc_score

    phish, benign = yp[yt == 1], yp[yt == 0]
    return {
        "n_phishing": int(len(phish)),
        "n_benign": int(len(benign)),
        "auc": round(float(roc_auc_score(yt, yp)), 4),
        "recall_at_0.6": round(float((phish > 0.6).mean()), 4),
        "recall_at_0.85": round(float((phish > 0.85).mean()), 4),
        "benign_flagged_at_0.6": round(float((benign > 0.6).mean()), 4),
    }


def phishing_source_mix(hosts: Iterable[str]) -> dict[str, int]:
    """Hosts per feed ('source' column of data/phishtank.csv)."""
    wanted = set(hosts)
    mix: dict[str, int] = {}
    with open(os.path.join(DATA_DIR, "phishtank.csv"), encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            try:
                host = (urlparse(row.get("url", "")).hostname or "").lower()
            except ValueError:
                continue
            if host in wanted:
                wanted.discard(host)
                source = row.get("source") or "?"
                mix[source] = mix.get(source, 0) + 1
    return dict(sorted(mix.items()))


def benign_provenance() -> Optional[dict]:
    """The record refresh_training_feeds wrote beside the benign lists, or
    None when there is none to read (lists placed by hand, an unreadable
    file) — model_meta.json then says null rather than guess a month."""
    try:
        with open(os.path.join(DATA_DIR, BENIGN_SOURCES_JSON), encoding="utf-8") as f:
            record = json.load(f)
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def average_members(members: list) -> "CatBoostClassifier":
    """One CatBoostClassifier whose raw score is the mean of the members'
    (catboost.sum_models with equal weights) — a single .cbm / .onnx, the
    same 27-feature contract, so serving does not change."""
    import tempfile

    from catboost import CatBoostClassifier, sum_models

    if len(members) == 1:
        return members[0]
    summed = sum_models(members, weights=[1.0 / len(members)] * len(members))
    # sum_models keeps each member's metadata only under "model<i>:"; without
    # a top-level loss the ONNX export is a regressor (one raw 'predictions'
    # output) and ml_scorer cannot read it. The members share these.
    meta = summed.get_metadata()
    first = members[0].get_metadata()
    for key in ("params", "class_params", "output_options"):
        if key in first and key not in meta:
            meta[key] = first[key]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ensemble.cbm")
        summed.save_model(path)
        model = CatBoostClassifier()
        model.load_model(path)
    return model


def split_group(host: str) -> str:
    """The train/test split's group: a tenant's own host, else its
    registrable domain."""
    return host if shared_tenant(host)[0] else legacy_registrable_domain(host)


def train(replace_anyway: bool = False, seed: int = SEED):
    from catboost import CatBoostClassifier
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    from sklearn.model_selection import GroupShuffleSplit

    print("=" * 60)
    print("Cleanway ML Model Training — CatBoost")
    print("=" * 60)

    # ── Load data ──
    print("\nLoading data...")
    held_out = load_held_out()
    phishing = load_phishing_domains(N_PHISHING, held_out)
    # Exclude any benign that also appears in the phishing feed (compromised-legit
    # domains show up in both) so labels stay clean.
    benign = load_benign_domains(N_BENIGN, exclude=phishing, held_out=held_out, seed=seed)
    n_ips = sum(_is_ip_literal(d) for d in phishing)
    n_shapes = sum(bool(_subdomain_labels(d)) or bool(_ru_registrable_domain(d)) for d in benign)
    n_tenants = sum(shared_tenant(d)[0] is not None for d in benign)
    print(f"  Held out:         {len(held_out)} registrable domains (evaluation sets)")
    print(f"  Phishing domains: {len(phishing)} ({len(phishing) - n_ips} names, {n_ips} IPs)")
    print(f"  Benign domains:   {len(benign)} ({n_shapes} host shapes, {n_tenants} of them hosting tenants)")

    # ── Extract features ──
    print("\nExtracting features...")
    start = time.time()
    feature_cache: dict[str, list[float]] = {}
    phishing, X_phish = build_feature_matrix(phishing, feature_cache)
    benign, X_benign = build_feature_matrix(benign, feature_cache)
    hosts = phishing + benign
    X = np.array(X_phish + X_benign)
    y = np.array([1] * len(phishing) + [0] * len(benign))
    print(f"  Features extracted: {X.shape[0]} samples × {X.shape[1]} features")
    print(f"  Time: {time.time() - start:.1f}s")
    print(f"  Class balance: {sum(y)} phishing / {len(y) - sum(y)} benign")

    # ── Split ──
    # By registrable domain (a tenant by its own host): the subdomains of one
    # phishing domain, and the repeated verified rows, land on one side, so
    # the test AUC is not a lookup of a sibling seen in training.
    groups = [split_group(h) for h in hosts]
    idx_train, idx_test = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
                               .split(X, y, groups))
    X_train, X_test, y_train, y_test = X[idx_train], X[idx_test], y[idx_train], y[idx_test]
    print(f"\n  Train: {len(X_train)}, Test: {len(X_test)}")

    # ── Train CatBoost ──
    print(f"\nTraining CatBoost model ({ENSEMBLE_MEMBERS} members)...")
    start = time.time()

    def fit(X_fit: np.ndarray, y_fit: np.ndarray, member_seed: int) -> "CatBoostClassifier":
        member = CatBoostClassifier(
            iterations=500,
            depth=6,
            learning_rate=0.1,
            l2_leaf_reg=3,
            class_weights=[BENIGN_CLASS_WEIGHT, 1.0],
            random_seed=member_seed,
            verbose=100,
        )
        member.fit(X_fit, y_fit, eval_set=(X_test, y_test), early_stopping_rounds=50)
        return member

    members = [fit(X_train, y_train, seed)]
    # Every further member: the same phishing training rows, its own benign
    # sample (another draw of every stratum), never a host of the test split.
    test_groups = {groups[i] for i in idx_test}
    phish_train = [i for i in idx_train if y[i] == 1]
    for k in range(1, ENSEMBLE_MEMBERS):
        more = [h for h in load_benign_domains(N_BENIGN, exclude=phishing, held_out=held_out, seed=seed + k)
                if split_group(h) not in test_groups]
        _, X_more = build_feature_matrix(more, feature_cache)
        X_k = np.vstack([X[phish_train], np.array(X_more)])
        y_k = np.array([1] * len(phish_train) + [0] * len(X_more))
        members.append(fit(X_k, y_k, seed + k))
    model = average_members(members)

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
    names_only = _names_only_metrics([hosts[i] for i in idx_test], y_test, y_proba)
    print(f"Names only (no IP literals): {names_only}")

    # ── Feature importance ──
    print("\nTop 15 Feature Importances:")
    importances = np.mean([m.feature_importances_ for m in members], axis=0)  # the sum has none
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

    # ── Replacement guard (see REPLACE_TOLERANCE) ──
    legit_hosts, X_legit = build_feature_matrix(load_held_out_legit())
    X_legit = np.array(X_legit)
    candidate_flagged = int((model.predict_proba(X_legit)[:, 1] > LEGIT_FLAG_THRESHOLD).sum())
    replace, why = replacement_decision(candidate_flagged, _committed_flagged(legit_hosts), len(legit_hosts))
    print(f"\nReplacement guard: {why}")
    if not replace:
        if replace_anyway:
            print("  --replace-anyway: replacing it regardless")
        else:
            print(f"::warning::retrain held back — {why}. The served model stays; nothing will be committed.")
            return

    # ── Save model ──
    model_path = os.path.join(MODEL_DIR, "phishing_model.cbm")
    model.save_model(model_path)
    print(f"\nModel saved to: {model_path}")

    # ── Export ONNX for lean production inference ──
    # Prod runs onnxruntime (~40 MB RSS) instead of catboost (~400 MB deps) so
    # the model fits Railway's 512 MB plan. Keep BOTH artifacts in sync: the
    # .cbm is authoritative for retraining, the .onnx is what ships. See
    # api/services/ml_scorer.py (onnxruntime-first, catboost fallback).
    onnx_path = os.path.join(MODEL_DIR, "phishing_model.onnx")
    model.save_model(onnx_path, format="onnx")
    print(f"ONNX model saved to: {onnx_path}")

    # Save feature names
    meta_path = os.path.join(MODEL_DIR, "model_meta.json")
    with open(meta_path, "w") as f:
        json.dump({
            "feature_names": FEATURE_NAMES,
            "n_features": len(FEATURE_NAMES),
            "features_version": FEATURES_VERSION,
            "train_samples": len(X_train),   # 80% split actually fit
            "total_samples": len(X),         # full labeled corpus (what copy cites)
            "test_auc": round(auc, 4),
            "test_names_only": names_only,
            "phishing_names": len(phishing) - n_ips,
            "phishing_ips": n_ips,
            "benign_host_shapes": n_shapes,
            "benign_tenants": n_tenants,
            "held_out_registrable_domains": len(held_out),
            # Provenance: which feeds the phishing class came from (the CC0 /
            # unrestricted ones only since 2026-10-21) and how it was drawn.
            "phishing_sources": phishing_source_mix(phishing),
            # …and which benign lists (Majestic Million, CrUX month, licences)
            # since 2026-10-22; plus data/typosquat_targets_ru.json, first-party.
            "benign_sources": benign_provenance(),
            "benign_class_weight": BENIGN_CLASS_WEIGHT,
            "ensemble_members": ENSEMBLE_MEMBERS,
            "seed": seed,
            # The suffixes the tenant feature knows (ml_features.shared_tenant).
            "shared_suffixes": len(_SCORER_SHARED_SUFFIXES | TENANT_SUFFIXES),
            # The data files read as features, by sha256: ml_scorer serves the
            # model these exact copies (live, or archived in data/feature_data/);
            # and the typosquat rule its is_typosquat learned (typosquat_rule).
            "feature_data": feature_data_record(DATA_DIR, top_domains_provenance()),
        }, f, indent=2)
    print(f"Metadata saved to: {meta_path}")

    print("\n" + "=" * 60)
    print("DONE. Model ready for integration.")


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--replace-anyway", action="store_true")
    p.add_argument("--seed", type=int, default=SEED,
                   help="benign sampling, split and CatBoost seed (offline seed sweeps)")
    args = p.parse_args()
    train(replace_anyway=args.replace_anyway, seed=args.seed)
