"""
Benchmark: Scoring Engine Detection Rate

Tests the rule-based scoring engine against:
  - PhishTank verified phishing URLs (positive samples)
  - Tranco Top 10K domains (negative samples / benign)

Reports:
  - True Positive Rate (TPR / Recall): % of phishing caught
  - False Positive Rate (FPR): % of legit flagged as dangerous
  - Precision, F1 score
  - Score distribution
"""

import csv
import json
import os
import sys
import time
from collections import Counter
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.services.scoring import calculate_score, _extract_base_domain


def load_phishing_domains(max_samples: int = 5000) -> list[str]:
    """Load PhishTank domains (extract domain from URL)."""
    csv_path = os.path.join(os.path.dirname(__file__), "..", "data", "phishtank.csv")
    domains = set()
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url", "")
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname
                    if host:
                        domains.add(host.lower())
                except Exception:
                    continue
                if len(domains) >= max_samples:
                    break
    except FileNotFoundError:
        print("ERROR: PhishTank CSV not found. Run download first.")
        sys.exit(1)

    return list(domains)


def load_benign_domains(max_samples: int = 5000) -> list[str]:
    """Load Tranco top domains as benign samples."""
    json_path = os.path.join(os.path.dirname(__file__), "..", "data", "top_10k.json")
    try:
        with open(json_path, "r") as f:
            data = json.load(f)
            domains = list(data.keys())[:max_samples]
            return domains
    except FileNotFoundError:
        print("ERROR: top_10k.json not found.")
        sys.exit(1)


def benchmark_domain(domain: str) -> tuple[int, str]:
    """Score a domain using only rule-based signals (no API calls)."""
    # Build minimal signals dict (no external API calls in benchmark)
    signals = {
        "domain": domain,
        "raw_url": domain,
        # No blocklist hits (we're testing rule-based features only)
        "safe_browsing_hit": False,
        "phishtank_hit": False,
        "urlhaus_hit": False,
    }
    score, level, reasons = calculate_score(signals)
    return score, level.value


def run_benchmark():
    print("=" * 60)
    print("LinkShield Scoring Engine — Detection Rate Benchmark")
    print("=" * 60)

    # Load datasets
    print("\nLoading datasets...")
    phishing = load_phishing_domains(5000)
    benign = load_benign_domains(5000)
    print(f"  Phishing domains: {len(phishing)}")
    print(f"  Benign domains:   {len(benign)}")

    # ── Benchmark phishing domains ──
    print("\nScoring phishing domains...")
    start = time.time()
    phish_results = []
    phish_scores = []
    for domain in phishing:
        score, level = benchmark_domain(domain)
        phish_results.append(level)
        phish_scores.append(score)

    phish_time = time.time() - start
    phish_dangerous = phish_results.count("dangerous")
    phish_caution = phish_results.count("caution")
    phish_safe = phish_results.count("safe")

    # ── Benchmark benign domains ──
    print("Scoring benign domains...")
    start = time.time()
    benign_results = []
    benign_scores = []
    for domain in benign:
        score, level = benchmark_domain(domain)
        benign_results.append(level)
        benign_scores.append(score)

    benign_time = time.time() - start
    benign_dangerous = benign_results.count("dangerous")
    benign_caution = benign_results.count("caution")
    benign_safe = benign_results.count("safe")

    # ── Calculate metrics ──
    # For "dangerous" threshold (score > 50)
    tp = phish_dangerous  # True positives: phishing caught as dangerous
    fn = len(phishing) - phish_dangerous  # False negatives: phishing missed
    fp = benign_dangerous  # False positives: benign marked dangerous
    tn = len(benign) - benign_dangerous  # True negatives: benign marked safe/caution

    tpr = tp / max(tp + fn, 1)  # Recall / sensitivity
    fpr = fp / max(fp + tn, 1)  # False positive rate
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * tpr / max(precision + tpr, 0.001)

    # For "caution OR dangerous" threshold (score > 20)
    tp_broad = phish_dangerous + phish_caution
    fn_broad = phish_safe
    fp_broad = benign_dangerous + benign_caution
    tn_broad = benign_safe

    tpr_broad = tp_broad / max(tp_broad + fn_broad, 1)
    fpr_broad = fp_broad / max(fp_broad + tn_broad, 1)

    # ── Print results ──
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    print(f"\n[Phishing domains] ({len(phishing)} samples)")
    print(f"  Dangerous (caught):  {phish_dangerous:>5} ({phish_dangerous/len(phishing)*100:.1f}%)")
    print(f"  Caution (warned):    {phish_caution:>5} ({phish_caution/len(phishing)*100:.1f}%)")
    print(f"  Safe (MISSED):       {phish_safe:>5} ({phish_safe/len(phishing)*100:.1f}%)")
    print(f"  Avg score:           {sum(phish_scores)/len(phish_scores):.1f}")
    print(f"  Time:                {phish_time:.2f}s ({phish_time/len(phishing)*1000:.1f}ms/domain)")

    print(f"\n[Benign domains] ({len(benign)} samples)")
    print(f"  Safe (correct):      {benign_safe:>5} ({benign_safe/len(benign)*100:.1f}%)")
    print(f"  Caution (false warn):{benign_caution:>5} ({benign_caution/len(benign)*100:.1f}%)")
    print(f"  Dangerous (FALSE+):  {benign_dangerous:>5} ({benign_dangerous/len(benign)*100:.1f}%)")
    print(f"  Avg score:           {sum(benign_scores)/len(benign_scores):.1f}")
    print(f"  Time:                {benign_time:.2f}s ({benign_time/len(benign)*1000:.1f}ms/domain)")

    print(f"\n[Strict threshold: 'dangerous' only (score > 50)]")
    print(f"  True Positive Rate (Recall): {tpr*100:.1f}%")
    print(f"  False Positive Rate:         {fpr*100:.2f}%")
    print(f"  Precision:                   {precision*100:.1f}%")
    print(f"  F1 Score:                    {f1*100:.1f}%")

    print(f"\n[Broad threshold: 'caution + dangerous' (score > 20)]")
    print(f"  True Positive Rate (Recall): {tpr_broad*100:.1f}%")
    print(f"  False Positive Rate:         {fpr_broad*100:.2f}%")

    # Score distribution
    print("\n[Score Distribution — Phishing]")
    buckets = Counter()
    for s in phish_scores:
        bucket = (s // 10) * 10
        buckets[bucket] += 1
    for bucket in sorted(buckets.keys()):
        bar = "█" * (buckets[bucket] * 40 // max(buckets.values()))
        print(f"  {bucket:>3}-{bucket+9:<3}: {bar} {buckets[bucket]}")

    print("\n[Score Distribution — Benign]")
    buckets = Counter()
    for s in benign_scores:
        bucket = (s // 10) * 10
        buckets[bucket] += 1
    for bucket in sorted(buckets.keys()):
        bar = "█" * (buckets[bucket] * 40 // max(buckets.values()))
        print(f"  {bucket:>3}-{bucket+9:<3}: {bar} {buckets[bucket]}")

    # What signals are most triggered on phishing?
    print("\n[Most triggered signals on phishing domains]")
    signal_counts = Counter()
    for domain in phishing[:1000]:
        signals = {"domain": domain, "raw_url": domain, "safe_browsing_hit": False, "phishtank_hit": False, "urlhaus_hit": False}
        _, _, reasons = calculate_score(signals)
        for r in reasons:
            signal_counts[r.signal] += 1
    for signal, count in signal_counts.most_common(15):
        print(f"  {signal:<30} {count:>5} ({count/min(len(phishing),1000)*100:.1f}%)")

    print("\n" + "=" * 60)

    # Verdict
    if tpr >= 0.7:
        print(f"VERDICT: GOOD — {tpr*100:.0f}% detection rate (rules-only, no API calls)")
    elif tpr >= 0.4:
        print(f"VERDICT: MODERATE — {tpr*100:.0f}% detection rate. ML model will help significantly.")
    else:
        print(f"VERDICT: NEEDS IMPROVEMENT — {tpr*100:.0f}% detection rate. ML model is critical.")

    print("Note: This benchmark uses ONLY rule-based features.")
    print("In production, 9 blocklist APIs will catch the majority of known phishing.")


if __name__ == "__main__":
    run_benchmark()
