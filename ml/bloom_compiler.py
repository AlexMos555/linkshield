"""
Bloom Filter Compiler — Server-side.

Generates a bloom filter from Tranco Top 100K domains
and outputs it as JSON for CDN distribution to extension clients.

Run: python -m ml.bloom_compiler
Output: data/bloom_top100k.json (~175KB)

The extension downloads this file and uses it for instant
local checks (<1ms) without API calls.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

# Parameters matching extension/src/utils/bloom.js
BLOOM_SIZE = 1_437_759  # bits
BLOOM_HASH_COUNT = 10


def murmurhash3(key: str, seed: int) -> int:
    """MurmurHash3 — must match JS implementation exactly."""
    h = seed & 0xFFFFFFFF
    for ch in key:
        k = ord(ch) & 0xFFFFFFFF
        k = (k * 0xCC9E2D51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1B873593) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    h ^= len(key)
    h ^= (h >> 16)
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h & 0xFFFFFFFF


def get_hash_positions(key: str) -> list[int]:
    positions = []
    for i in range(BLOOM_HASH_COUNT):
        h = murmurhash3(key, (i * 0x9E3779B9) & 0xFFFFFFFF)
        positions.append(h % BLOOM_SIZE)
    return positions


def compile_bloom():
    print("=" * 50)
    print("Bloom Filter Compiler")
    print("=" * 50)

    # Load domains
    top100k_path = os.path.join(DATA_DIR, "top_100k.json")
    print(f"\nLoading {top100k_path}...")

    with open(top100k_path, "r") as f:
        domains = json.load(f)

    if isinstance(domains, dict):
        domains = list(domains.keys())

    print(f"  Domains loaded: {len(domains):,}")

    # Build bloom filter
    print("\nBuilding bloom filter...")
    start = time.time()

    bits = bytearray((BLOOM_SIZE + 7) // 8)
    for domain in domains:
        positions = get_hash_positions(domain.lower())
        for pos in positions:
            byte_idx = pos >> 3
            bit_idx = pos & 7
            bits[byte_idx] |= (1 << bit_idx)

    elapsed = time.time() - start
    print(f"  Build time: {elapsed:.2f}s")
    print(f"  Filter size: {len(bits):,} bytes ({len(bits)/1024:.0f} KB)")

    # Calculate fill ratio
    set_bits = sum(bin(b).count("1") for b in bits)
    fill_ratio = set_bits / BLOOM_SIZE
    print(f"  Fill ratio: {fill_ratio:.3f} ({set_bits:,}/{BLOOM_SIZE:,} bits set)")

    # Estimate false positive rate
    # FP ≈ (1 - e^(-kn/m))^k
    import math
    k, n, m = BLOOM_HASH_COUNT, len(domains), BLOOM_SIZE
    fp_rate = (1 - math.exp(-k * n / m)) ** k
    print(f"  Estimated FP rate: {fp_rate:.4%}")

    # Verify a sample
    print("\nVerification:")
    test_domains = ["google.com", "facebook.com", "paypal.com", "github.com"]
    for d in test_domains:
        positions = get_hash_positions(d.lower())
        found = all((bits[p >> 3] & (1 << (p & 7))) != 0 for p in positions)
        print(f"  {d}: {'FOUND' if found else 'MISS'}")

    # Test false positive with random domains
    import random
    import string
    fp_count = 0
    fp_tests = 10000
    for _ in range(fp_tests):
        random_domain = "".join(random.choices(string.ascii_lowercase, k=12)) + ".com"
        positions = get_hash_positions(random_domain)
        found = all((bits[p >> 3] & (1 << (p & 7))) != 0 for p in positions)
        if found:
            fp_count += 1
    actual_fp = fp_count / fp_tests
    print(f"\n  Actual FP rate (10K random tests): {actual_fp:.4%}")

    # Save as JSON (array of uint8 values)
    output = {
        "bits": list(bits),
        "size": BLOOM_SIZE,
        "hash_count": BLOOM_HASH_COUNT,
        "domain_count": len(domains),
        "version": time.strftime("%Y%m%d"),
        "fp_rate": round(fp_rate, 6),
    }

    output_path = os.path.join(DATA_DIR, "bloom_top100k.json")
    with open(output_path, "w") as f:
        json.dump(output, f)

    file_size = os.path.getsize(output_path)
    print(f"\nOutput: {output_path}")
    print(f"  File size: {file_size:,} bytes ({file_size/1024:.0f} KB)")
    print("\nDone! Upload this file to CDN for extension clients.")


if __name__ == "__main__":
    compile_bloom()
