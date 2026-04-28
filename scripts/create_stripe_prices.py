#!/usr/bin/env python3
"""
Create the 24 Stripe price IDs Cleanway needs (3 plans × 4 PPP tiers × 2 intervals).

Run this ONCE after activating the Stripe account. It's idempotent: if a price
with the same lookup_key already exists, it's reused. Output is a YAML block
ready to paste into Railway env (STRIPE_PRICE_PERSONAL_T1_MONTHLY=price_xxx
and so on) plus a JSON dump for the api/services/pricing.py PRICE_MAP.

Why lookup keys: Stripe price IDs change when you delete + recreate a product,
but lookup keys stay stable. The price IDs we hardcode in env vars stay fresh
because we look them up by key on subsequent runs.

Usage:
    export STRIPE_SECRET_KEY=sk_live_...
    python3 scripts/create_stripe_prices.py [--dry-run]

Pre-req: pip install stripe (already in requirements.txt).

Pricing source: .planning/PRICING_MATRIX.md (mirrored here so the script
is self-contained — bump both files together if we re-tier).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterator, NamedTuple


# ───────────────────────────── Pricing matrix ─────────────────────────────
# (plan, tier, interval) → (cents, friendly_name).
# Tier 1 = Premium (×1.2), Tier 2 = Base (×1.0), Tier 3 = Mid (×0.5), Tier 4 = Affordable (×0.3).

class PlanSpec(NamedTuple):
    plan: str
    monthly_cents_t2: int  # baseline at Tier 2
    description: str


PLANS: list[PlanSpec] = [
    PlanSpec("personal", 499, "Cleanway Personal — full threat detail, weekly report, priority support"),
    PlanSpec("family",   999, "Cleanway Family — up to 6 devices, Family Hub, Granny + Kids modes"),
    PlanSpec("business", 399, "Cleanway Business — per-seat phishing protection + simulation"),
]

# Per-tier multiplier (×100 for integer math, then divide).
TIER_MULT: dict[int, float] = {1: 1.20, 2: 1.00, 3: 0.50, 4: 0.30}


def cents_for(plan: PlanSpec, tier: int, interval: str) -> int:
    """Compute integer cents for (plan, tier, interval).

    Yearly is 10× monthly (16.7% discount, matches landing copy "save 17%").
    Round to nearest cent so we don't end up with $4.99 × 0.5 = $2.495.
    """
    monthly = round(plan.monthly_cents_t2 * TIER_MULT[tier])
    return monthly if interval == "monthly" else monthly * 10


def lookup_key(plan: str, tier: int, interval: str) -> str:
    """Stable identifier so we can re-find the price later."""
    return f"cleanway_{plan}_t{tier}_{interval}"


def all_specs() -> Iterator[tuple[str, int, str, int]]:
    for plan in PLANS:
        for tier in (1, 2, 3, 4):
            for interval in ("monthly", "yearly"):
                yield plan.plan, tier, interval, cents_for(plan, tier, interval)


# ───────────────────────────── Stripe interaction ─────────────────────────


def get_or_create_product(stripe, plan: PlanSpec, dry_run: bool):
    """One Stripe Product per plan ('personal', 'family', 'business')."""
    product_id_key = f"cleanway_{plan.plan}"
    existing = stripe.Product.list(active=True, limit=100)
    for p in existing.auto_paging_iter():
        if p.metadata and p.metadata.get("cleanway_plan") == plan.plan:
            return p
    if dry_run:
        print(f"  [dry-run] would create Product cleanway_{plan.plan}")
        return None
    return stripe.Product.create(
        name=plan.description.split("—")[0].strip(),
        description=plan.description,
        metadata={"cleanway_plan": plan.plan, "cleanway_id": product_id_key},
    )


def get_or_create_price(stripe, product, plan: str, tier: int, interval: str, cents: int, dry_run: bool):
    key = lookup_key(plan, tier, interval)
    # Stripe lookup_keys uniquely identify prices we've already created.
    found = stripe.Price.list(lookup_keys=[key], active=True, limit=1)
    if found.data:
        return found.data[0]
    if dry_run:
        print(f"  [dry-run] would create Price {key} = ${cents/100:.2f} {interval}")
        return None
    return stripe.Price.create(
        product=product.id,
        unit_amount=cents,
        currency="usd",
        recurring={"interval": "month" if interval == "monthly" else "year"},
        lookup_key=key,
        metadata={
            "cleanway_plan": plan,
            "cleanway_tier": str(tier),
            "cleanway_interval": interval,
        },
        nickname=f"{plan.title()} T{tier} {interval}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Print what would be created; don't touch Stripe")
    args = parser.parse_args()

    secret = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not secret:
        print("error: STRIPE_SECRET_KEY env var not set", file=sys.stderr)
        return 2
    if not args.dry_run and not secret.startswith(("sk_live_", "sk_test_")):
        print("error: STRIPE_SECRET_KEY doesn't look right (must start sk_live_ or sk_test_)", file=sys.stderr)
        return 2

    try:
        import stripe  # type: ignore
    except ImportError:
        print("error: pip install stripe", file=sys.stderr)
        return 2
    stripe.api_key = secret

    print(f"{'DRY RUN — ' if args.dry_run else ''}creating products + 24 prices...\n")

    products: dict[str, object] = {}
    for plan in PLANS:
        prod = get_or_create_product(stripe, plan, args.dry_run)
        products[plan.plan] = prod

    price_map: dict[str, dict[int, dict[str, str]]] = {p.plan: {1: {}, 2: {}, 3: {}, 4: {}} for p in PLANS}
    env_lines: list[str] = []

    for plan_name, tier, interval, cents in all_specs():
        product = products[plan_name]
        if product is None and not args.dry_run:
            continue
        price = get_or_create_price(stripe, product, plan_name, tier, interval, cents, args.dry_run)
        price_id = price.id if price else f"<dry-run:{lookup_key(plan_name, tier, interval)}>"
        price_map[plan_name][tier][interval] = price_id
        env_var = f"STRIPE_PRICE_{plan_name.upper()}_T{tier}_{interval.upper()}"
        env_lines.append(f"{env_var}={price_id}")
        print(f"  {plan_name:<8} T{tier} {interval:<7} ${cents/100:>7.2f}  {price_id}")

    print("\n" + "=" * 60)
    print("Paste into Railway env vars (Service → Variables → Raw editor):")
    print("=" * 60)
    for line in env_lines:
        print(line)

    print("\n" + "=" * 60)
    print("PRICE_MAP for api/services/pricing.py:")
    print("=" * 60)
    print(json.dumps(price_map, indent=2))

    if args.dry_run:
        print("\n(dry run — re-run without --dry-run to actually create on Stripe)")
    else:
        print("\nDone. 1 Product per plan + 24 Prices live on Stripe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
