#!/usr/bin/env python3
"""
Create the 16 Stripe prices the world's device plan needs:
(plan + extra device) × 4 PPP tiers × 2 intervals.

Run this ONCE after activating the Stripe account (and again after a price
change). It's idempotent: a price whose lookup_key already exists is reused.
Output is a block of env lines to paste into Railway:

    STRIPE_PRICE_DEVICES_T1_MONTHLY=price_...
    STRIPE_PRICE_EXTRA_DEVICE_T1_MONTHLY=price_...
    ...

which api/services/pricing.py reads at import time.

The amounts are NOT mirrored here: the script imports TIER_PRICES from
api/services/pricing.py, so the page, the API and Stripe cannot drift apart.
Stripe prices are immutable — when an amount changes, the lookup key changes
too (it carries the amount), a new price is created, and the env line must be
updated; running subscriptions keep their old price until moved.

Usage:
    export STRIPE_SECRET_KEY=sk_test_...   # or sk_live_...
    python3 scripts/create_stripe_prices.py [--dry-run]

Pre-req: pip install stripe (already in requirements.txt).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterator, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services.pricing import INTERVALS, TIER_NAMES, TIER_PRICES, TIERS  # noqa: E402


class ProductSpec(NamedTuple):
    key: str          # "devices" | "extra_device" — also the env-var stem
    name: str
    description: str


PRODUCTS: tuple[ProductSpec, ...] = (
    ProductSpec(
        "devices",
        "Cleanway Unlimited",
        "Unlimited detailed checks of links and messages on 3 devices of one account.",
    ),
    ProductSpec(
        "extra_device",
        "Cleanway extra device",
        "One more device on a Cleanway Unlimited subscription.",
    ),
)


class PriceSpec(NamedTuple):
    product: ProductSpec
    tier: int
    interval: str
    cents: int

    @property
    def env_var(self) -> str:
        return f"STRIPE_PRICE_{self.product.key.upper()}_T{self.tier}_{self.interval.upper()}"

    @property
    def lookup_key(self) -> str:
        """Stable per amount: a new amount gets a new key (Stripe prices are immutable)."""
        return f"cleanway_{self.product.key}_t{self.tier}_{self.interval}_{self.cents}"


def all_specs() -> Iterator[PriceSpec]:
    for product in PRODUCTS:
        for tier in TIERS:
            prices = TIER_PRICES[tier]
            for interval in INTERVALS:
                cents = prices.plan(interval) if product.key == "devices" else prices.extra_device(interval)
                yield PriceSpec(product, tier, interval, cents)


# ───────────────────────────── Stripe interaction ─────────────────────────


def get_or_create_product(stripe, spec: ProductSpec, dry_run: bool):
    """One Stripe Product per ProductSpec, found again by metadata."""
    for p in stripe.Product.list(active=True, limit=100).auto_paging_iter():
        if p.metadata and p.metadata.get("cleanway_product") == spec.key:
            return p
    if dry_run:
        print(f"  [dry-run] would create Product {spec.name}")
        return None
    return stripe.Product.create(
        name=spec.name,
        description=spec.description,
        metadata={"cleanway_product": spec.key},
    )


def get_or_create_price(stripe, product, spec: PriceSpec, dry_run: bool):
    found = stripe.Price.list(lookup_keys=[spec.lookup_key], active=True, limit=1)
    if found.data:
        return found.data[0]
    if dry_run:
        print(f"  [dry-run] would create Price {spec.lookup_key} = ${spec.cents / 100:.2f} {spec.interval}")
        return None
    return stripe.Price.create(
        product=product.id,
        unit_amount=spec.cents,
        currency="usd",
        recurring={"interval": "month" if spec.interval == "monthly" else "year"},
        lookup_key=spec.lookup_key,
        metadata={
            "cleanway_product": spec.product.key,
            "cleanway_tier": str(spec.tier),
            "cleanway_interval": spec.interval,
        },
        nickname=f"{spec.product.name} T{spec.tier} ({TIER_NAMES[spec.tier]}) {spec.interval}",  # type: ignore[index]
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

    specs = list(all_specs())
    print(f"{'DRY RUN — ' if args.dry_run else ''}creating {len(PRODUCTS)} products + {len(specs)} prices...\n")

    products = {spec.key: get_or_create_product(stripe, spec, args.dry_run) for spec in PRODUCTS}

    env_lines: list[str] = []
    for spec in specs:
        product = products[spec.product.key]
        if product is None and not args.dry_run:
            continue
        price = get_or_create_price(stripe, product, spec, args.dry_run)
        price_id = price.id if price else f"<dry-run:{spec.lookup_key}>"
        env_lines.append(f"{spec.env_var}={price_id}")
        print(f"  {spec.product.key:<12} T{spec.tier} {spec.interval:<7} ${spec.cents / 100:>6.2f}  {price_id}")

    print("\n" + "=" * 60)
    print("Paste into Railway env vars (Service → Variables → Raw editor):")
    print("=" * 60)
    for line in env_lines:
        print(line)

    if args.dry_run:
        print("\n(dry run — re-run without --dry-run to actually create on Stripe)")
    else:
        print(f"\nDone. {len(PRODUCTS)} Products + {len(specs)} Prices live on Stripe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
