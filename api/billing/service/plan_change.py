"""Changing plans (§2.4): unused days are converted, never refunded in money.

    20 days left at 99 ₽ ≈ 66 ₽ ≈ 7 days at 270 ₽.

An upgrade is a NEW consent with the new price (pre-ticked boxes are
illegal, п. 3.1 ст. 16 ЗоЗПП); a downgrade takes effect at the end of the
paid period. Only the arithmetic lives here; the endpoint is a later PR.
"""
from __future__ import annotations

from datetime import datetime


def days_remaining(period_end: datetime, now: datetime) -> int:
    """Whole days left in the paid period, never negative."""
    return max(0, (period_end - now).days)


def converted_days(remaining_days: int, old_price_kopecks: int, new_price_kopecks: int) -> int:
    """How many days of the new plan the unused days of the old one buy (rounded down)."""
    if remaining_days <= 0 or old_price_kopecks <= 0:
        return 0
    if new_price_kopecks <= 0:
        raise ValueError("new price must be positive")
    return (remaining_days * old_price_kopecks) // new_price_kopecks


def is_upgrade(old_price_kopecks: int, new_price_kopecks: int) -> bool:
    return new_price_kopecks > old_price_kopecks
