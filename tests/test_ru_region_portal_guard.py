"""A region's state-service portal (gosuslugi26.ru, 51gosuslugi.ru) is not
flagged by the ML model's weight alone.

The 2026-10-12 weekly retrain scored all 14 regional Gosuslugi portals of
tests/data/ru_heuristics_legit.txt above 0.6 (brand + digits reads like
sberbank24.ru), and the held-out Russian gate of retrain-ml.yml refused the
model. The set stays held out of training; the scorer withholds the model's
weight for exactly this shape: the brand's own name with a 01-99 region
number in front or behind, under .ru or .рф. Everything else — a lure word,
a look-alike letter, another TLD — keeps the model's weight and the name
rules, which these tests pin with a stubbed model so a retrain cannot move
them.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from api.models.schemas import RiskLevel
from api.services.scoring import calculate_score, is_regional_state_portal_name

LEGIT = Path(__file__).resolve().parent / "data" / "ru_heuristics_legit.txt"


def _held_out_portals() -> list[str]:
    hosts = []
    for line in LEGIT.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            host = line.split(" | ")[0].strip()
            if "gosuslugi" in host:
                hosts.append(host)
    return hosts


PORTALS = _held_out_portals()

# Not a region's portal: each must keep the model's weight.
NOT_PORTALS = [
    "gosuslugi-oplata.ru",      # lure word (typosquatting rule)
    "gosuslugi26-pay.ru",       # region number + lure word
    "gosusiugi26.ru",           # homoglyph: l -> i
    "gosuslugl26.ru",           # homoglyph: i -> l
    "gosuslugi26.top",          # phishing-favoured TLD
    "gosuslugi26.com",          # not a Russian TLD
    "gosuslugi100.ru",          # three digits
    "gosuslugi00.ru",           # no region 00
    "gosuslugi0.ru",
    "gosuslugi2626.ru",
    "mygosuslugi26.ru",         # anything around the brand + number
    "gosuslugi26lk.ru",
    "gosuslugi26.tw1.ru",       # a hosting tenant: the registered name is tw1
    "gosuslugi26.spb.ru",       # a regional zone anyone can register under
    "sberbank26.ru",            # not a state-service brand
]


@pytest.fixture
def ml_says(monkeypatch):
    import api.services.ml_scorer as ml_scorer

    def stub(prob: float, confidence: float = 0.9):
        monkeypatch.setattr(
            ml_scorer, "ml_predict",
            lambda domain: {"phishing_probability": prob, "confidence": confidence},
        )
    return stub


def _ml_signals(domain: str) -> set[str]:
    _, _, reasons = calculate_score({"domain": domain})
    return {r.signal for r in reasons if r.signal.startswith("ml_") and r.weight > 0}


def test_the_held_out_set_has_the_fourteen_portals():
    assert len(PORTALS) == 14
    assert "gosuslugi26.ru" in PORTALS and "51gosuslugi.ru" in PORTALS and "44gosuslugi.ru" in PORTALS


@pytest.mark.parametrize("host", PORTALS + [
    "gosuslugi1.ru", "gosuslugi01.ru", "99gosuslugi.ru",
    "new.gosuslugi86.ru",                     # the Yugra portal's own subdomain
    "госуслуги74.рф".encode("idna").decode("ascii"),
])
def test_regional_portal_shape(host):
    assert is_regional_state_portal_name(host)


@pytest.mark.parametrize("host", NOT_PORTALS + ["gosuslugi.ru"])
def test_not_a_regional_portal(host):
    assert not is_regional_state_portal_name(host)


@pytest.mark.parametrize("host", PORTALS)
@pytest.mark.parametrize("prob", [0.65, 0.99])
def test_the_model_alone_does_not_flag_a_regional_portal(ml_says, host, prob):
    ml_says(prob)
    score, level, reasons = calculate_score({"domain": host})
    assert not _ml_signals(host), [(r.signal, r.weight) for r in reasons]
    assert level == RiskLevel.safe, (score, [(r.signal, r.weight) for r in reasons])


@pytest.mark.parametrize("host", NOT_PORTALS)
def test_everything_else_keeps_the_models_weight(ml_says, host):
    ml_says(0.99)
    assert "ml_high_risk" in _ml_signals(host)
    ml_says(0.7)
    assert "ml_suspicious" in _ml_signals(host)


@pytest.mark.parametrize("host, at_least", [
    # What the name rules alone say today (2026-10-15) — the guard leaves it.
    ("gosuslugi-oplata.ru", RiskLevel.caution),
    ("gosuslugi26.top", RiskLevel.dangerous),
    ("gosuslugi26.com", RiskLevel.caution),
    ("gosuslugi77.ru", RiskLevel.caution),     # not a region's portal: 77 is not in 'official'
])
def test_the_name_rules_still_judge_the_name(ml_says, host, at_least):
    order = [RiskLevel.safe, RiskLevel.caution, RiskLevel.dangerous]
    for prob in (0.3, 0.99):
        ml_says(prob, confidence=0.5)
        _, level, _ = calculate_score({"domain": host})
        assert order.index(level) >= order.index(at_least), (host, prob, level)


def test_gosuslugi77_keeps_its_typosquat_signal_under_the_guard(ml_says):
    # The guard withholds only the model's weight: 77 matches the shape, so
    # the model is silent, but the typosquat rule still reports the name.
    ml_says(0.99)
    _, level, reasons = calculate_score({"domain": "gosuslugi77.ru"})
    signals = {r.signal for r in reasons if r.weight > 0}
    assert "typosquatting" in signals and not _ml_signals("gosuslugi77.ru")
    assert level != RiskLevel.safe
