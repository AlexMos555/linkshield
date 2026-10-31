"""A popularity rank a young registration did not earn gives no trust.

A rank is the links and visits a name gathered, maybe under an earlier holder
(a dropped name keeps its backlinks) or bought from a link farm. Of ranked
names with a known registration date on 2026-10-31, 24% of ranks 100k-1M and
8% of the top 100k were registered within a year — mostly casinos, link
farms and piracy (11 *.uk/*.nl names registered the same day, ranks
130k-360k). analyzer._young_rank: such a name's rank is replaced by
"unranked" when settings.popularity_age_gate is "on"; "shadow" only logs.
"""
from __future__ import annotations

import logging

import pytest

from api.config import get_settings
from api.services import analyzer, scoring
from api.services.ml_features import extract_ml_features
from api.services.url_features import extract_features

RANKED = {"ranked": True, "rank": 176_011, "weight": -3, "label": "Top 1M", "registrable_rank": 176_011}


@pytest.fixture
def gate(monkeypatch):
    def _set(mode: str = "on", days: int = 365) -> None:
        monkeypatch.setattr(get_settings(), "popularity_age_gate", mode, raising=False)
        monkeypatch.setattr(get_settings(), "popularity_min_age_days", days, raising=False)
    return _set


def _outcomes(age, tranco=RANKED, pulses=0, **extra) -> dict:
    out = {"tranco": (tranco, True), "whois": ({"age_days": age} if age is not None else {}, True),
           "alienvault": ({"pulse_count": pulses, "distinct_pulses": pulses, "hit": pulses > 0}, True)}
    out.update({k: (v, True) for k, v in extra.items()})
    return out


def _signals(domain: str, outcomes: dict) -> dict:
    sig = analyzer._build_signals(domain, domain, False, outcomes, 18)
    sig["checks_succeeded"] = 18
    sig["total_checks"] = 18
    return sig


def test_a_young_names_rank_is_withheld(gate):
    gate("on")
    sig = _signals("primebonusworks.uk", _outcomes(121))
    assert (sig["tranco_ranked"], sig["tranco_rank"], sig["tranco_registrable_rank"], sig["tranco_weight"]) == (
        False, None, None, 0)
    assert sig["popularity_withheld"] is True and sig["young_rank"] == 176_011
    _, _, reasons = scoring.calculate_score(sig)
    assert "tranco_popularity" not in {r.signal for r in reasons}


def test_an_old_names_rank_stays(gate):
    gate("on")
    sig = _signals("example-old-site.co.uk", _outcomes(3000))
    assert sig["tranco_rank"] == 176_011 and sig["popularity_withheld"] is False and sig["young_rank"] is None


@pytest.mark.parametrize("age, withheld", [(364, True), (365, False)])
def test_the_boundary(gate, age, withheld):
    gate("on")
    assert _signals("boundary-example.com", _outcomes(age))["popularity_withheld"] is withheld


@pytest.mark.parametrize("whois", [None, "failed"])
def test_an_unknown_age_keeps_the_rank(gate, whois):
    """.ru and .de have no RDAP, GMO answers 429: the rank applies as before."""
    gate("on")
    outcomes = _outcomes(None)
    if whois == "failed":
        outcomes["whois"] = ({}, False)
    sig = _signals("no-rdap-example.ru", outcomes)
    assert sig["tranco_rank"] == 176_011 and sig["popularity_withheld"] is False


def test_otx_reports_about_a_young_ranked_name_count_in_full(gate):
    gate("off")
    off = _signals("primebonusworks.uk", _outcomes(121, pulses=3))
    gate("on")
    on = _signals("primebonusworks.uk", _outcomes(121, pulses=3))
    otx = lambda sig: sum(r.weight for r in scoring.calculate_score(sig)[2] if r.signal.startswith("alienvault_otx"))  # noqa: E731
    assert otx(off) == 0  # top 1M, up to 5 reports: waived
    assert otx(on) == 30
    assert off["blocklist_hits"] == 0 and on["blocklist_hits"] == 1


def test_a_young_rank_vouches_for_nothing(gate, monkeypatch):
    gate("on")
    sig = _signals("primebonusworks.uk", _outcomes(121))

    async def _no_lookup(name):
        raise AssertionError("a withheld rank is not looked up again")

    monkeypatch.setattr(analyzer, "get_tranco_rank", _no_lookup)
    import asyncio

    from api.services.analysis_budget import Deadline
    assert asyncio.run(analyzer._name_is_vouched_for("primebonusworks.uk", sig, Deadline(5.0))) is False
    gov = _signals("portal.gov.uk", _outcomes(121))
    assert asyncio.run(analyzer._name_is_vouched_for("portal.gov.uk", gov, Deadline(5.0))) is True


def test_a_young_ranked_names_fresh_certificate_is_not_a_renewal(gate):
    gate("off")
    off = scoring.calculate_score(_signals("primebonusworks.uk", _outcomes(121, ssl={"has_ssl": True, "cert_age_days": 3})))
    gate("on")
    on = scoring.calculate_score(_signals("primebonusworks.uk", _outcomes(121, ssl={"has_ssl": True, "cert_age_days": 3})))
    assert "new_certificate" not in {r.signal for r in off[2]}
    assert "new_certificate" in {r.signal for r in on[2]}


def test_the_llm_judge_is_not_told_a_withheld_rank(gate):
    from api.services import llm_judge

    gate("off")
    off = llm_judge._extract_judge_features(_signals("primebonusworks.uk", _outcomes(121)), 10)
    gate("on")
    on = llm_judge._extract_judge_features(_signals("primebonusworks.uk", _outcomes(121)), 10)
    assert off["popularity_ranked"] is True and off["popularity_weight"] == -3
    assert on["popularity_ranked"] is False and on["popularity_weight"] == 0


def test_the_models_inputs_do_not_change(gate):
    gate("off")
    off = _signals("primebonusworks.uk", _outcomes(121))
    gate("on")
    on = _signals("primebonusworks.uk", _outcomes(121))
    assert extract_features("primebonusworks.uk", off) == extract_features("primebonusworks.uk", on)
    assert extract_ml_features("primebonusworks.uk") == extract_ml_features("primebonusworks.uk")


def test_shadow_changes_nothing(gate):
    gate("shadow")
    sig = _signals("primebonusworks.uk", _outcomes(121))
    assert sig["tranco_rank"] == 176_011 and sig["popularity_withheld"] is False and sig["young_rank"] == 176_011


def test_shadow_logs_what_withholding_would_change(gate, offline_analyzer, caplog):
    import asyncio

    gate("shadow")
    offline_analyzer(site="reachable", values={"tranco": RANKED, "whois": {"age_days": 121}})
    with caplog.at_level(logging.INFO, logger=analyzer.logger.name):
        asyncio.run(analyzer.analyze_domain("primebonusworks.uk", budget_s=5.0))
    shadow = [r for r in caplog.records if r.getMessage() == "popularity_age_gate_shadow"]
    assert len(shadow) == 1
    assert shadow[0].rank == 176_011 and shadow[0].age_days == 121
    assert hasattr(shadow[0], "gated_verdict")


def test_off_and_on_log_no_shadow(gate, offline_analyzer, caplog):
    import asyncio

    for mode in ("off", "on"):
        gate(mode)
        offline_analyzer(site="reachable", values={"tranco": RANKED, "whois": {"age_days": 121}})
        with caplog.at_level(logging.INFO, logger=analyzer.logger.name):
            asyncio.run(analyzer.analyze_domain("primebonusworks.uk", budget_s=5.0))
    assert not [r for r in caplog.records if r.getMessage() == "popularity_age_gate_shadow"]


def test_the_model_cannot_talk_a_young_ranked_name_down(gate, monkeypatch):
    from api.services import ml_scorer

    monkeypatch.setattr(ml_scorer, "ml_predict", lambda d: {"phishing_probability": 0.02, "confidence": 0.9})
    host = "paypal.com.login.primebonusworks.uk"
    gate("off")
    off = scoring.calculate_score(_signals(host, _outcomes(121)))
    gate("on")
    on = scoring.calculate_score(_signals(host, _outcomes(121)))
    assert "ml_safe_override" in {r.signal for r in off[2]}
    assert "ml_safe_override" not in {r.signal for r in on[2]}
