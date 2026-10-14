"""URL-parameter PII / token leak detection tests.

Strategy doc Top-20 #20. Pin every regex hit + scoring path against
realistic phishing-redirector and tracker URLs.
"""
from __future__ import annotations

import pytest

from api.services.scoring import _detect_url_pii_leak


def test_no_query_string_returns_zero():
    """Plain domain, no '?'. No PII signal possible — weight 0."""
    out = _detect_url_pii_leak("paypal.com/login")
    assert out == {"jwt": False, "email": False, "long_random": False, "weight": 0}


def test_jwt_in_query_flagged():
    """Classic phishing redirector: ?token=eyJ..."""
    url = (
        "example.com/r?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NSJ9.signature_part"
    )
    out = _detect_url_pii_leak(url)
    assert out["jwt"] is True
    assert out["email"] is False
    # Cap respected — weight stays ≤ 25.
    assert out["weight"] == 25


def test_email_in_query_flagged():
    """Tracker pattern: ?email=alice@example.com."""
    out = _detect_url_pii_leak(
        "click.tracker.com/redir?email=alice@example.com&u=https://target.com"
    )
    assert out["email"] is True
    assert out["jwt"] is False
    assert out["weight"] == 15


def test_jwt_and_email_capped_at_25():
    """When multiple PII signals fire, the contribution is capped so a
    single URL can't single-handedly dominate the verdict."""
    url = (
        "phish.example/r?email=victim@bank.com&"
        "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.sig"
    )
    out = _detect_url_pii_leak(url)
    assert out["jwt"] is True
    assert out["email"] is True
    # Cap holds — never above 25.
    assert out["weight"] == 25


def test_percent_encoded_email_decoded_first():
    """%40 hides the @. We URL-decode the query before matching so a
    sneakily-encoded email is still caught."""
    url = "example.com/r?u=alice%40example.com"
    out = _detect_url_pii_leak(url)
    assert out["email"] is True


def test_long_random_session_id_flagged():
    """Long high-entropy value that looks like a session id."""
    url = "example.com/r?session=Abc123DefGhi456Jkl789Mno012Pqr"
    out = _detect_url_pii_leak(url)
    assert out["long_random"] is True
    # When only long-random fires, weight is the small contribution.
    assert out["weight"] == 5


def test_long_random_skipped_when_jwt_or_email_present():
    """The long-random heuristic is noisy. We don't double-count it
    when a higher-confidence pattern (JWT/email) already fired."""
    url = (
        "example.com/r?email=alice@x.com&"
        "tracking=Abc123DefGhi456Jkl789Mno012Pqr"
    )
    out = _detect_url_pii_leak(url)
    assert out["email"] is True
    assert out["long_random"] is False, (
        "long_random suppressed when email/jwt is present"
    )


def test_letters_only_long_value_not_flagged():
    """Pure-alpha tokens (e.g. CSRF cookies that just use letters) are
    common false positives — require BOTH letters AND digits."""
    out = _detect_url_pii_leak("example.com/r?csrf=AbcDefGhiJklMnoPqrStuVwxYzAbcDef")
    assert out["long_random"] is False


def test_digits_only_long_value_not_flagged():
    """Pure-numeric value (e.g. a timestamp or product id). Not enough
    entropy to be a session id."""
    out = _detect_url_pii_leak("example.com/r?ts=20260616103045123456789012")
    assert out["long_random"] is False


def test_safe_url_with_short_params():
    """A normal URL with reasonable query parameters. No flags."""
    out = _detect_url_pii_leak("example.com/search?q=cleanway&page=2&lang=en")
    assert out == {"jwt": False, "email": False, "long_random": False, "weight": 0}


def test_malformed_url_doesnt_crash():
    """Defensive: a malformed URL should return zero weight, not raise."""
    out = _detect_url_pii_leak("?\x00broken")
    # Either zeros or no JWT/email — must not throw.
    assert isinstance(out, dict)
    assert out["weight"] == 0


@pytest.mark.parametrize(
    "url",
    [
        "auth.example/cb?code=eyJabc.eyJdef.signature",  # JWT-shaped
        "login.fake/?token=eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.sig",
        "redirect.attacker/r?sso=eyJfoo.eyJbar.eyJbaz",
    ],
)
def test_real_phishing_patterns_caught(url):
    """Each of these patterns appears in actual phishing campaigns
    (auth-token-as-URL-parameter style). All three should weight in."""
    out = _detect_url_pii_leak(url)
    assert out["jwt"] is True


def test_score_signal_wires_into_calculate_score():
    """End-to-end: calculate_score with a raw_url that carries PII
    must surface a url_pii_leak reason in the output."""
    from api.services.scoring import calculate_score

    signals = {
        "domain": "redirector.example",
        "raw_url": "redirector.example/r?email=victim@bank.com",
        "blocklist_hits": 0,
        "checks_succeeded": 14,
        "total_checks": 14,
    }
    _, _, reasons = calculate_score(signals)
    pii_reasons = [r for r in reasons if r.signal == "url_pii_leak"]
    assert len(pii_reasons) == 1
    assert "email" in pii_reasons[0].detail.lower()


# ─── Linear-time matchers (CodeQL py/polynomial-redos) ──────────────────────
# _has_jwt / _has_email replaced two unanchored regexes that re.search retried
# from every offset — quadratic on "eyJeyJ…" or "%%%%…". They must answer
# exactly what the old regexes answered, and in linear time.

import random  # noqa: E402
import re  # noqa: E402
import time  # noqa: E402

from api.services.scoring import _has_email, _has_jwt  # noqa: E402

_OLD_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_OLD_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")


@pytest.mark.parametrize("text", [
    "", "eyJ", "eyJa.b.c", "eyJ.b.c", "eyJa..c", "eyJa.b.", "xxeyJa.b.c", "eyJeyJ.b.c",
    "a.eyJb.c.d", "eyJa.b", "eyJ-_.x.y", "token=eyJhbGc.eyJzdWI.sig&x=1", "eyJa.b.c.d.e",
    "a@b.co", "@b.co", "a@b.c", "a@.co", "a@b..co", "%@x.com", "a b@c.de", "a@b@c.de",
    "foo=bar%40example.com", "a@b.c0m", "me@sub.domain.museum", "x@y." + "z" * 30,
])
def test_linear_matchers_agree_with_the_old_regexes(text):
    assert _has_jwt(text) is bool(_OLD_JWT_RE.search(text))
    assert _has_email(text) is bool(_OLD_EMAIL_RE.search(text))


def test_linear_matchers_agree_on_random_strings():
    rng = random.Random(20261015)
    alphabet = ["e", "y", "J", "eyJ", ".", "@", "a", "Z", "9", "-", "_", "%", "+", "&", "=", " ", "co", "com"]
    for _ in range(5000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
        assert _has_jwt(text) is bool(_OLD_JWT_RE.search(text)), text
        assert _has_email(text) is bool(_OLD_EMAIL_RE.search(text)), text


@pytest.mark.parametrize("hostile", [
    "eyJ" * 30_000,
    "eyJa" * 30_000 + ".",
    "%" * 100_000,
    "a" * 100_000 + "@",
    "@a" * 50_000,
])
def test_pii_leak_detection_is_linear(hostile):
    started = time.perf_counter()
    _detect_url_pii_leak("example.com/?q=" + hostile)
    assert time.perf_counter() - started < 1.0
