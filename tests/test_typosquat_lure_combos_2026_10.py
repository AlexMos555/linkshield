"""Brand combos the typosquat rule missed (PR #294's known gaps).

The rule compared a name with each brand as a whole word glued or hyphened
to ONE other word (paypal-login, googlemail). Two shapes phishing uses
every day got through:

  - look-alike characters inside the combo: g00glemail, micr0soft-login,
    ad0belogin, paypa1-login — the brand part is no longer the brand's
    string, so neither the combo nor the look-alike test (same length
    only) matched;
  - several hyphenated words for a global brand: outlook-de-login,
    paypal-secure-login, apple-id-verify, netflix-billing-update. The
    Russian brands had this (_check_lure_combo, Russian and English lure
    words); the global ones read 'de-login' as one word and found no lure.

Now a look-alike spelling of a brand (four letters or more, at least one
look-alike character) counts as the brand in a combo, and a global brand
as one whole hyphenated word with an English lure keyword
(_COMBOSQUAT_KEYWORDS, the high-precision list) as another is a combo.
The false-positive pass is in the PR: the whole licensed ranking (1M
names), the names that left the allowlist and the held-out Russian sets.
"""
from __future__ import annotations

import pytest

from api.services import ml_features, scoring
from api.services.scoring import _check_typosquatting_v2


@pytest.mark.parametrize("domain,legit", [
    # look-alike characters inside 'brand + word'
    ("g00glemail.com", "google.com"),
    ("go0glemail.com", "google.com"),
    ("faceb00kmail.com", "facebook.com"),
    ("ad0belogin.com", "adobe.com"),
    ("micr0soft-login.com", "microsoft.com"),
    ("micr0softlogin.com", "microsoft.com"),
    ("paypa1-login.com", "paypal.com"),
    ("faceb00k-login.com", "facebook.com"),
    ("secure-paypa1.com", "paypal.com"),
    # several hyphenated words with a lure keyword
    ("outlook-de-login.com", "outlook.com"),
    ("paypal-secure-login.com", "paypal.com"),
    ("secure-paypal-login.com", "paypal.com"),
    ("paypal-us-login.com", "paypal.com"),
    ("apple-id-verify.com", "apple.com"),
    ("netflix-billing-update.com", "netflix.com"),
    ("microsoft-account-verify.com", "microsoft.com"),
    ("amazon-de-sign-in.com", "amazon.com"),
    # both at once, and a brand glued to a generic word among the words
    ("micr0soft-account-verify.com", "microsoft.com"),
    ("googlemail-login.com", "google.com"),
])
def test_global_brand_combos_are_caught(domain, legit):
    result = _check_typosquatting_v2(domain)
    assert result is not None, domain
    assert result == (legit, "combosquatting"), (domain, result)


@pytest.mark.parametrize("domain,legit", [
    ("5berbank-bonus.ru", "sberbank.ru"),
    ("0zon-priz.ru", "ozon.ru"),
])
def test_a_russian_brand_in_look_alike_characters_with_a_lure_is_caught(domain, legit):
    assert _check_typosquatting_v2(domain) == (legit, "combosquatting")


@pytest.mark.parametrize("domain", [
    # A word next to the brand that is not a lure keyword: shops, fan
    # pages, regional sites keep their answer (amazon-de-support needs
    # 'support', a generic word, which counts only right after the brand).
    "santander-pl.com", "apple-pie-recipes.com", "netflix-and-friends-party.com", "amazon-de-support.com",
    "outlook-de-hilfe.com",
    # The brand not as a whole word (paypalito), or a look-alike of a short
    # brand: 72-bonus is not Tele2 (t2), up5-login stays unread.
    "paypalito-login-guide.com", "72-bonus.ru", "up5-help.com",
    # A digit that is the brand's own (office365) is not a look-alike.
    "office365-tips-and-tricks.com",
])
def test_names_that_are_not_combos_stay_unflagged(domain):
    assert _check_typosquatting_v2(domain) is None, (domain, _check_typosquatting_v2(domain))


@pytest.mark.parametrize("domain,expected", [
    # What the rule already said stays as it was.
    ("g00gle.com", ("google.com", "character substitution")),
    ("paypal-login.com", ("paypal.com", "combosquatting")),
    ("rnicrosoft-login.com", ("microsoft.com", "glyph homoglyph")),
    ("sberbank-bonus.ru", ("sberbank.ru", "combosquatting")),
    ("googlemail.com", None),  # Google's own (data/typosquat_targets.json 'alternates')
])
def test_existing_answers_do_not_move(domain, expected):
    assert _check_typosquatting_v2(domain) == expected


@pytest.mark.parametrize("domain", ["g00glemail.com", "outlook-de-login.com", "micr0soft-login.com"])
def test_the_model_reads_the_same_rule(domain):
    # is_typosquat is the rule's answer, as for every name since
    # features_version 4: a typosquat the rule now names is one to the
    # model as well.
    assert ml_features.extract_ml_features(domain)["is_typosquat"] == 1.0


def test_the_reason_says_which_brand():
    _, _, reasons = scoring.calculate_score({"domain": "outlook-de-login.com"})
    typo = [r for r in reasons if r.signal == "typosquatting"]
    assert typo and typo[0].detail == "Impersonates outlook.com (combosquatting)"
