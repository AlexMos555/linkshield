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

Review of PR #309 (2026-10-23):
  - 'secure' is not a lure next to 'booking' in those combos: 'secure
    booking' is what hotel and airport booking engines call their checkout
    (four of the six names the rule added on the 1M ranking);
  - the served ML model keeps the is_typosquat it was trained on (rule 1):
    model_meta.json records the definition (feature_data.typosquat_rule),
    and a model trained from now on records rule 2;
  - a hosting tenant's name with the brand in look-alike characters
    (paypa1-login.ngrok-free.app) is a brand on a tenant, as the
    registered names are.
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


# Every name the 2026-10-23 rule flags that the rule before it did not
# (main at cf76ac38 answered None for each).
NEWLY_FLAGGED = (
    "g00glemail.com", "go0glemail.com", "faceb00kmail.com", "ad0belogin.com", "micr0soft-login.com",
    "micr0softlogin.com", "paypa1-login.com", "faceb00k-login.com", "secure-paypa1.com", "outlook-de-login.com",
    "paypal-secure-login.com", "secure-paypal-login.com", "paypal-us-login.com", "apple-id-verify.com",
    "netflix-billing-update.com", "microsoft-account-verify.com", "amazon-de-sign-in.com",
    "micr0soft-account-verify.com", "googlemail-login.com", "5berbank-bonus.ru", "0zon-priz.ru",
    "paypa1-login.tk", "micros0ft-account-verify.com",
)


@pytest.mark.parametrize("domain", NEWLY_FLAGGED)
def test_the_served_model_reads_the_rule_it_was_trained_on(domain):
    # The rule flags the name; the model served today learned is_typosquat
    # from the rule before 2026-10-23 (its model_meta.json records no later
    # definition) and is given that rule's answer. A model trained from now
    # on (LIVE_FEATURE_DATA, what ml/train_model.py reads) learns the new one.
    import api.services.ml_scorer as ml_scorer

    assert _check_typosquatting_v2(domain) is not None, domain
    assert ml_scorer.is_serving(), ml_scorer.model_status()
    served = ml_scorer._feature_data
    if served.typosquat_rule == 1:
        assert ml_features.extract_ml_features(domain, served)["is_typosquat"] == 0.0, domain
        assert _check_typosquatting_v2(domain, rule_version=1) is None, domain
    assert ml_features.extract_ml_features(domain, ml_features.LIVE_FEATURE_DATA)["is_typosquat"] == 1.0


@pytest.mark.parametrize("domain", ["paypal-login.com", "g00gle.com", "rnicrosoft-login.com", "sberbank-bonus.ru",
                                    "securebooking.com", "sberbamk.ru", "ozon-priz.ru"])
def test_rule_1_answers_what_it_always_answered(domain):
    assert _check_typosquatting_v2(domain, rule_version=1) == _check_typosquatting_v2(domain)


def test_the_live_rule_is_the_one_a_new_model_records():
    assert scoring.TYPOSQUAT_RULE_VERSION == 2
    assert ml_features.LIVE_FEATURE_DATA.typosquat_rule == scoring.TYPOSQUAT_RULE_VERSION
    assert ml_features.feature_data_record()["typosquat_rule"] == scoring.TYPOSQUAT_RULE_VERSION


# ── 'secure booking' is a booking engine's checkout, not a lure ──

@pytest.mark.parametrize("domain", [
    # Ranked (licensed 1M, 2026-10-23): a hotel booking engine (rank
    # 216,459, registered 2016), Belfast International Airport's parking and
    # fast-track booking (Rezcomm, rank 796,107), Djubo's hotel sales
    # platform (rank 279,111); live unranked booking engines ('South Beach
    # Resort - Book Secure').
    "secure-direct-hotel-booking.com", "securebooking-belfastairport.com", "secure-booking-engine.com",
    "hotel-booking-secure.net", "secure-online-booking.com",
])
def test_secure_booking_engines_are_not_typosquats(domain):
    assert _check_typosquatting_v2(domain) is None, (domain, _check_typosquatting_v2(domain))


@pytest.mark.parametrize("domain", [
    # The brand and the one keyword: a combo before 2026-10-23 and still.
    "secure-booking.com", "securebooking.com", "booking-secure.com",
    # Any other lure among the words.
    "booking-secure-login.com", "secure-booking-verify.com", "booking-confirm-reservation.com",
    "booking-account-update.com",
])
def test_booking_phishing_names_stay_caught(domain):
    assert _check_typosquatting_v2(domain) == ("booking.com", "combosquatting")


# ── A hosting tenant's name in look-alike characters ──

@pytest.mark.parametrize("host,brand", [
    ("paypa1-login.ngrok-free.app", "paypal"),
    ("paypa1-login.us.kg", "paypal"),
    ("5berbank-bonus.pages.dev", "sberbank"),
    ("micr0soft-login.trycloudflare.com", "microsoft"),
    ("faceb00k-login.netlify.app", "facebook"),
    ("app1e-id-verify.vercel.app", "apple"),
    ("micr0softlogin.pages.dev", "microsoft"),
])
def test_a_look_alike_brand_with_a_lure_on_a_tenant_is_caught(host, brand):
    assert scoring._check_brand_on_hosting_tenant(host) == brand


@pytest.mark.parametrize("host", [
    # No lure, a short brand's 'look-alike' (72 is not t2), the brand's own
    # digits, and a student clone.
    "paypa1.pages.dev", "72-bonus.pages.dev", "office365-tips.netlify.app", "netf1ix-clone.vercel.app",
])
def test_a_look_alike_tenant_without_a_lure_is_not(host):
    assert scoring._check_brand_on_hosting_tenant(host) is None


def test_the_reason_says_which_brand():
    _, _, reasons = scoring.calculate_score({"domain": "outlook-de-login.com"})
    typo = [r for r in reasons if r.signal == "typosquatting"]
    assert typo and typo[0].detail == "Impersonates outlook.com (combosquatting)"
