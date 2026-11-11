"""Which generated mobile/i18n file a flat key of the source goes to.

Every base file, mobile/i18n/<locale>.json, is imported by
mobile/src/i18n/resources.ts and ships in the iPhone's JS bundle. App
Review's automated check read 1.0.4 as "contains VPN functionality"
(2026-10-30, docs/IOS.md §3.6), and that bundle carried 15 strings per
locale saying "VPN", while the iPhone shows only two of them:

  * 8 in landing.* (the support FAQ about the Android VPN, the DNS page).
    The app reads neither the landing site's nor the emails' strings — no
    `landing.` or `email.` key appears in mobile/app, mobile/src or
    mobile/modules — so both namespaces stay out of mobile/i18n (about 1 MB
    over the 10 locales as well);
  * 4 that only Android shows: they go to mobile/i18n/android/<locale>.json,
    which only src/i18n/resources.android.ts imports. Metro picks that file
    on Android and resources.ts on iOS and web;
  * 1 iPhone note, reworded without the word (mobile.ios.dns.note_other_dns);
  * 2 that name Apple's own Settings page, General → VPN & Device
    Management → DNS. They stay.

mobile/scripts/test-ios-strings-no-vpn.mjs pins the result, and
scripts/check-mobile-i18n.py fails when the app references a key of a
namespace left out here, or any key the generated files lack. Used by
scripts/build-i18n.py.
"""
from __future__ import annotations

import re

MOBILE_SKIP_NAMESPACES = ("landing.", "email.")
ANDROID_ONLY_KEYS = (
    "mobile.home.interrupted_revoked",       # the VPN permission was taken back
    "mobile.shield.disclosure.body",         # Google Play's VpnService disclosure
    "mobile.keep_alive.always_on_ok",        # the Always-on VPN row
    "mobile.keep_alive.always_on_optional",
)
# A plural variant of an Android-only key is Android-only too.
_PLURAL_VARIANT = re.compile(r"_(?:zero|one|two|few|many|other)$")


def split_for_mobile(flat: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """(base, android) from every flat key of one locale's source.

    The landing and email namespaces are dropped; ANDROID_ONLY_KEYS and their
    plural variants move to the android file. Key order is kept.
    """
    base: dict[str, str] = {}
    android: dict[str, str] = {}
    for key, value in flat.items():
        if key.startswith(MOBILE_SKIP_NAMESPACES):
            continue
        if key in ANDROID_ONLY_KEYS or _PLURAL_VARIANT.sub("", key) in ANDROID_ONLY_KEYS:
            android[key] = value
        else:
            base[key] = value
    return base, android
