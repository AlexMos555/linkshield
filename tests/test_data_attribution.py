"""The credit the open data asks for is on the site and in the app, in every language.

Since 2026-10-23 the popularity ranking (the allowlist, the phone's veto list,
the extensions' tenant suffixes) and the phishing model's real-site examples
come from the Majestic Million (CC BY 3.0) and the Chrome UX Report
(CC BY 4.0). CC BY asks for the credit where the adapted data is used in
public. The shipped files carry it in their headers (docs/THIRD_PARTY_FEEDS.md
§5); people read it in the "Data sources" section of /transparency/methodology,
linked from the transparency report and from the app's Settings → About.

Pinned here:
  * every string of that section, the report's link and the Settings row
    exists in all ten locales, and a sentence is not left in English (a
    missing key renders as the raw key on the page and in the app);
  * the Settings row names both CC BY datasets and licences in every
    language;
  * the ranking's sentence does not say the installed apps carry it: the
    Android app's veto list and the extensions' tenant suffixes ship with
    their next releases (docs/THIRD_PARTY_FEEDS.md §2a), and only their own
    sentence names them;
  * every feed the blocklist (with BLOCKLIST_LICENSED_ONLY, as production
    runs it) and the model are built from is listed in
    landing/lib/data-sources.ts, so a new source cannot ship uncredited.

What each listed source links to, and that the app's link lands on the
section the page renders, is in scripts/test-landing-honesty.mjs, which can
import the TypeScript.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
I18N_DIR = ROOT / "packages" / "i18n-strings" / "src"
DATA_SOURCES_TS = ROOT / "landing" / "lib" / "data-sources.ts"

LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]

# (namespace path, keys) of every string the attribution renders.
ATTRIBUTION_KEYS: dict[tuple[str, ...], tuple[str, ...]] = {
    ("landing", "methodology"): (
        "sources_heading",
        "sources_intro",
        "sources_popularity_heading",
        "sources_popularity_body",
        "sources_popularity_apps",
        "sources_popularity_model",
        "sources_phishing_heading",
        "sources_phishing_body",
        "sources_via",
        "sources_terms",
        "sources_full_list",
    ),
    ("landing", "transparency"): ("sources_link",),
    ("mobile", "settings"): ("data_sources", "data_sources_desc"),
}
# Names and licences, never translated: the credit is to them.
CREDITED_IN_APP = ("Majestic Million", "CC BY 3.0", "Chrome UX Report", "CC BY 4.0")
# A sentence, not a name (scripts/check-i18n-parity.py uses the same bar).
LONG_WORDS = 4


def _load(locale: str) -> dict:
    return json.loads((I18N_DIR / f"{locale}.json").read_text(encoding="utf-8"))


def _node(data: dict, path: tuple[str, ...]) -> dict:
    for part in path:
        data = data.get(part, {})
    return data


def _module(name: str):
    """A script loaded the way its own test loads it (not left in sys.modules)."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _attributed_ids() -> set[str]:
    """The `id` of every source the page lists (one `id: "..."` line each)."""
    return set(re.findall(r'^\s*id: "([^"]+)",$', DATA_SOURCES_TS.read_text(encoding="utf-8"), re.M))


@pytest.mark.parametrize("locale", LOCALES)
def test_every_attribution_string_exists(locale):
    data = _load(locale)
    missing = [
        ".".join((*path, key))
        for path, keys in ATTRIBUTION_KEYS.items()
        for key in keys
        if not isinstance(_node(data, path).get(key), str) or not _node(data, path)[key].strip()
    ]
    assert not missing, f"[{locale}] missing or empty: {missing}"


@pytest.mark.parametrize("locale", [loc for loc in LOCALES if loc != "en"])
def test_no_attribution_sentence_is_left_in_english(locale):
    en, data = _load("en"), _load(locale)
    english = [
        ".".join((*path, key))
        for path, keys in ATTRIBUTION_KEYS.items()
        for key in keys
        if _node(data, path).get(key) == _node(en, path).get(key)
        and len(str(_node(en, path).get(key, "")).split()) >= LONG_WORDS
    ]
    assert not english, f"[{locale}] still English: {english}"


@pytest.mark.parametrize("locale", LOCALES)
def test_the_settings_row_names_both_cc_by_datasets(locale):
    desc = _load(locale)["mobile"]["settings"]["data_sources_desc"]
    for name in CREDITED_IN_APP:
        assert name in desc, f"[{locale}] mobile.settings.data_sources_desc does not name {name!r}: {desc!r}"


@pytest.mark.parametrize("locale", LOCALES)
def test_the_ranking_sentence_leaves_the_installed_apps_out(locale):
    # Installed builds keep Tranco's lists until the next releases, so the
    # present-tense sentence about the ranking names only what the server
    # does; the apps get their own sentence, which promises the next releases.
    # "Android" is spelled in Latin in every locale.
    methodology = _load(locale)["landing"]["methodology"]
    assert "Android" not in methodology["sources_popularity_body"], f"[{locale}] {methodology['sources_popularity_body']!r}"
    assert "Android" in methodology["sources_popularity_apps"], f"[{locale}] {methodology['sources_popularity_apps']!r}"


def test_both_cc_by_datasets_are_listed():
    assert {"Majestic Million", "Chrome UX Report"} <= _attributed_ids()


def test_every_feed_the_licensed_blocklist_reads_is_listed():
    rdd = _module("refresh_dangerous_domains")
    excluded = rdd.excluded_feeds({rdd.LICENSED_ONLY_ENV: "1"})
    # CSIRT Italia is a MISP manifest that _fetch_feeds reads itself, not a
    # single-GET spec. PhishTank joins only with a key nobody has (§1); it
    # needs a line on the page the day BLOCKLIST_PHISHTANK_SOURCE is set.
    feeds = {spec[0] for spec in rdd._feed_specs(excluded)} | {"CSIRT Italia"}
    assert feeds, "no feeds"
    assert not feeds & rdd.NON_COMMERCIAL_FEEDS
    assert feeds <= _attributed_ids(), f"not credited on the page: {sorted(feeds - _attributed_ids())}"


def test_every_feed_the_model_learns_from_is_listed():
    rtf = _module("refresh_training_feeds")
    trained = {source.name for source in rtf.PHISHING_SOURCES}
    # What the served model and the committed ranking really recorded.
    meta = json.loads((ROOT / "data" / "model_meta.json").read_text(encoding="utf-8"))
    ranking = json.loads((ROOT / "data" / "top_domains_sources.json").read_text(encoding="utf-8"))
    recorded = set(meta["phishing_sources"]) | set(ranking["sources"]["phishing_feeds"])
    for names in (trained, recorded):
        assert names <= _attributed_ids(), f"not credited on the page: {sorted(names - _attributed_ids())}"
