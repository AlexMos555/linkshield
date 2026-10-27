"""No UI string, in any namespace, is a note to the translator.

Notes reached users through mobile.* twice: ar mobile.report.times_one
("times_one: «…» (and optionally add _two …)", until #303), then, until #310
(2026-10-27), ar mobile.history.minutes_ago / hours_ago / days_ago ("Plural
variants: … Single-string fallback: …") on every History row and it
mobile.breach.found_body ("found_body_one: \"…\" / found_body_other: …") on
the breach card. The landing site, the three extensions and the emails read
the other namespaces of packages/i18n-strings/src (landing.*, extension.*,
email.*), and nothing guarded them; a scan on 2026-10-27 found no note there
yet.

Pinned here, running each script the way CI runs it:
  * scripts/check-i18n-parity.py (lint job) fails on a note in any namespace
    of the source, list items included (the generated mobile/i18n files drop
    lists, so the landing FAQ, terms and pricing bullets are only in the
    source and landing/messages);
  * scripts/check-mobile-i18n.py (mobile job) fails on the shapes the #310
    review found passing: the variant key quoted, dotted, with no colon, or
    mid-sentence;
  * in extension.* and email.* a {"text": …} leaf's `description` stays
    free text: it is chrome.i18n's note for translators, and no browser
    renders it; its other strings, and every key of a landing dict that has
    a "text", are checked;
  * the shared heuristic (scripts/i18n_notes.py) flags none of today's
    strings in the 10 locales, and leaves words like es/pt "todo" (upper
    case too) and id "metodologi", and copy like "Translators wanted", alone;
  * the pre-commit hook runs the parity check on a source edit.
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
SOURCE_DIR = ROOT / "packages" / "i18n-strings" / "src"
LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]


def _module(path: Path):
    """A script loaded the way tests/test_data_attribution.py loads one."""
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _run(tmp_path: Path, script: str, data_dirs: tuple[str, ...], edits: dict) -> subprocess.CompletedProcess:
    """Run a copy of `script` (with the shared i18n_*.py helpers) over copies
    of `data_dirs`, after setting each (file, key path) of `edits` to its value."""
    (tmp_path / "scripts").mkdir()
    for path in [SCRIPTS / script, *sorted(SCRIPTS.glob("i18n_*.py"))]:
        shutil.copy(path, tmp_path / "scripts")
    for rel in data_dirs:
        shutil.copytree(ROOT / rel, tmp_path / rel)
    for (rel, keys), value in edits.items():
        path = tmp_path / rel
        data = json.loads(path.read_text(encoding="utf-8"))
        node = data
        for key in keys[:-1]:
            node = node[key]
        assert isinstance(node, list) or keys[-1] in node, f"{rel}: no {keys}"
        node[keys[-1]] = value
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(tmp_path / "scripts" / script)],
        capture_output=True, text=True, timeout=120,
    )


def _src(locale: str) -> str:
    return f"packages/i18n-strings/src/{locale}.json"


def _dotted(keys: tuple) -> str:
    """The key as the checks print it: list items as [i], a {text} leaf by its own name."""
    out = ""
    for key in keys:
        if isinstance(key, int):
            out += f"[{key}]"
        elif key != "text":
            out += f".{key}" if out else key
    return out


# The notes that shipped, verbatim from the source: times_one until #303
# (f8469f2a), the others until #310 (fefe0fb8).
SHIPPED_NOTES = {
    "ar times_one": (
        "mobile.report.times_one",
        "times_one: «فحص واحد» (and optionally add _two «فحصان», _few «{{count}} فحوصات», "
        "_many «{{count}} فحصًا»; keep _other as «عدد الفحوصات: {{count}}»)",
    ),
    "ar minutes_ago": (
        "mobile.history.minutes_ago",
        "Add Arabic plural variants: minutes_ago_one «قبل دقيقة», _two «قبل دقيقتين», "
        "_few «قبل {{minutes}} دقائق», _many/_other «قبل {{minutes}} دقيقة». If the key must "
        "stay a single string, use the number-safe «قبل {{minutes}} من الدقائق».",
    ),
    "ar hours_ago": (
        "mobile.history.hours_ago",
        "Plural variants: _one «قبل ساعة», _two «قبل ساعتين», _few «قبل {{hours}} ساعات», "
        "_many/_other «قبل {{hours}} ساعة». Single-string fallback: «قبل {{hours}} من الساعات».",
    ),
    "it found_body": (
        "mobile.breach.found_body",
        'found_body_one: "Questo indirizzo è comparso {{times}} volta nelle liste di password '
        'trapelate. Se lo usi come password da qualche parte, cambia subito quella password." / '
        'found_body_other: "Questo indirizzo è comparso {{times}} volte nelle liste di password '
        'trapelate. Se lo usi come password da qualche parte, cambia subito quella password."',
    ),
}

# The four shapes the #310 review found passing check-mobile-i18n.py, keyed
# into the generated mobile files they would land in.
F1_SHAPES = {
    "dotted full key": (
        "it", "mobile.breach.found_body",
        'mobile.breach.found_body_one: "Questo indirizzo è comparso {{times}} volta." / '
        'mobile.breach.found_body_other: "Questo indirizzo è comparso {{times}} volte."',
    ),
    "quoted key": (
        "it", "mobile.breach.found_body",
        '"found_body_one": "Questo indirizzo è comparso {{times}} volta." / '
        '"found_body_other": "Questo indirizzo è comparso {{times}} volte."',
    ),
    "no colon": (
        "ar", "mobile.history.hours_ago",
        "hours_ago_one «قبل ساعة», hours_ago_two «قبل ساعتين», hours_ago_other «قبل {{hours}} ساعة»",
    ),
    "mid-sentence": (
        "ar", "mobile.history.minutes_ago",
        "Use minutes_ago_one «قبل دقيقة» and minutes_ago_other «قبل {{minutes}} دقيقة»",
    ),
}

# Notes in the namespaces nothing guarded before: (locale, source key path, value).
OTHER_NAMESPACE_NOTES = {
    "landing list item says it is for the translator": (
        "ru", ("landing", "pricing", "free_items", 0),
        "Translator: keep it under 60 characters — Блокирует известные сайты-мошенники во всех приложениях",
    ),
    "landing value opens with its own key": (
        "fr", ("landing", "hero", "title_part1"),
        "title_part1 : « Une protection contre le phishing qui »",
    ),
    "landing FAQ answer names its plural variants": (
        "es", ("landing", "faq", "items", 0, "a"),
        "a_one «Se envía solo el nombre de un sitio», a_other «Se envían solo los nombres de los sitios»",
    ),
    "extension text quotes its dotted key": (
        "de", ("extension", "popup", "status_safe_title", "text"),
        '"extension.popup.status_safe_title": «Diese Seite ist sicher»',
    ),
    "extension text left with a TODO": (
        "hi", ("extension", "block_page", "title", "text"),
        "TODO: अनुवाद जाँचें — रुकें! यह धोखाधड़ी वाली साइट है",
    ),
    "email subject opens with its dotted key": (
        "es", ("email", "breach_alert", "subject", "text"),
        "email.breach_alert.subject: Tu correo apareció en una filtración de datos",
    ),
    "English email left with a FIXME": (
        "en", ("email", "welcome", "subject", "text"),
        "FIXME shorter subject — Welcome to Cleanway — you're protected now",
    ),
    "mobile in the source too": (
        "ar", ("mobile", "history", "hours_ago"),
        "hours_ago_one «قبل ساعة», hours_ago_two «قبل ساعتين», hours_ago_other «قبل {{hours}} ساعة»",
    ),
    # Two openings the PR #350 review found passing (F2).
    "email subject opens with its key in backticks": (
        "ru", ("email", "breach_alert", "subject", "text"),
        "`subject`: Ваш адрес нашёлся в утечке паролей",
    ),
    "landing value opens with its key in spaced guillemets": (
        "fr", ("landing", "hero", "title_part1"),
        "« title_part1 » : Une protection contre le phishing qui",
    ),
}

# What the TODO/FIXME and translator rules still catch after the PR #350
# review (F3) narrowed them to the shapes of a note.
NOTE_SHAPES = {
    "TODO with an owner": ("landing.hero.badge", "TODO(alex): Bloquea los sitios fraudulentos"),
    "TODO with French spacing": ("landing.hero.badge", "Bloque les sites frauduleux (TODO : vérifier)"),
    "note to the translators": ("landing.hero.badge", "Note to the translators: formal tone. Блокирует сайты-мошенники"),
    "for translators": ("extension.popup.status_safe_title", "For translators — keep the brand. Esta página es segura"),
    "translator's note": ("email.welcome.subject", "Bienvenido a Cleanway (translator's note: usted, not tú)"),
}

# Real strings from the source, plus one made-up host on an email.* subdomain
# (a scam-link product may well name one), that the heuristic must leave alone.
LEGIT = {
    "es todo": ("extension.evidence.no_https", "Todo lo que escribas en este sitio se envía sin protección y puede ser interceptado."),
    "pt todo": ("extension.options.clear_desc", "Excluir todo o histórico de verificações guardado neste dispositivo"),
    "id metodologi": ("landing.methodology.page_title", "Metodologi pengukuran"),
    "id ends with a colon": ("landing.dns.privacy_more", "Arsitektur dan metodologi lengkap:"),
    "ar number-safe plural": ("mobile.history.minutes_ago", "قبل {{minutes}} من الدقائق"),
    "it number-safe count": (
        "mobile.breach.found_body",
        "Questo indirizzo compare nelle liste di password trapelate (occorrenze: {{times}}). "
        "Se lo usi come password da qualche parte, cambia subito quella password.",
    ),
    "chrome.i18n placeholder": ("email.common.greeting_formal", "Hello $NAME$,"),
    "next-intl placeholder": ("landing.hero.badge", "In our latest benchmark, our server flagged {recall}% of fresh phishing links as dangerous"),
    "an address": ("landing.signup.email_placeholder", "you@example.com"),
    "an address in a sentence": (
        "landing.support.email_not_live_body",
        "Our support mailbox is temporarily not working, so messages to support@cleanway.ai may not reach us.",
    ),
    "a host that looks like a namespace": ("extension.webmail.finding_example", "Links go to email.mg.example.com, not to the sender's site"),
    "a word that is a key": ("landing.faq.items[0].q", "What does Cleanway learn about me?"),
    # Copy the PR #350 review found flagged (F3): "todo" is "all" in es/pt,
    # and upper-case buttons and badges are ordinary there.
    "es upper-case 'see all'": ("extension.popup.view_all", "VER TODO"),
    "es upper-case 'all included'": ("landing.pricing.badge", "TODO INCLUIDO"),
    "pt upper-case 'all' mid-sentence": ("landing.pricing.cta", "PROTEJA TODO O SEU CELULAR"),
    "translators wanted": ("landing.footer.translators", "Translators wanted: help bring Cleanway to your language"),
    "volunteer translators": ("landing.about.team", "Our volunteer translators check every language before it ships."),
}


@pytest.fixture(scope="module")
def notes():
    return _module(SCRIPTS / "i18n_notes.py")


@pytest.fixture(scope="module")
def parity():
    return _module(SCRIPTS / "check-i18n-parity.py")


@pytest.mark.parametrize("case", sorted(SHIPPED_NOTES))
def test_the_notes_that_shipped_are_notes(notes, case):
    key, value = SHIPPED_NOTES[case]
    assert notes.is_translator_note(key, value)


@pytest.mark.parametrize("case", sorted(F1_SHAPES))
def test_a_note_naming_a_variant_key_is_a_note(notes, case):
    _, key, value = F1_SHAPES[case]
    assert notes.is_translator_note(key, value)


@pytest.mark.parametrize("case", sorted(OTHER_NAMESPACE_NOTES))
def test_notes_in_other_namespaces_are_notes(notes, case):
    _, keys, value = OTHER_NAMESPACE_NOTES[case]
    assert notes.is_translator_note(_dotted(keys), value)


@pytest.mark.parametrize("case", sorted(NOTE_SHAPES))
def test_marker_and_translator_shapes_are_notes(notes, case):
    key, value = NOTE_SHAPES[case]
    assert notes.is_translator_note(key, value)


@pytest.mark.parametrize("case", sorted(LEGIT))
def test_legit_strings_are_not_notes(notes, case):
    key, value = LEGIT[case]
    assert not notes.is_translator_note(key, value)


def test_only_chrome_i18n_leaves_render_their_text_alone(parity):
    # extension.* goes to chrome.i18n and email.* to the email templates'
    # t(), both of which render a {text} leaf's `text` only. landing.* is
    # handed to next-intl whole and mobile.* is plain strings, so there a
    # "text" key is one more string beside its siblings (PR #350 review, F1).
    source = {
        "extension": {
            "meta": {"description": {"text": "Short", "description": "Store note"}},
            "popup": {"x": {"text": "A", "description": "note", "placeholders": {"d": {"content": "$1"}}, "hint": "B"}},
        },
        "email": {"common": {"y": {"text": "C", "description": "note"}}},
        "landing": {"card": {"title": "T", "text": "Body"}},
        "mobile": {"tip": {"text": "M", "hint": "H"}},
    }
    assert dict(parity.source_strings(source)) == {
        "extension.meta.description": "Short",
        "extension.popup.x": "A",
        "extension.popup.x.placeholders.d.content": "$1",
        "extension.popup.x.hint": "B",
        "email.common.y": "C",
        "landing.card.title": "T",
        "landing.card.text": "Body",
        "mobile.tip.text": "M",
        "mobile.tip.hint": "H",
    }


@pytest.mark.parametrize("locale", LOCALES)
def test_no_string_of_today_is_flagged(notes, parity, locale):
    source = json.loads((SOURCE_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    strings = list(parity.source_strings(source))
    # Every surface's strings are in the walk: a {text} leaf as its text,
    # landing lists item by item.
    assert {key.split(".", 1)[0] for key, _ in strings} == set(source)
    assert any("[" in key for key, _ in strings)
    flagged = [key for key, text in strings if notes.is_translator_note(key, text)]
    assert not flagged, f"[{locale}] {flagged}"


def test_the_real_files_pass_both_checks():
    for script in ("check-i18n-parity.py", "check-mobile-i18n.py"):
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / script)], capture_output=True, text=True, timeout=120,
        )
        assert result.returncode == 0, f"{script}: {result.stdout}{result.stderr}"


PARITY_DATA = ("landing/messages", "packages/i18n-strings/src")


def test_parity_baseline_passes(tmp_path):
    result = _run(tmp_path, "check-i18n-parity.py", PARITY_DATA, {})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", sorted(OTHER_NAMESPACE_NOTES))
def test_parity_check_fails_on_a_note_in_any_namespace(tmp_path, case):
    locale, keys, value = OTHER_NAMESPACE_NOTES[case]
    result = _run(tmp_path, "check-i18n-parity.py", PARITY_DATA, {(_src(locale), keys): value})
    output = result.stdout + result.stderr
    assert result.returncode == 1, f"{case} passed: {output}"
    assert "translator note" in output
    assert f"{locale}: {_dotted(keys)}" in output, output


def test_parity_check_leaves_the_translators_description_alone(tmp_path):
    # en extension.meta.name.description ships to the Chrome Web Store
    # dashboard as chrome.i18n's note for translators; it is never rendered.
    keys = ("extension", "meta", "name", "description")
    note = "Translator: keep it under 45 characters (the store's limit); no plural forms needed"
    result = _run(tmp_path, "check-i18n-parity.py", PARITY_DATA, {(_src("en"), keys): note})
    assert result.returncode == 0, result.stdout + result.stderr


NOTES_BESIDE_TEXT = {
    "landing": (
        "fr", ("landing", "hero", "title_part1"),
        {"title": "Translator: keep it short", "text": "Une protection contre le phishing qui"},
        "landing.hero.title_part1.title",
    ),
    "extension": (
        "de", ("extension", "popup", "status_safe_title"),
        {"text": "Diese Seite ist sicher", "hint": "Translator: keep it short"},
        "extension.popup.status_safe_title.hint",
    ),
}


@pytest.mark.parametrize("case", sorted(NOTES_BESIDE_TEXT))
def test_parity_check_fails_on_a_note_beside_a_text_key(tmp_path, case):
    locale, keys, value, flagged = NOTES_BESIDE_TEXT[case]
    result = _run(tmp_path, "check-i18n-parity.py", PARITY_DATA, {(_src(locale), keys): value})
    output = result.stdout + result.stderr
    assert result.returncode == 1, f"{case} passed: {output}"
    assert f"{locale}: {flagged}" in output, output


def test_the_pre_commit_hook_runs_on_a_source_edit():
    # The parity check reads packages/i18n-strings/src since PR #350; a note
    # put in an extension.* or email.* key changes no landing/messages file.
    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    hook = config.split("- id: i18n-parity", 1)[1].split("- id:", 1)[0]
    files = re.compile(re.search(r"^\s*files:\s*['\"]?(.+?)['\"]?\s*$", hook, re.MULTILINE).group(1))
    for path in ("landing/messages/ru.json", "packages/i18n-strings/src/ar.json"):
        assert files.search(path), f"{files.pattern} skips {path}"


def test_mobile_baseline_passes(tmp_path):
    result = _run(tmp_path, "check-mobile-i18n.py", ("mobile/i18n",), {})
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("case", sorted(F1_SHAPES))
def test_mobile_check_fails_on_a_note_naming_a_variant_key(tmp_path, case):
    locale, key, value = F1_SHAPES[case]
    result = _run(tmp_path, "check-mobile-i18n.py", ("mobile/i18n",), {(f"mobile/i18n/{locale}.json", (key,)): value})
    assert result.returncode == 1, f"{case} passed: {result.stdout}"
    assert "translator note" in result.stdout
    assert key in result.stdout
