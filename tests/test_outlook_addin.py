"""The Outlook add-in says what it sends, sends no more, and can reach the API.

The 2026-10-22 sweep found the add-in's manifest promising on-device
analysis while the task pane posts the email's sender, subject and body to
the API; both "Report phishing" paths storing the full sender address and
subject in feedback_reports (kept forever); and the manifest naming
addin.cleanway.ai, a host with no DNS record that the API also refused.
Pinned here:

  - the manifest's descriptions say the email goes to our server, and fit
    the manifest's 250-character limit;
  - every manifest URL is https on cleanway.ai/outlook/ — the copy the
    landing already serves (scripts/sync-addin.cjs) — and names a file that
    the add-in folder really contains;
  - a report sends the sender's domain and nothing else of the email;
  - the API's default CORS list lets that origin in;
  - the privacy policy gives a legal basis for both buttons, in every
    language, and the docs point at the policy sections that describe them.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADDIN = ROOT / "email-plugin-outlook"
MANIFEST = ADDIN / "manifest.xml"
# The site itself: /outlook/* has its own CSP (landing/next.config.ts), and the
# origin is already allowed by CORS. A separate host needed a DNS record, a
# Vercel alias and a Railway setting before the add-in could load at all.
ADDIN_ORIGIN = "https://cleanway.ai"
SOURCE_DIR = ROOT / "packages" / "i18n-strings" / "src"
LOCALES = ("en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar")
NS = {
    "o": "http://schemas.microsoft.com/office/appforoffice/1.1",
    "bt": "http://schemas.microsoft.com/office/officeappbasictypes/1.0",
}


def _manifest() -> ET.Element:
    return ET.parse(MANIFEST).getroot()


def test_manifest_description_says_the_email_goes_to_the_server() -> None:
    description = _manifest().find("o:Description", NS).get("DefaultValue")
    assert len(description) <= 250
    assert "on your device" not in description.lower()
    assert "server" in description.lower()
    assert "not stored" in description.lower()


def test_manifest_button_texts_say_what_each_sends() -> None:
    strings = {
        s.get("id"): s.get("DefaultValue")
        for s in _manifest().iter("{http://schemas.microsoft.com/office/officeappbasictypes/1.0}String")
    }
    assert "server" in strings["scanBtnDesc"].lower()
    assert "domain" in strings["reportBtnDesc"].lower()
    # A report alone never warns or blocks anything (api/services/own_sources.py).
    assert "warned" not in strings["reportBtnDesc"].lower()
    for value in strings.values():
        assert len(value) <= 250


def test_every_manifest_url_is_a_file_on_the_addin_host() -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    urls = re.findall(r'DefaultValue="(https?://[^"]+)"', text)
    hosted = [u for u in urls if "/outlook/" in u]
    assert len(hosted) >= 7
    for url in hosted:
        assert url.startswith(f"{ADDIN_ORIGIN}/outlook/"), url
        assert (ADDIN / url.split("/outlook/", 1)[1]).is_file(), url
    # Including <AppDomain>, which takes no DefaultValue.
    assert "addin.cleanway.ai" not in text


def _report_payloads(source: str) -> list[str]:
    """The object literal sent to /api/v1/feedback/report, as source text."""
    inline = re.findall(r"feedback/report[\s\S]{0,600}?body:\s*JSON\.stringify\((\{[\s\S]*?\})\)", source)
    named = re.findall(r"const payload = (\{[\s\S]*?\});", source)
    return inline + named


def test_reports_send_the_sender_domain_and_nothing_else() -> None:
    for name in ("commands/commands.js", "taskpane/taskpane.js"):
        source = (ADDIN / name).read_text(encoding="utf-8")
        payloads = _report_payloads(source)
        assert payloads, f"{name}: no report payload found"
        for payload in payloads:
            assert "domain" in payload, name
            for field in ("subject", "sender=", "from_address", "senderEmail", "body"):
                assert field not in payload, f"{name}: report carries {field}"


def test_api_lets_the_addin_origin_in_by_default() -> None:
    from api.config import Settings

    origins = Settings.model_fields["allowed_origins"].default.split(",")
    assert ADDIN_ORIGIN in [o.strip() for o in origins]


def _policy(locale: str) -> dict:
    source = json.loads((SOURCE_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    return source["landing"]["privacy_policy"]


def test_policy_gives_both_buttons_a_legal_basis_in_every_language() -> None:
    # Section 8 says what "Scan email" and "Report phishing" send; the legal
    # bases (GDPR Art. 13) must cover them too, not only the webmail scan.
    for locale in LOCALES:
        bases = next(s for s in _policy(locale)["sections"] if s.get("id") == "legal_bases")
        text = " ".join(bases["items"])
        assert "Outlook" in text, locale
        assert "Scan email" in text and "Report phishing" in text, locale


def test_docs_name_the_policy_sections_that_describe_the_addin() -> None:
    numbers = {}
    for section in _policy("en")["sections"]:
        number, _, name = section["title"].partition(". ")
        numbers[name] = int(number)
    browser, retention = numbers["The browser extension"], numbers["How long we keep data"]
    runbook = (ROOT / "docs" / "runbooks" / "outlook-addin-hosting.md").read_text(encoding="utf-8")
    assert f"sections {browser} and {retention}" in runbook


def test_readme_links_a_doc_that_exists() -> None:
    readme = (ADDIN / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((\.\./docs/[^)]+)\)", readme):
        assert (ADDIN / target).resolve().is_file(), target
