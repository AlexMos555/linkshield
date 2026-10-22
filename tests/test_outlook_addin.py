"""The Outlook add-in says what it sends, sends no more, and can reach the API.

The 2026-10-22 sweep found the add-in's manifest promising on-device
analysis while the task pane posts the email's sender, subject and body to
the API; both "Report phishing" paths storing the full sender address and
subject in feedback_reports (kept forever); and the API refusing the
add-in's origin. Pinned here:

  - the manifest's descriptions say the email goes to our server, and fit
    the manifest's 250-character limit;
  - every manifest URL is https on the add-in host and names a file that
    the add-in folder really contains;
  - a report sends the sender's domain and nothing else of the email;
  - the API's default CORS list lets the add-in host in.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADDIN = ROOT / "email-plugin-outlook"
MANIFEST = ADDIN / "manifest.xml"
ADDIN_ORIGIN = "https://addin.cleanway.ai"
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
    urls = re.findall(r'DefaultValue="(https?://[^"]+)"', MANIFEST.read_text(encoding="utf-8"))
    hosted = [u for u in urls if "/outlook/" in u]
    assert len(hosted) >= 7
    for url in hosted:
        assert url.startswith(f"{ADDIN_ORIGIN}/outlook/"), url
        assert (ADDIN / url.split("/outlook/", 1)[1]).is_file(), url


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


def test_readme_links_a_doc_that_exists() -> None:
    readme = (ADDIN / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\((\.\./docs/[^)]+)\)", readme):
        assert (ADDIN / target).resolve().is_file(), target
