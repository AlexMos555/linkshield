"""Consent texts (plan A.9): the confirmation screen is versioned in the repo.

`api/billing/consent_texts/<locale>/<version>.md` is what the app shows before
the SMS code. Its sha256 goes into every `consents` row, so a dispute can be
answered with the exact text and price the person saw. The app sends the
version it showed; the server accepts only the current one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

CONSENT_TEXTS_DIR = Path(__file__).parent / "consent_texts"


@dataclass(frozen=True)
class ConsentDoc:
    version: str     # "ru/v1"
    sha256: str
    text: str


class UnknownConsentVersion(ValueError):
    """The app showed a text this server does not have (or a stale one)."""


def _parse_version(version: str) -> Optional[Path]:
    parts = version.split("/")
    if len(parts) != 2 or not all(p.isalnum() for p in parts):
        return None
    return CONSENT_TEXTS_DIR / parts[0] / f"{parts[1]}.md"


@lru_cache(maxsize=32)
def load_consent_doc(version: str) -> ConsentDoc:
    path = _parse_version(version)
    if path is None or not path.is_file():
        raise UnknownConsentVersion(version)
    text = path.read_text(encoding="utf-8")
    return ConsentDoc(version=version, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(), text=text)


def require_current(version: str, current: str) -> ConsentDoc:
    """The doc for `version`, only if it is the version this server currently shows."""
    if version != current:
        raise UnknownConsentVersion(version)
    return load_consent_doc(version)
