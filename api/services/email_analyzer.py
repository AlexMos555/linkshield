"""
Email phishing analyzer.

Analyzes an inbound email for phishing markers:
- **Sender spoofing** — visually-similar lookalike domains
  (`chasе.com` with Cyrillic "е" vs `chase.com`), display-name mismatches,
  freemail domains claiming corporate identity.
- **URL reputation** — every link extracted and scored via the same pipeline
  used by the browser extension (bloom filter + `check_safe_browsing`).
- **Body patterns** — urgency, credential-ask, money-transfer, fake-brand
  mentions. All patterns stored as data so they're auditable + localizable.
- **Authentication gaps** — SPF/DKIM/DMARC failures if the headers are
  present (pass-through; we don't re-verify cryptographically here).

The output is a structured verdict: level (safe/suspicious/dangerous),
score (0–100), list of specific reasons, and highlighted suspect spans so
the client can visually flag them.

Surface is stateless and synchronous except for external URL checks —
callers pass in a `DomainChecker` callable for testability.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Iterable, Optional

logger = logging.getLogger("cleanway.email_analyzer")


# ─── Types ────────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    dangerous = "dangerous"


@dataclass(frozen=True)
class EmailHeaders:
    """Subset of email headers we care about for phishing analysis."""

    from_address: str = ""       # e.g. "security@chase.com"
    from_display: str = ""       # e.g. "Chase Bank Security"
    reply_to: str = ""
    subject: str = ""
    return_path: str = ""
    # Full values from Authentication-Results, if the receiving MTA added them.
    # We do not re-verify — too expensive + duplicative — just propagate state.
    spf: Optional[str] = None    # "pass" / "fail" / "softfail" / None
    dkim: Optional[str] = None   # "pass" / "fail" / "none" / None
    dmarc: Optional[str] = None  # "pass" / "fail" / "none" / None


@dataclass(frozen=True)
class EmailBody:
    """Plain-text + (optional) HTML of the message body."""

    text: str = ""
    html: str = ""


@dataclass(frozen=True)
class ExtractedLink:
    url: str
    display_text: str  # The anchor text (may differ from URL — a spoofing signal)
    domain: str


@dataclass(frozen=True)
class Finding:
    """One concrete phishing indicator, contributing to the final score."""

    category: str              # e.g. "sender_spoofing", "url_reputation"
    severity: int              # 1–100 — how much it contributes to score
    message: str               # human-readable short explanation
    evidence: str = ""         # raw substring or URL that triggered this


@dataclass(frozen=True)
class AnalysisResult:
    level: RiskLevel
    score: int  # 0–100
    findings: tuple[Finding, ...]
    links: tuple[ExtractedLink, ...]

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "message": f.message,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
            "links": [
                {"url": link.url, "display_text": link.display_text, "domain": link.domain}
                for link in self.links
            ],
        }


# A callable that decides if a domain is dangerous. Injected so tests can
# stub it out and so the analyzer doesn't hard-code which detector is used.
DomainChecker = Callable[[str], Awaitable[bool]]


# ─── Known legitimate domains + brand lookalikes ──────────────────────────────

# Small curated list — not exhaustive. Intentionally conservative so we don't
# false-positive on "apple*.com" subsidiaries. Expand as product needs grow.
KNOWN_BRANDS: dict[str, tuple[str, ...]] = {
    # brand_key → canonical domain(s)
    "chase": ("chase.com",),
    "paypal": ("paypal.com",),
    "google": ("google.com", "gmail.com", "googleapis.com"),
    "apple": ("apple.com", "icloud.com"),
    "microsoft": ("microsoft.com", "outlook.com", "office.com", "live.com"),
    "amazon": ("amazon.com",),
    "netflix": ("netflix.com",),
    "meta": ("facebook.com", "instagram.com", "whatsapp.com"),
    "sberbank": ("sberbank.ru", "sber.ru"),
    "tinkoff": ("tinkoff.ru", "tbank.ru"),
    "stripe": ("stripe.com",),
    "dhl": ("dhl.com",),
    "ups": ("ups.com",),
    "fedex": ("fedex.com",),
}

# Free email domains — legitimate senders, but corporate impersonators
# often claim to be "Chase Bank Security <chasesecurity1234@gmail.com>".
FREEMAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "mail.ru",
    "yandex.ru",
    "protonmail.com",
    "icloud.com",
    "aol.com",
}


# ─── Body patterns ────────────────────────────────────────────────────────────

# Tuples of (regex, severity, message). All regex case-insensitive.
URGENCY_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\b(urgent|immediate(ly)?|right away|act now|expires? in)\b", re.I), 15, "Urgency language"),
    (re.compile(r"\b(within \d+ hours?|last chance|final notice)\b", re.I), 20, "Countdown pressure"),
    (re.compile(r"\b(срочно|немедленно|последнее предупреждение)\b", re.I), 15, "Urgency (RU)"),
]

CREDENTIAL_ASK_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\b(verify your (account|identity|password))\b", re.I), 30, "Requests credential verification"),
    (re.compile(r"\b(confirm (your )?(account|password|login|details))\b", re.I), 25, "Asks to confirm credentials"),
    (re.compile(r"\b(enter (your )?(password|pin|social security|ssn|card number))\b", re.I), 40, "Asks for credential entry"),
    (re.compile(r"\bclick (the link|here|below) to (verify|confirm|unlock|sign ?in)\b", re.I), 30, "Click-to-verify pattern"),
    (re.compile(r"\b(введите (пароль|код из sms|данные карты))\b", re.I), 40, "Credential entry (RU)"),
]

MONEY_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\b(wire transfer|send (?:us|me) (?:the )?money|bitcoin|gift card|itunes card)\b", re.I), 35, "Money-transfer request"),
    (re.compile(r"\b(inheritance|lottery winner|bank transfer fee|processing fee)\b", re.I), 40, "Advance-fee scam marker"),
    (re.compile(r"\b(перевести деньги|отправить биткоин|выигрыш в лотерею)\b", re.I), 40, "Money request (RU)"),
]

ACCOUNT_LOCK_PATTERNS: list[tuple[re.Pattern[str], int, str]] = [
    (re.compile(r"\b(your account (has been|will be|is about to be) (locked|suspended|closed|deactivated))\b", re.I), 30, "Account-lock threat"),
    (re.compile(r"\b(unusual (activity|sign[- ]?in)|suspicious login)\b", re.I), 25, "Fake security alert"),
    (re.compile(r"\b(ваш (аккаунт|счёт) (заблокирован|приостановлен))\b", re.I), 30, "Account lock (RU)"),
]

ALL_BODY_PATTERNS = (
    *URGENCY_PATTERNS,
    *CREDENTIAL_ASK_PATTERNS,
    *MONEY_PATTERNS,
    *ACCOUNT_LOCK_PATTERNS,
)


# ─── Public API ───────────────────────────────────────────────────────────────


async def analyze_email(
    headers: EmailHeaders,
    body: EmailBody,
    check_domain: Optional[DomainChecker] = None,
) -> AnalysisResult:
    """
    Main entry point. Returns an `AnalysisResult`.

    `check_domain` is optional; if provided, each extracted link's domain is
    checked against the threat pipeline and findings recorded per dangerous
    hit. If omitted, URL-reputation checks are skipped (useful for offline
    tests or when the caller plans to do bulk checking separately).
    """
    findings: list[Finding] = []

    # 1. Sender analysis
    findings.extend(_analyze_sender(headers))

    # 2. Auth header gaps
    findings.extend(_analyze_auth_headers(headers))

    # 3. Body patterns
    findings.extend(_scan_body_patterns(body))

    # 4. Extract links (used by both UI highlighting and URL reputation)
    links = tuple(_extract_links(body))

    # 5. Check each unique domain via injected checker
    if check_domain is not None:
        seen: set[str] = set()
        for link in links:
            if not link.domain or link.domain in seen:
                continue
            seen.add(link.domain)
            try:
                is_bad = await check_domain(link.domain)
            except Exception as e:
                logger.debug("email_checker_error", extra={"domain": link.domain, "error": str(e)})
                continue
            if is_bad:
                findings.append(
                    Finding(
                        category="url_reputation",
                        severity=50,
                        message=f"Known-dangerous domain: {link.domain}",
                        evidence=link.url,
                    )
                )

    # 6. Display-text vs URL mismatch (a classic phishing tell)
    findings.extend(_detect_link_text_mismatch(links))

    score = _aggregate_score(findings)
    level = _level_for_score(score)

    return AnalysisResult(
        level=level,
        score=score,
        findings=tuple(findings),
        links=links,
    )


# ─── Sender analysis ──────────────────────────────────────────────────────────


def _analyze_sender(headers: EmailHeaders) -> list[Finding]:
    out: list[Finding] = []
    addr = headers.from_address.strip().lower()
    display = headers.from_display.strip()
    if not addr or "@" not in addr:
        return out

    local, _, domain = addr.rpartition("@")

    # 1a. Non-ASCII in domain (potential homograph / IDN spoof)
    if _has_non_ascii(domain):
        out.append(
            Finding(
                category="sender_spoofing",
                severity=45,
                message="Sender domain contains non-ASCII characters — possible homograph attack",
                evidence=domain,
            )
        )

    # 1b. Brand claim in display name but sender from freemail / different TLD
    lower_display = display.lower()
    for brand, canonical in KNOWN_BRANDS.items():
        if brand in lower_display:
            if domain in FREEMAIL_DOMAINS:
                out.append(
                    Finding(
                        category="sender_spoofing",
                        severity=55,
                        message=(
                            f"Claims to be {brand!r} in display name but sends from "
                            f"free-email domain ({domain})"
                        ),
                        evidence=f"{display} <{addr}>",
                    )
                )
            elif not any(domain == c or domain.endswith("." + c) for c in canonical):
                # Brand name present but domain doesn't match canonical
                out.append(
                    Finding(
                        category="sender_spoofing",
                        severity=45,
                        message=(
                            f"Claims to be {brand!r} but sender domain doesn't match known domains"
                        ),
                        evidence=f"{display} <{addr}>",
                    )
                )
            break

    # 1c. Reply-To differs from From domain (phishing redirects replies)
    if headers.reply_to:
        reply_addr = headers.reply_to.strip().lower()
        _, _, reply_domain = reply_addr.rpartition("@")
        if reply_domain and reply_domain != domain:
            # Tolerate obvious subdomain relationships
            if not (reply_domain.endswith("." + domain) or domain.endswith("." + reply_domain)):
                out.append(
                    Finding(
                        category="sender_spoofing",
                        severity=25,
                        message="Reply-To points to a different domain than From",
                        evidence=f"From: {domain}  Reply-To: {reply_domain}",
                    )
                )

    return out


def _has_non_ascii(s: str) -> bool:
    try:
        s.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True


# ─── Authentication headers ──────────────────────────────────────────────────


def _analyze_auth_headers(headers: EmailHeaders) -> list[Finding]:
    out: list[Finding] = []
    pairs = [
        ("SPF", headers.spf),
        ("DKIM", headers.dkim),
        ("DMARC", headers.dmarc),
    ]
    for name, value in pairs:
        if value is None:
            continue
        norm = value.strip().lower()
        if norm in ("fail", "hardfail"):
            out.append(
                Finding(
                    category="auth_fail",
                    severity=30 if name == "DMARC" else 20,
                    message=f"{name} verification failed",
                    evidence=f"{name}={norm}",
                )
            )
        elif norm == "softfail" and name == "SPF":
            out.append(
                Finding(
                    category="auth_fail",
                    severity=10,
                    message="SPF softfail — sender might not be authorized",
                    evidence=f"SPF={norm}",
                )
            )
    return out


# ─── Body scanning ───────────────────────────────────────────────────────────


def _scan_body_patterns(body: EmailBody) -> list[Finding]:
    haystack = (body.text or "") + "\n" + _strip_html(body.html or "")
    if not haystack.strip():
        return []
    findings: list[Finding] = []
    for pattern, severity, message in ALL_BODY_PATTERNS:
        for match in pattern.finditer(haystack):
            findings.append(
                Finding(
                    category="body_pattern",
                    severity=severity,
                    message=message,
                    evidence=match.group(0),
                )
            )
            break  # one finding per pattern — don't double-count
    return findings


_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_RE = re.compile(r"&[#a-zA-Z0-9]+;")


def _strip_html(html: str) -> str:
    """Cheap tag stripper. We don't need perfect — enough for pattern scanning."""
    return _ENTITY_RE.sub(" ", _TAG_RE.sub(" ", html))


# ─── Link extraction ─────────────────────────────────────────────────────────


_URL_RE = re.compile(
    r"https?://[^\s<>\"'`\[\]{}|\\^]+",
    re.IGNORECASE,
)
_ANCHOR_RE = re.compile(
    r"<a\s[^>]*href\s*=\s*['\"]([^'\"]+)['\"][^>]*>(.*?)</a>",
    re.IGNORECASE | re.DOTALL,
)


def _extract_links(body: EmailBody) -> Iterable[ExtractedLink]:
    seen: set[str] = set()

    # HTML anchors (preserves display text for mismatch detection)
    for match in _ANCHOR_RE.finditer(body.html or ""):
        url = match.group(1).strip()
        display = _strip_html(match.group(2)).strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)
        yield ExtractedLink(
            url=url,
            display_text=display,
            domain=_domain_from_url(url),
        )

    # Plain-text URLs
    for source in (body.text or "", _strip_html(body.html or "")):
        for match in _URL_RE.finditer(source):
            url = match.group(0).rstrip(".,;:!?)")
            if url in seen:
                continue
            seen.add(url)
            yield ExtractedLink(
                url=url,
                display_text=url,
                domain=_domain_from_url(url),
            )


def _domain_from_url(url: str) -> str:
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    if "@" in s:  # userinfo@host
        s = s.split("@", 1)[1]
    if ":" in s:  # port
        s = s.split(":", 1)[0]
    return s.lower()


def _detect_link_text_mismatch(links: Iterable[ExtractedLink]) -> list[Finding]:
    """
    Flag anchors where the visible text looks like a different URL/domain
    than the actual href. Classic phishing pattern.

    Example: <a href="evil.test/steal">https://chase.com/login</a>
    """
    out: list[Finding] = []
    for link in links:
        text = link.display_text.strip()
        if not text or text == link.url:
            continue
        # If the display text contains a domain that differs from the actual one,
        # flag it. Use the URL extractor on the display text itself.
        text_match = _URL_RE.search(text)
        if text_match:
            text_domain = _domain_from_url(text_match.group(0))
            if text_domain and text_domain != link.domain:
                out.append(
                    Finding(
                        category="link_text_mismatch",
                        severity=50,
                        message=(
                            f"Link text shows '{text_domain}' but actually points to "
                            f"'{link.domain}'"
                        ),
                        evidence=f"text={text_domain!r} actual={link.domain!r}",
                    )
                )
    return out


# ─── Scoring ──────────────────────────────────────────────────────────────────


def _aggregate_score(findings: list[Finding]) -> int:
    """
    Caps each *category* before summing — so a single category can't push
    the score over the threshold by itself, which would be noisy.
    """
    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = min(60, by_category.get(f.category, 0) + f.severity)
    total = sum(by_category.values())
    return min(100, total)


def _level_for_score(score: int) -> RiskLevel:
    if score >= 60:
        return RiskLevel.dangerous
    if score >= 25:
        return RiskLevel.suspicious
    return RiskLevel.safe
