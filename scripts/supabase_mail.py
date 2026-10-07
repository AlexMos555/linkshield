#!/usr/bin/env python3
"""Wire Supabase Auth mail for Cleanway: SMTP provider, Russian templates, DNS.

Entry point: ``bash scripts/wire-supabase-smtp.sh`` (same flags, finds python3).
Founder checklist: docs/EMAIL_SIGNIN.md.

Sign-in by email code is dead until Supabase stops using its built-in mailer
(2 messages per hour, project members only). This script is everything that
can be prepared without the founder's mail-provider account:

  --step smtp       point Supabase Auth at the provider (PATCH smtp_* fields,
                    6-digit codes, 1-hour expiry, sane rate limits)
  --step templates  apply docs/email-templates/ (grandma-plain Russian,
                    code first) to mailer_subjects_* / mailer_templates_*
  --step dns        print the DNS records the provider needs for cleanway.ai
                    (and MX for support@ when the same provider hosts it);
                    --check-dns looks them up over DNS-over-HTTPS
  --step verify     read the live config back and say whether sign-in can scale
  --step all        smtp + templates + verify (default)

Dry-run by DEFAULT: nothing is written until ``--apply`` is given. Every write
is a diff against the live config, so running it twice is a no-op. Secrets
(SMTP_PASS, the access token, the captcha secret) never appear in output; the
password travels only inside the HTTPS request body, never on a command line.

Inputs come from the environment or the repo-root ``.env`` (git-ignored):

  SUPABASE_ACCESS_TOKEN   Management API token (sbp_...)
  SUPABASE_PROJECT_REF    defaults to the production project
  SMTP_PROVIDER           yandex | resend | custom   (or --provider)
  SMTP_HOST / SMTP_PORT   custom only; presets fill them for yandex/resend
  SMTP_USER               yandex: defaults to SMTP_SENDER (login = mailbox)
                          resend: defaults to the literal "resend"
  SMTP_PASS               yandex: app password; resend: API key (re_...)
  SMTP_SENDER             From address, default no-reply@cleanway.ai
  SMTP_SENDER_NAME        default "Cleanway"
  SMTP_RATE_LIMIT         emails per hour Supabase may send, default 200
  SMTP_MIN_INTERVAL       seconds between emails to one address, default 60

Why Яндекс 360 для бизнеса is the first preset: the mail (addresses of
Russian users) stays on servers in Russia, which is what 152-ФЗ asks of a
product sold to T2 subscribers; Resend stays as the second preset because
the backend already sends through it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "docs" / "email-templates"
ENV_FILE = ROOT / ".env"

MANAGEMENT_API = "https://api.supabase.com/v1/projects/{ref}/config/auth"
DOH_ENDPOINT = "https://dns.google/resolve"
HTTP_TIMEOUT_S = 30

DEFAULT_PROJECT_REF = "bpyqgzzclsbfvxthyfsf"
DEFAULT_DOMAIN = "cleanway.ai"
DEFAULT_SENDER_LOCAL = "no-reply"
DEFAULT_SENDER_NAME = "Cleanway"
DEFAULT_RATE_LIMIT_PER_HOUR = 200
DEFAULT_MIN_INTERVAL_S = 60
DEFAULT_RESEND_REGION = "us-east-1"

# The templates promise «Код действует 1 час» and the app accepts exactly six
# digits (mobile/src/services/auth.ts OTP_CODE_LEN). Both are pinned here so
# the copy and the config cannot drift apart again (2026-09-13: Supabase sent
# 8-digit codes into a 6-digit field).
OTP_LENGTH = 6
OTP_EXPIRY_S = 3600

# Supabase template types we ship. invite / reauthentication / *_notification
# are never sent by Cleanway and keep Supabase's defaults.
TEMPLATE_TYPES = ("magic_link", "confirmation", "recovery", "email_change")
# Code-first templates: the person types the code, no link is needed. The
# other two keep {{ .ConfirmationURL }} because nothing in the app or on the
# site accepts a code for them.
CODE_TEMPLATES = frozenset({"magic_link", "confirmation"})
LINK_TEMPLATES = frozenset({"recovery", "email_change"})
TOKEN_VAR = "{{ .Token }}"
URL_VAR = "{{ .ConfirmationURL }}"

# Keys of the auth config that must never be printed.
SECRET_KEYS = frozenset({"smtp_pass", "security_captcha_secret"})

ENV_KEYS = (
    "SUPABASE_ACCESS_TOKEN",
    "SUPABASE_PROJECT_REF",
    "SMTP_PROVIDER",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "SMTP_SENDER",
    "SMTP_SENDER_NAME",
    "SMTP_RATE_LIMIT",
    "SMTP_MIN_INTERVAL",
    "RESEND_API_KEY",
)

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ConfigError(Exception):
    """A problem the founder has to fix in .env or the flags (exit 1)."""


class ApiError(Exception):
    """The Management API or DoH refused or failed (exit 2)."""


# ─── Providers ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Preset:
    key: str
    label: str
    host: str | None
    port: str | None
    fixed_user: str | None
    """Login the provider dictates (Resend: the literal "resend")."""
    user_is_sender: bool
    """Yandex: the login IS the mailbox the mail is sent from."""
    password_hint: str


PRESETS: Mapping[str, Preset] = {
    "yandex": Preset(
        key="yandex",
        label="Яндекс 360 для бизнеса",
        host="smtp.yandex.ru",
        port="465",
        fixed_user=None,
        user_is_sender=True,
        password_hint="пароль приложения (id.yandex.ru → Безопасность → Пароли приложений → Почта)",
    ),
    "resend": Preset(
        key="resend",
        label="Resend",
        host="smtp.resend.com",
        port="465",
        fixed_user="resend",
        user_is_sender=False,
        password_hint="API key (resend.com → API Keys, re_...)",
    ),
    "custom": Preset(
        key="custom",
        label="custom SMTP",
        host=None,
        port=None,
        fixed_user=None,
        user_is_sender=False,
        password_hint="SMTP password",
    ),
}


@dataclass(frozen=True)
class SmtpSettings:
    provider: str
    host: str
    port: str
    user: str
    password: str
    sender: str
    sender_name: str
    rate_limit_per_hour: int
    min_interval_s: int

    @property
    def domain(self) -> str:
        return self.sender.rsplit("@", 1)[1].lower()


def _env(env: Mapping[str, str], key: str) -> str:
    return (env.get(key) or "").strip()


def _int_env(env: Mapping[str, str], key: str, default: int, minimum: int) -> int:
    raw = _env(env, key)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} must be a whole number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{key} must be >= {minimum}, got {value}")
    return value


def resolve_smtp(provider: str, env: Mapping[str, str]) -> SmtpSettings:
    """Merge a preset with the environment into one validated settings object.

    The environment always wins over the preset, so an unusual Yandex setup
    (587 + STARTTLS, a dedicated SMTP login) is a .env change, not a code
    change. Raises ConfigError with a sentence the founder can act on.
    """
    if provider not in PRESETS:
        raise ConfigError(f"unknown provider {provider!r}; use one of {', '.join(PRESETS)}")
    preset = PRESETS[provider]

    sender = _env(env, "SMTP_SENDER") or f"{DEFAULT_SENDER_LOCAL}@{DEFAULT_DOMAIN}"
    if not EMAIL_RE.match(sender):
        raise ConfigError(f"SMTP_SENDER must be an email address, got {sender!r}")

    host = _env(env, "SMTP_HOST") or (preset.host or "")
    port = _env(env, "SMTP_PORT") or (preset.port or "")
    if not host or not port:
        raise ConfigError("SMTP_HOST and SMTP_PORT are required for --provider custom")
    if not port.isdigit():
        raise ConfigError(f"SMTP_PORT must be a number, got {port!r}")

    user = _env(env, "SMTP_USER")
    if not user:
        if preset.fixed_user:
            user = preset.fixed_user
        elif preset.user_is_sender:
            user = sender
    if not user:
        raise ConfigError("SMTP_USER is required for --provider custom")

    password = _env(env, "SMTP_PASS")
    if not password and provider == "resend":
        # The old script took the key under this name; keep it working.
        password = _env(env, "RESEND_API_KEY")
    if not password:
        raise ConfigError(f"SMTP_PASS is empty — {preset.label} needs the {preset.password_hint}")

    return SmtpSettings(
        provider=provider,
        host=host,
        port=port,
        user=user,
        password=password,
        sender=sender,
        sender_name=_env(env, "SMTP_SENDER_NAME") or DEFAULT_SENDER_NAME,
        rate_limit_per_hour=_int_env(env, "SMTP_RATE_LIMIT", DEFAULT_RATE_LIMIT_PER_HOUR, 1),
        min_interval_s=_int_env(env, "SMTP_MIN_INTERVAL", DEFAULT_MIN_INTERVAL_S, 0),
    )


def smtp_warnings(settings: SmtpSettings) -> list[str]:
    """Things that will not stop the PATCH but will stop the mail."""
    out: list[str] = []
    if settings.provider == "yandex" and settings.user.lower() != settings.sender.lower():
        out.append(
            "Яндекс отклоняет письма, у которых From не совпадает с ящиком логина "
            f"(или его алиасом): логин {settings.user}, отправитель {settings.sender}."
        )
    if settings.domain != DEFAULT_DOMAIN:
        out.append(f"sender is on {settings.domain}, not {DEFAULT_DOMAIN} — DNS records below are for the sender's domain")
    if settings.min_interval_s > 62:
        out.append(
            f"SMTP_MIN_INTERVAL={settings.min_interval_s}s is longer than the app's resend cooldown (62 s): "
            "«Отправить ещё раз» would hit 429 the moment it re-enables"
        )
    return out


# ─── Auth config: SMTP ────────────────────────────────────────────

# Everything the smtp step sets, in the shape the Management API takes.
# smtp_port is a STRING in UpdateAuthConfigBody (verified against the OpenAPI
# document); sending an integer is rejected.
def smtp_desired_config(settings: SmtpSettings) -> dict[str, object]:
    return {
        "external_email_enabled": True,
        "smtp_host": settings.host,
        "smtp_port": settings.port,
        "smtp_user": settings.user,
        "smtp_pass": settings.password,
        "smtp_admin_email": settings.sender,
        "smtp_sender_name": settings.sender_name,
        "smtp_max_frequency": settings.min_interval_s,
        "rate_limit_email_sent": settings.rate_limit_per_hour,
        "mailer_otp_length": OTP_LENGTH,
        "mailer_otp_exp": OTP_EXPIRY_S,
    }


def _same(current: object, desired: object) -> bool:
    if isinstance(desired, bool) or isinstance(current, bool):
        return bool(current) == bool(desired)
    return str(current if current is not None else "") == str(desired)


def config_changes(
    current: Mapping[str, object],
    desired: Mapping[str, object],
    *,
    force: bool = False,
) -> dict[str, object]:
    """Fields that differ between the live config and what we want.

    Secrets are compared only by presence, never by value: the API may echo
    a stored password back, but a diff on it would print nothing useful and
    risk logging it. Whenever anything else changes (or --force), the secret
    is sent again so the host and its password always land together.
    """
    changed: dict[str, object] = {}
    for key, value in desired.items():
        if key in SECRET_KEYS:
            continue
        if not _same(current.get(key), value):
            changed[key] = value
    secrets = {k: v for k, v in desired.items() if k in SECRET_KEYS}
    if secrets and (changed or force or not current.get("smtp_host")):
        changed.update(secrets)
    return changed


def redact(config: Mapping[str, object]) -> dict[str, object]:
    """A copy safe to print: secrets replaced by whether they are set."""
    out: dict[str, object] = {}
    for key, value in config.items():
        if key in SECRET_KEYS:
            out[key] = "(set)" if value else "(empty)"
        else:
            out[key] = value
    return out


# ─── Auth config: templates ───────────────────────────────────────


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"template file missing: {path}") from exc


def validate_template(kind: str, subject: str, html: str) -> list[str]:
    """Rules that keep the mail usable by the people it is written for."""
    problems: list[str] = []
    if not subject.strip():
        problems.append(f"{kind}: empty subject")
    if "\n" in subject.strip():
        problems.append(f"{kind}: subject must be one line")
    if kind in CODE_TEMPLATES:
        if TOKEN_VAR not in html:
            problems.append(f"{kind}: must show the code ({TOKEN_VAR})")
        if URL_VAR in html:
            problems.append(f"{kind}: a code suffices here — no {URL_VAR}")
    if kind in LINK_TEMPLATES and URL_VAR not in html:
        problems.append(f"{kind}: nothing accepts a code for this flow — needs {URL_VAR}")
    if "http://" in html:
        problems.append(f"{kind}: plain http:// link")
    if "{{ .SiteURL }}" in html and "https://" not in html:
        problems.append(f"{kind}: {{ .SiteURL }} without https")
    return problems


def load_templates(directory: Path = TEMPLATES_DIR) -> dict[str, str]:
    """docs/email-templates/<kind>.subject.txt + <kind>.html → API fields."""
    fields: dict[str, str] = {}
    problems: list[str] = []
    for kind in TEMPLATE_TYPES:
        subject = _read(directory / f"{kind}.subject.txt").strip()
        html = _read(directory / f"{kind}.html")
        problems.extend(validate_template(kind, subject, html))
        fields[f"mailer_subjects_{kind}"] = subject
        fields[f"mailer_templates_{kind}_content"] = html
    if problems:
        raise ConfigError("email templates rejected:\n  - " + "\n  - ".join(problems))
    return fields


# ─── DNS ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DnsRecord:
    name: str
    rtype: str
    value: str
    why: str
    priority: int | None = None
    required: bool = True
    """False = only when the founder also wants support@ on this provider."""
    match: str | None = None
    """Stable substring a live answer must contain; defaults to the value
    up to its first <placeholder>."""

    @property
    def needle(self) -> str:
        if self.match:
            return self.match.lower()
        return self.value.split("<", 1)[0].strip().rstrip(".").lower()


def dns_records(
    provider: str,
    domain: str = DEFAULT_DOMAIN,
    *,
    with_mx: bool = False,
    resend_region: str = DEFAULT_RESEND_REGION,
) -> list[DnsRecord]:
    """What to add at the registrar. Values that only the provider's panel
    knows (DKIM key, verification code) are left as <...> placeholders.

    Current live state (checked 2026-10-04): apex TXT ``v=spf1 -all``, no MX,
    no DKIM, ``_dmarc`` = ``v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s``.
    With p=reject every record below must be right before the first code.
    """
    if provider == "yandex":
        records = [
            DnsRecord(
                domain, "TXT", "yandex-verification: <код из admin.yandex.ru → Домены>",
                "подтверждение владения доменом (один раз)", match="yandex-verification:",
            ),
            DnsRecord(
                domain, "TXT", "v=spf1 include:_spf.yandex.net -all",
                "SPF: ЗАМЕНИТЬ существующую запись «v=spf1 -all» (вторую SPF добавлять нельзя)",
                match="include:_spf.yandex.net",
            ),
            DnsRecord(
                f"mail._domainkey.{domain}", "TXT", "v=DKIM1; k=rsa; p=<ключ из admin.yandex.ru → Домены → DKIM>",
                "DKIM-подпись; при p=reject без неё письма отбрасываются", match="p=",
            ),
            DnsRecord(
                domain, "MX", "mx.yandex.net.", "приём почты (support@, ответы на no-reply@)",
                priority=10, required=with_mx, match="mx.yandex.net",
            ),
        ]
    elif provider == "resend":
        records = [
            DnsRecord(
                f"resend._domainkey.{domain}", "TXT", "p=<из resend.com → Domains → Records>",
                "DKIM; the only record DMARC alignment rests on (aspf=s rejects the send. subdomain)", match="p=",
            ),
            DnsRecord(
                f"send.{domain}", "MX", f"feedback-smtp.{resend_region}.amazonses.com", "bounce handling (Return-Path)",
                priority=10, match="amazonses.com",
            ),
            DnsRecord(
                f"send.{domain}", "TXT", "v=spf1 include:amazonses.com ~all",
                "SPF for the Return-Path subdomain; the apex «v=spf1 -all» stays as it is", match="include:amazonses.com",
            ),
        ]
        if with_mx:
            records.append(DnsRecord(
                domain, "MX", "<MX of a mailbox provider — Resend does not host inboxes>",
                "support@ needs a mailbox (Яндекс 360 / Zoho); Resend only sends",
                priority=10, required=False,
            ))
    else:
        records = [
            DnsRecord(domain, "TXT", "v=spf1 include:<provider SPF> -all", "SPF for the apex sender", match="v=spf1 include:"),
            DnsRecord(f"<selector>._domainkey.{domain}", "TXT", "v=DKIM1; k=rsa; p=<key>", "DKIM", match="p="),
        ]
    records.append(DnsRecord(
        f"_dmarc.{domain}", "TXT", "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@" + domain,
        "already present without rua; add rua once a mailbox can receive the reports",
        required=False, match="v=dmarc1",
    ))
    return records


Resolver = Callable[[str, str], Sequence[str]]


def doh_lookup(name: str, rtype: str) -> list[str]:
    """TXT/MX answers over DNS-over-HTTPS; works where port 53 is filtered."""
    url = f"{DOH_ENDPOINT}?name={urllib.request.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, ValueError) as exc:
        raise ApiError(f"DNS lookup failed for {name} {rtype}: {exc}") from exc
    return [str(a.get("data", "")).strip('"') for a in data.get("Answer", [])]


def check_dns(records: Sequence[DnsRecord], resolve: Resolver = doh_lookup) -> list[tuple[DnsRecord, bool]]:
    """Which of the records are visible on the public DNS right now.

    Placeholders (<...>) are matched on the stable prefix only: a DKIM TXT that
    starts with ``v=DKIM1`` or ``p=`` counts, whatever key it carries.
    """
    results: list[tuple[DnsRecord, bool]] = []
    for record in records:
        # Long TXT values come back as '"part1" "part2"'; MX as '10 host.'.
        answers = [a.replace('" "', "").replace('"', "").lower() for a in resolve(record.name, record.rtype)]
        needle = record.needle
        found = any(needle in a for a in answers) if needle else bool(answers)
        results.append((record, found))
    return results


# ─── Environment ──────────────────────────────────────────────────


def read_env_file(path: Path = ENV_FILE) -> dict[str, str]:
    """Minimal KEY=VALUE reader for the git-ignored .env (no printing, ever)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def merged_env(process_env: Mapping[str, str], file_env: Mapping[str, str]) -> dict[str, str]:
    """Process environment wins over .env, as every dotenv tool does."""
    out = {k: file_env[k] for k in ENV_KEYS if file_env.get(k)}
    out.update({k: process_env[k] for k in ENV_KEYS if process_env.get(k)})
    return out


# ─── Management API ───────────────────────────────────────────────


class ManagementApi:
    def __init__(self, token: str, project_ref: str) -> None:
        if not token:
            raise ConfigError("SUPABASE_ACCESS_TOKEN is missing (.env or environment)")
        self._token = token
        self._url = MANAGEMENT_API.format(ref=project_ref)

    def _request(self, method: str, body: Mapping[str, object] | None) -> dict[str, object]:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self._url,
            data=payload,
            method=method,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode("utf-8", "replace")
            raise ApiError(f"{method} auth config → HTTP {exc.code}: {_scrub(detail, body)}") from exc
        except (urllib.error.URLError, ValueError) as exc:
            raise ApiError(f"{method} auth config failed: {exc}") from exc

    def get(self) -> dict[str, object]:
        return self._request("GET", None)

    def patch(self, body: Mapping[str, object]) -> dict[str, object]:
        return self._request("PATCH", body)


def _scrub(text: str, body: Mapping[str, object] | None) -> str:
    """An error body must never carry our secret back to the terminal."""
    if not body:
        return text
    for key in SECRET_KEYS:
        value = body.get(key)
        if isinstance(value, str) and value:
            text = text.replace(value, "(secret)")
    return text


# ─── Steps ────────────────────────────────────────────────────────


def _print_changes(title: str, changes: Mapping[str, object]) -> None:
    print(f"→ {title}")
    if not changes:
        print("  nothing to change — already applied")
        return
    for key, value in redact(changes).items():
        shown = value if not isinstance(value, str) or len(value) <= 70 else f"{value[:67]}… ({len(value)} chars)"
        print(f"  {key}: {shown!s}")


def step_smtp(api: ManagementApi | None, settings: SmtpSettings, current: Mapping[str, object], *, apply: bool, force: bool) -> int:
    desired = smtp_desired_config(settings)
    changes = config_changes(current, desired, force=force)
    print(f"→ provider: {PRESETS[settings.provider].label} ({settings.host}:{settings.port}, login {settings.user}, from «{settings.sender_name}» <{settings.sender}>)")
    for warning in smtp_warnings(settings):
        print(f"  ! {warning}")
    _print_changes("SMTP / OTP config diff", changes)
    if not changes:
        return 0
    if not apply or api is None:
        print("  dry run — re-run with --apply to write")
        return 0
    api.patch(changes)
    print("  applied")
    return 0


def step_templates(api: ManagementApi | None, current: Mapping[str, object], *, apply: bool, force: bool) -> int:
    desired = load_templates()
    changes = config_changes(current, desired, force=force)
    _print_changes(f"email templates diff ({', '.join(TEMPLATE_TYPES)})", changes)
    if not changes:
        return 0
    if not apply or api is None:
        print("  dry run — re-run with --apply to write")
        return 0
    api.patch(changes)
    print("  applied")
    return 0


def step_dns(provider: str, domain: str, *, with_mx: bool, resend_region: str, check: bool) -> int:
    records = dns_records(provider, domain, with_mx=with_mx, resend_region=resend_region)
    print(f"→ DNS records for {domain} ({PRESETS[provider].label}); add at the registrar (Squarespace Domains → DNS):")
    for r in records:
        prio = f" {r.priority}" if r.priority is not None else ""
        tag = "" if r.required else " [optional]"
        print(f"  {r.rtype:<4} {r.name:<32}{prio} {r.value}{tag}")
        print(f"       — {r.why}")
    if not check:
        return 0
    print("→ live DNS check (dns.google):")
    missing = 0
    for record, found in check_dns(records):
        mark = "ok  " if found else ("miss" if record.required else "none")
        missing += int(record.required and not found)
        print(f"  {mark} {record.rtype:<4} {record.name}")
    print(f"  => {'all required records visible' if not missing else f'{missing} required record(s) not visible yet'}")
    return 0 if not missing else 1


def verify_report(current: Mapping[str, object]) -> tuple[bool, list[str]]:
    """Human-readable state of the live config + one yes/no."""
    host = current.get("smtp_host") or ""
    rate = int(current.get("rate_limit_email_sent") or 0)
    otp_len = current.get("mailer_otp_length")
    otp_exp = current.get("mailer_otp_exp")
    lines = [
        f"smtp_host:        {host or '(built-in Supabase mailer — 2 emails/hour)'}",
        f"smtp_port/user:   {current.get('smtp_port') or '-'} / {current.get('smtp_user') or '-'}",
        f"sender:           {current.get('smtp_sender_name') or '-'} <{current.get('smtp_admin_email') or '-'}>",
        f"emails per hour:  {rate}",
        f"min interval:     {current.get('smtp_max_frequency')} s",
        f"otp length/exp:   {otp_len} digits / {otp_exp} s",
        f"captcha:          {'on' if current.get('security_captcha_enabled') else 'off'} ({current.get('security_captcha_provider') or '-'})",
    ]
    template_ok = all(
        TOKEN_VAR in str(current.get(f"mailer_templates_{kind}_content") or "") for kind in CODE_TEMPLATES
    )
    lines.append(f"code in templates: {'yes' if template_ok else 'NO — emails would carry no code'}")
    ok = bool(host) and rate > 2 and otp_len == OTP_LENGTH and otp_exp == OTP_EXPIRY_S and template_ok
    return ok, lines


def step_verify(current: Mapping[str, object]) -> int:
    ok, lines = verify_report(current)
    print("→ live auth config:")
    for line in lines:
        print(f"  {line}")
    print(f"  => {'SMTP wired — sign-in can scale' if ok else 'NOT ready — see the lines above'}")
    return 0 if ok else 1


# ─── CLI ──────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--provider", choices=sorted(PRESETS), help="overrides SMTP_PROVIDER (default yandex)")
    p.add_argument("--step", choices=("smtp", "templates", "dns", "verify", "all"), default="all")
    p.add_argument("--apply", action="store_true", help="write to Supabase (default is a dry run)")
    p.add_argument("--force", action="store_true", help="re-send the password even when nothing else differs")
    p.add_argument("--domain", default=None, help="sender domain for the DNS step (default: SMTP_SENDER's domain)")
    p.add_argument("--with-mx", action="store_true", help="include the MX record for support@ on the same provider")
    p.add_argument("--resend-region", default=DEFAULT_RESEND_REGION, help="region shown in Resend → Domains (default us-east-1)")
    p.add_argument("--check-dns", action="store_true", help="look the records up over DNS-over-HTTPS")
    p.add_argument("--env-file", type=Path, default=ENV_FILE, help=argparse.SUPPRESS)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    env = merged_env(os.environ, read_env_file(args.env_file))
    provider = args.provider or env.get("SMTP_PROVIDER") or "yandex"
    try:
        if args.step == "dns":
            domain = args.domain or (_env(env, "SMTP_SENDER").rsplit("@", 1)[-1] if "@" in _env(env, "SMTP_SENDER") else DEFAULT_DOMAIN)
            return step_dns(provider, domain, with_mx=args.with_mx, resend_region=args.resend_region, check=args.check_dns)

        needs_smtp = args.step in ("smtp", "all")
        settings = resolve_smtp(provider, env) if needs_smtp else None
        api = ManagementApi(env.get("SUPABASE_ACCESS_TOKEN", ""), env.get("SUPABASE_PROJECT_REF") or DEFAULT_PROJECT_REF)
        current = api.get()

        rc = 0
        if settings is not None:
            rc |= step_smtp(api, settings, current, apply=args.apply, force=args.force)
        if args.step in ("templates", "all"):
            rc |= step_templates(api, current, apply=args.apply, force=args.force)
        if args.step in ("verify", "all"):
            # Re-read after writes so the report shows what is live, not what we sent.
            rc |= step_verify(api.get() if args.apply else current)
            if not args.apply and args.step == "all":
                print("  (dry run: the report above is the state BEFORE this script's changes)")
        return rc
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    except ApiError as exc:
        print(f"api error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
