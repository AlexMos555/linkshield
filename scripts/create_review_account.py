#!/usr/bin/env python3
"""Create or rotate the store reviewers' sign-in account (review@cleanway.ai).

App Store, Google Play and RuStore reviewers cannot sign in with an emailed
code: the code would land in our inbox. The app shows a password field for
the addresses in EXPO_PUBLIC_REVIEW_EMAILS (mobile/src/utils/review-login.ts)
and this script gives that account its password. Runbook:
docs/runbooks/app-review-account.md. The founder runs it on his Mac; nothing
in CI or in an agent session runs it against production.

What it does, against the Supabase project in SUPABASE_URL:

  1. looks the user up by email (GoTrue admin API, GET /auth/v1/admin/users);
  2. creates it (POST, email_confirm=true) or rotates its password
     (PUT /auth/v1/admin/users/{id}: new password, email_confirm=true, a ban
     from "disable between reviews" lifted);
  3. stores the password in the macOS login Keychain — service
     "Cleanway app review account", account = the email — and prints only
     the command that copies it to the clipboard.

Every run generates a new password: re-running IS the rotation.
--dry-run looks the account up and says what it would do; nothing is written.

The password is 32 letters and digits from the `secrets` module, always with
lower case, upper case and digits — which covers the project's GoTrue rules
(password_required_characters and password_min_length in
scripts/supabase_mail.py; HIBP is on, and a random password is not in its
list). It travels only inside the HTTPS request body and on
the stdin of `security -i` — never in argv (visible in `ps`), stdout, stderr
or an error message.

Inputs, from the environment or the repo-root .env (git-ignored) — the names
the backend reads (api/config.py, api/services/supabase_keys.py):

  SUPABASE_URL            https://<ref>.supabase.co
  SUPABASE_SECRET_KEY     sb_secret_… (preferred)
  SUPABASE_SERVICE_KEY    the legacy service_role JWT (fallback)

Run:  python3 scripts/create_review_account.py [--dry-run] [--email ADDRESS]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import string
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from api.services import supabase_keys  # noqa: E402  (key kinds + headers, as the backend sends them)
from supabase_mail import HARDENED_EXPECTED, read_env_file  # noqa: E402  (the live password rules)

ENV_FILE = ROOT / ".env"
EAS_JSON = ROOT / "mobile" / "eas.json"

REVIEW_EMAIL = "review@cleanway.ai"
KEYCHAIN_SERVICE = "Cleanway app review account"
REVIEW_EMAILS_VAR = "EXPO_PUBLIC_REVIEW_EMAILS"

PASSWORD_LENGTH = 32
MIN_PASSWORD_LENGTH = 24
# Letters and digits only: nothing a shell, the `security -i` line or a paste
# into a store console could mangle. 32 of 62 symbols ≈ 190 bits.
ALPHABET = string.ascii_letters + string.digits
# GoTrue wants at least one character of each ":"-separated group of the
# project's password_required_characters ("letters:digits" today).
PROJECT_GROUPS = tuple(g for g in str(HARDENED_EXPECTED["password_required_characters"]).split(":") if g)
# What every generated password carries: stricter than the project rule, so a
# later switch to "lower:upper:digits" in the dashboard cannot break a rotation.
REQUIRED_GROUPS = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
_GROUP_NAMES = {
    string.ascii_lowercase: "lower-case letter",
    string.ascii_uppercase: "upper-case letter",
    string.ascii_letters: "letter",
    string.digits: "digit",
}

PER_PAGE = 100
MAX_PAGES = 1000
HTTP_TIMEOUT_S = 30
KEYCHAIN_TIMEOUT_S = 300  # a locked Keychain asks for the Mac password first

ENV_KEYS = ("SUPABASE_URL", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_KEY")
PLACEHOLDER_MARKERS = ("YOUR_PROJECT", "REPLACE_WITH")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ConfigError(Exception):
    """Something to fix in .env, the flags or the machine (exit 1)."""


class ApiError(Exception):
    """The GoTrue admin API refused or failed (exit 2)."""


class KeychainError(Exception):
    """The password could not be stored in or read back from the Keychain (exit 3)."""


# ─── The password ─────────────────────────────────────────────────


def generate_password(length: int = PASSWORD_LENGTH, rng=None) -> str:
    """A fresh password: one character of every required group, the rest from
    ALPHABET, shuffled. `rng` defaults to the OS CSPRNG (secrets.SystemRandom)."""
    if length < MIN_PASSWORD_LENGTH:
        raise ValueError(f"length {length} < {MIN_PASSWORD_LENGTH}")
    rng = rng or secrets.SystemRandom()
    chars = [rng.choice(group) for group in REQUIRED_GROUPS]
    chars += [rng.choice(ALPHABET) for _ in range(length - len(chars))]
    rng.shuffle(chars)
    return "".join(chars)


def password_problems(password: str) -> list[str]:
    """Rules the password breaks — each named, never quoting the password."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"too short ({len(password)} < {MIN_PASSWORD_LENGTH})")
    groups = REQUIRED_GROUPS + tuple(g for g in PROJECT_GROUPS if g not in REQUIRED_GROUPS)
    for group in groups:
        if not any(c in group for c in password):
            problems.append(f"no {_GROUP_NAMES.get(group, 'character of a required group')}")
    if any(c not in ALPHABET for c in password):
        problems.append("letters and digits only (the Keychain command line and a paste must not mangle it)")
    return problems


# ─── GoTrue admin payloads ────────────────────────────────────────


def create_payload(email: str, password: str) -> dict[str, object]:
    """POST /auth/v1/admin/users. email_confirm: nobody reads that mailbox, and
    an unconfirmed address cannot sign in."""
    return {"email": email, "password": password, "email_confirm": True}


def update_payload(password: str) -> dict[str, object]:
    """PUT /auth/v1/admin/users/{id}. "none" lifts a ban set between reviews,
    so a re-run always leaves a working account."""
    return {"password": password, "email_confirm": True, "ban_duration": "none"}


# ─── Configuration ────────────────────────────────────────────────


@dataclass(frozen=True)
class Config:
    url: str
    key: str


def merged_env(process_env: Mapping[str, str], env_file: Path) -> dict[str, str]:
    """Only the three names; the shell wins over .env, as in supabase_mail.py."""
    file_env = read_env_file(env_file)
    out = {k: file_env[k] for k in ENV_KEYS if file_env.get(k)}
    out.update({k: process_env[k] for k in ENV_KEYS if process_env.get(k)})
    return out


def resolve_config(env: Mapping[str, str]) -> Config:
    """Messages name variables and key kinds, never values."""
    url = (env.get("SUPABASE_URL") or "").strip().rstrip("/")
    if not url or any(m in url for m in PLACEHOLDER_MARKERS):
        raise ConfigError("SUPABASE_URL is missing or still the placeholder (.env or environment)")
    if not url.startswith("https://"):
        raise ConfigError("SUPABASE_URL must start with https://")
    secret = (env.get("SUPABASE_SECRET_KEY") or "").strip()
    key = secret or (env.get("SUPABASE_SERVICE_KEY") or "").strip()
    name = "SUPABASE_SECRET_KEY" if secret else "SUPABASE_SERVICE_KEY"
    if not key:
        raise ConfigError("SUPABASE_SECRET_KEY is missing (the legacy SUPABASE_SERVICE_KEY is accepted in its place)")
    kind = supabase_keys.key_kind(key)
    if kind not in ("secret", "legacy_service_role"):
        raise ConfigError(f"{name} holds a {kind} key, not a server key (sb_secret_… or the service_role JWT)")
    return Config(url=url, key=key)


def check_email(email: str) -> str:
    address = (email or "").strip().lower()
    if not EMAIL_RE.match(address):
        raise ConfigError("--email is not an email address")
    return address


def build_allowlist(path: Path = EAS_JSON) -> list[str]:
    """EXPO_PUBLIC_REVIEW_EMAILS of the production EAS profile, parsed like the app does."""
    try:
        profiles = json.loads(path.read_text(encoding="utf-8"))["build"]
        raw = str(((profiles.get("production") or {}).get("env") or {}).get(REVIEW_EMAILS_VAR, ""))
    except (OSError, ValueError, KeyError, AttributeError):
        return []
    parts = (p.strip().lower() for p in raw.split(","))
    return [p for p in parts if p and not p.startswith("$")]


def allowlisted_in_build(email: str) -> bool:
    return check_email(email) in build_allowlist()


# ─── GoTrue admin API ─────────────────────────────────────────────

Transport = Callable[[str, str, Mapping[str, str], Optional[bytes]], Tuple[int, object]]


def _json_or_text(raw: bytes) -> object:
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> Tuple[int, object]:
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status, _json_or_text(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json_or_text(exc.read(2000))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        path = urllib.parse.urlsplit(url).path
        raise ApiError(f"{method} {path} failed: {getattr(exc, 'reason', exc)}") from None


def _describe(data: object) -> str:
    """GoTrue's error, short: code, message and weak-password reasons."""
    if not isinstance(data, dict):
        return str(data)[:300]
    code = data.get("error_code") or data.get("error") or data.get("code") or ""
    msg = data.get("msg") or data.get("error_description") or data.get("message") or ""
    out = f"{code}: {msg}" if code else str(msg)
    weak = data.get("weak_password")
    if isinstance(weak, dict) and weak.get("reasons"):
        out += f" (reasons: {', '.join(map(str, weak['reasons']))})"
    return out[:300]


def _scrub(text: str, body: Optional[Mapping[str, object]]) -> str:
    """An error body must never carry the password back to the terminal."""
    secret = body.get("password") if body else None
    if isinstance(secret, str) and secret:
        text = text.replace(secret, "(secret)")
    return text


class AdminApi:
    def __init__(self, base_url: str, key: str, transport: Transport = urllib_transport) -> None:
        self._base = base_url.rstrip("/")
        self._transport = transport
        self.headers = supabase_keys.api_key_headers(key)
        self.headers["Content-Type"] = "application/json"

    def _call(self, method: str, path: str, body: Optional[Mapping[str, object]] = None) -> object:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        status, data = self._transport(method, self._base + path, self.headers, payload)
        if status >= 400:
            raise ApiError(f"{method} {path.split('?')[0]} → HTTP {status}: {_scrub(_describe(data), body)}")
        return data

    def find_user(self, email: str) -> Optional[dict]:
        """Exact (case-insensitive) match, page by page — no server-side filter
        whose matching rules could find the wrong account."""
        for page in range(1, MAX_PAGES + 1):
            data = self._call("GET", f"/auth/v1/admin/users?page={page}&per_page={PER_PAGE}")
            users = data.get("users") if isinstance(data, dict) else None
            if not isinstance(users, list):
                raise ApiError("GET /auth/v1/admin/users: unexpected answer (no users list)")
            for user in users:
                if isinstance(user, dict) and str(user.get("email") or "").strip().lower() == email:
                    return user
            if len(users) < PER_PAGE:
                return None
        raise ApiError(f"more than {MAX_PAGES * PER_PAGE} users — find the account in the dashboard")

    def create_user(self, email: str, password: str) -> object:
        return self._call("POST", "/auth/v1/admin/users", create_payload(email, password))

    def update_user(self, user_id: str, password: str) -> object:
        quoted = urllib.parse.quote(user_id, safe="")
        return self._call("PUT", f"/auth/v1/admin/users/{quoted}", update_payload(password))


# ─── Keychain ─────────────────────────────────────────────────────


def _keychain_arg(value: str) -> str:
    if any(c in value for c in '"\\\n\r'):
        raise KeychainError("a Keychain field holds a quote, a backslash or a newline")
    return f'"{value}"'


def keychain_store_line(account: str, password: str, service: str = KEYCHAIN_SERVICE) -> str:
    """The `security -i` command that stores (-U: or replaces) the item."""
    if password_problems(password):
        raise KeychainError("refusing to store a password that breaks the rules")
    return (
        f"add-generic-password -U -a {_keychain_arg(account)} -s {_keychain_arg(service)} "
        f"-l {_keychain_arg(service)} -w {_keychain_arg(password)}\n"
    )


def store_in_keychain(account: str, password: str, run: Callable[..., object], service: str = KEYCHAIN_SERVICE) -> None:
    """`security -i` reads the command from stdin, so the password is never in
    argv. Interactive mode's exit status does not report a failed command, so
    the item is read back and compared in memory (never printed)."""
    line = keychain_store_line(account, password, service)
    try:
        run(["security", "-i"], input=line, capture_output=True, text=True, check=False, timeout=KEYCHAIN_TIMEOUT_S)
        back = run(
            ["security", "find-generic-password", "-a", account, "-s", service, "-w"],
            capture_output=True, text=True, check=False, timeout=KEYCHAIN_TIMEOUT_S,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeychainError(f"`security` did not run ({type(exc).__name__})") from None
    if getattr(back, "returncode", 1) != 0 or str(getattr(back, "stdout", "")).rstrip("\n") != password:
        raise KeychainError("the Keychain item could not be written or read back")


def copy_command(email: str, service: str = KEYCHAIN_SERVICE) -> str:
    """Puts the password on the clipboard without showing it (no trailing newline)."""
    return f"security find-generic-password -s {shlex.quote(service)} -a {shlex.quote(email)} -w | tr -d '\\n' | pbcopy"


# ─── CLI ──────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--email", default=REVIEW_EMAIL, help=f"the review account (default {REVIEW_EMAIL}); must be in {REVIEW_EMAILS_VAR}")
    p.add_argument("--dry-run", action="store_true", help="look the account up and say what would happen; write nothing")
    p.add_argument("--env-file", type=Path, default=ENV_FILE, help=argparse.SUPPRESS)
    return p


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    transport: Optional[Transport] = None,
    run: Optional[Callable[..., object]] = None,
    platform: Optional[str] = None,
) -> int:
    args = build_parser().parse_args(argv)
    transport = transport or urllib_transport
    run = run or subprocess.run
    platform = platform or sys.platform
    try:
        email = check_email(args.email)
        cfg = resolve_config(merged_env(os.environ, args.env_file))
        if not args.dry_run and platform != "darwin":
            raise ConfigError("the password goes into the macOS Keychain — run this on the founder's Mac (macOS)")
        password = generate_password()
        if password_problems(password):  # cannot happen; never send one that breaks the rules
            raise ConfigError("generated password breaks the rules: " + "; ".join(password_problems(password)))

        api = AdminApi(cfg.url, cfg.key, transport=transport)
        print(f"→ Supabase {cfg.url} ({supabase_keys.key_kind(cfg.key)} key), аккаунт {email}")
        if not allowlisted_in_build(email):
            print(
                f"! {email} нет в {REVIEW_EMAILS_VAR} (mobile/eas.json, production): "
                "приложение не покажет для него поле пароля — добавьте адрес до следующей сборки"
            )
        user = api.find_user(email)
        user_id = str(user.get("id") or "") if user else ""
        if user and not user_id:
            raise ApiError("the account was found but has no id")

        if args.dry_run:
            if user:
                print(f"dry run: сменил бы пароль {email} (id {user_id}), снял бы блокировку и обновил Keychain «{KEYCHAIN_SERVICE}»")
            else:
                print(f"dry run: создал бы {email} (адрес подтверждён) и сохранил пароль в Keychain «{KEYCHAIN_SERVICE}»")
            print("ничего не записано")
            return 0

        if user:
            api.update_user(user_id, password)
            print(f"✓ {email}: новый пароль (id {user_id}), адрес подтверждён, блокировки нет")
        else:
            created = api.create_user(email, password)
            new_id = created.get("id") if isinstance(created, dict) else None
            print(f"✓ {email}: аккаунт создан (id {new_id or '?'}), адрес подтверждён")
        store_in_keychain(email, password, run)
        print(f"✓ пароль в Keychain: служба «{KEYCHAIN_SERVICE}», аккаунт {email} (на экран не выводится)")
        print("Скопировать в буфер обмена:")
        print(f"  {copy_command(email)}")
        print("Куда вставить адрес и пароль (App Store Connect, Play Console, RuStore): docs/runbooks/app-review-account.md")
        return 0
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    except ApiError as exc:
        print(f"api error: {exc}", file=sys.stderr)
        return 2
    except KeychainError as exc:
        print(
            f"keychain error: {exc}. Пароль в Supabase уже новый, но нигде не сохранён — "
            "запустите скрипт ещё раз (он снова сменит пароль)",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
