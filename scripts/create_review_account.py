#!/usr/bin/env python3
"""Create or rotate the store reviewers' sign-in account (review@cleanway.ai).

App Store, Google Play and RuStore reviewers cannot sign in with an emailed
code: the code would land in our inbox. The app shows a password field for
the addresses in EXPO_PUBLIC_REVIEW_EMAILS (mobile/src/utils/review-login.ts)
and this script gives that account its password. Runbook:
docs/runbooks/app-review-account.md. The founder runs it on his Mac; nothing
in CI or in an agent session runs it against production.

What it does, against the Supabase project in SUPABASE_URL:

  1. looks the user up by email (GoTrue admin API, GET /auth/v1/admin/users)
     and, if it exists, whether a reviewer deleted it (users row,
     deletion_requested_at);
  2. creates it (POST, email_confirm=true) or rotates its password
     (PUT /auth/v1/admin/users/{id}: new password, email_confirm=true, a ban
     from "disable between reviews" lifted);
  3. stores the password in the macOS login Keychain — service
     "Cleanway app review account", account = the email — and prints only
     the command that copies it to the clipboard;
  4. if a reviewer deleted it (Apple tests account deletion), restores it
     as POST /api/v1/user/account/restore does: DELETE /user/account only
     marks the row and sets the Redis lock `deleted:{id}` for the 30-day
     grace — the auth user stays until the purge — so a new password alone
     leaves every API call answering 410 ("account on hold" in the app). The
     row is cleared with the server key, pinned to the grace window as the
     endpoint does it, and the lock and its caches (`deleted:`,
     `notdeleted:`, `tier:`) are deleted from the API's Redis (REDIS_URL).
     Without REDIS_URL, or past the window, it stops before writing
     anything and says what to do.

Every run generates a new password: re-running IS the rotation.
--dry-run looks the account up and says what it would do; nothing is written.

It only ever touches a review account: an address that is not on
@cleanway.ai AND in EXPO_PUBLIC_REVIEW_EMAILS of mobile/eas.json (production)
is refused before any request, dry run included. Otherwise a typo in --email
would give a real person's account a password only the founder's Keychain
holds, confirm their address, lift their ban and sign them out everywhere
(GoTrue ends all sessions on an admin password change).

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
  REDIS_URL               the API's Redis, reachable from the Mac (Railway →
                          Redis → Variables → REDIS_PUBLIC_URL). Needed only to
                          restore an account a reviewer deleted

Run:  python3 scripts/create_review_account.py [--dry-run] [--email ADDRESS]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import string
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
REVIEW_DOMAIN = "@cleanway.ai"  # the app's rule too (mobile/src/utils/review-login.ts)
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

ENV_KEYS = ("SUPABASE_URL", "SUPABASE_SECRET_KEY", "SUPABASE_SERVICE_KEY", "REDIS_URL")
PLACEHOLDER_MARKERS = ("YOUR_PROJECT", "REPLACE_WITH")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# The deletion grace: _DELETION_GRACE_DAYS in api/routers/user.py and
# GRACE_DAYS in api/services/account_purge.py (a test pins all three).
GRACE_DAYS = 30
# What DELETE /user/account sets and POST /user/account/restore clears: the
# 410 lock, and the caches beside it (api/services/auth.py, api/routers/user.py).
LOCK_KEYS = ("deleted:{id}", "notdeleted:{id}", "tier:{id}")
# Hosts that cannot be the production Redis as the Mac sees it: this machine
# (also 127.* and *.localhost) and Railway's private network (*.railway.internal).
LOCAL_HOSTS = ("localhost", "0.0.0.0", "::1")
RESTORE_IN_APP = "войдите этим аккаунтом в приложении и нажмите «Восстановить аккаунт»"
REDIS_HINT = "REDIS_PUBLIC_URL из Railway → Redis → Variables"


class ConfigError(Exception):
    """Something to fix in .env, the flags or the machine (exit 1)."""


class ApiError(Exception):
    """The GoTrue admin API refused or failed (exit 2)."""


class KeychainError(Exception):
    """The password could not be stored in or read back from the Keychain (exit 3)."""


class RestoreError(Exception):
    """A deleted review account could not be restored (exit 4)."""


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
    redis_url: str = ""


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
    redis_url = (env.get("REDIS_URL") or "").strip()
    if redis_url:
        check_redis_url(redis_url)
    return Config(url=url, key=key, redis_url=redis_url)


def redis_host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def check_redis_url(url: str) -> None:
    """The API's Redis, or nothing: a local one would "clear" a lock that
    production still holds. Messages name the host, never the URL (it holds
    the password)."""
    if urllib.parse.urlsplit(url).scheme not in ("redis", "rediss"):
        raise ConfigError("REDIS_URL must start with redis:// or rediss://")
    host = redis_host(url)
    if not host or host in LOCAL_HOSTS or host.startswith("127.") or host.endswith((".localhost", ".railway.internal")):
        raise ConfigError(
            f"REDIS_URL points at {host or 'no host'}, not at the API's Redis as the Mac reaches it: "
            "take REDIS_PUBLIC_URL from Railway → Redis → Variables"
        )


def check_email(email: str) -> str:
    address = (email or "").strip().lower()
    if not EMAIL_RE.match(address):
        raise ConfigError("--email is not an email address")
    return address


def build_allowlist(path: Path = EAS_JSON) -> list[str]:
    """EXPO_PUBLIC_REVIEW_EMAILS of the production EAS profile, parsed like the
    app does (parseReviewEmails): addresses on @cleanway.ai only, no "$…"
    references, no duplicates."""
    try:
        profiles = json.loads(path.read_text(encoding="utf-8"))["build"]
        raw = str(((profiles.get("production") or {}).get("env") or {}).get(REVIEW_EMAILS_VAR, ""))
    except (OSError, ValueError, KeyError, AttributeError):
        return []
    out: list[str] = []
    for part in raw.split(","):
        email = part.strip().lower()
        if email.startswith("$") or not EMAIL_RE.match(email) or not email.endswith(REVIEW_DOMAIN):
            continue
        if email not in out:
            out.append(email)
    return out


def require_review_email(email: str) -> str:
    """The only addresses this script may write to: ours AND in the build's list.
    Anything else is someone else's account (or one the app cannot sign in)."""
    address = check_email(email)
    if not address.endswith(REVIEW_DOMAIN) or address not in build_allowlist():
        raise ConfigError(
            f"{address} is not a review account: only {REVIEW_DOMAIN} addresses listed in "
            f"{REVIEW_EMAILS_VAR} (mobile/eas.json, production) — nothing was sent"
        )
    return address


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

    def _call(
        self, method: str, path: str, body: Optional[Mapping[str, object]] = None, prefer: str = ""
    ) -> object:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {**self.headers, "Prefer": prefer} if prefer else self.headers
        status, data = self._transport(method, self._base + path, headers, payload)
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

    def deletion_requested_at(self, user_id: str) -> Optional[str]:
        """users.deletion_requested_at: set from DELETE /user/account until the
        purge; None when the account is not deleted (or has no row)."""
        query = urllib.parse.urlencode({"id": f"eq.{user_id}", "select": "deletion_requested_at"})
        rows = self._call("GET", f"/rest/v1/users?{query}")
        if not isinstance(rows, list):
            raise ApiError("GET /rest/v1/users: unexpected answer (no list)")
        value = rows[0].get("deletion_requested_at") if rows and isinstance(rows[0], dict) else None
        return str(value) if value else None

    def cancel_deletion(self, user_id: str, cutoff: str) -> bool:
        """The PATCH of POST /user/account/restore: only a deletion still inside
        the grace window is cleared, in the UPDATE itself (the purge acts only
        past the same cutoff). False: the window closed, the purge has it."""
        query = urllib.parse.urlencode({
            "id": f"eq.{user_id}",
            "or": f'(deletion_requested_at.is.null,deletion_requested_at.gt."{cutoff}")',
            "select": "id",
        })
        rows = self._call("PATCH", f"/rest/v1/users?{query}", {"deletion_requested_at": None},
                          prefer="return=representation")
        if not isinstance(rows, list):
            raise ApiError("PATCH /rest/v1/users: unexpected answer (no list)")
        return bool(rows)


def parse_timestamp(value: str) -> Optional[datetime]:
    """A Postgres timestamptz as PostgREST sends it, on any python3 the Mac
    has (3.9's fromisoformat wants exactly 6 fraction digits and "+00:00")."""
    text = value.strip().replace(" ", "T", 1)
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), text)
    text = re.sub(r"([+-]\d{2})$", r"\1:00", text)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None  # the PATCH's own guard still decides
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def grace_cutoff(now: Optional[datetime] = None) -> datetime:
    return (now or datetime.now(timezone.utc)) - timedelta(days=GRACE_DAYS)


# ─── The API's Redis ──────────────────────────────────────────────


class RespError(Exception):
    """Redis answered an error; the message is its code only (WRONGPASS, NOAUTH…)."""


class RespClient:
    """Just enough of the Redis protocol for PING and DEL, on the standard
    library: the script runs on the Mac's own python3, which has no `redis`
    package. redis:// or rediss:// (TLS), a password, a database number."""

    def __init__(self, url: str, timeout: float = HTTP_TIMEOUT_S) -> None:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        sock = socket.create_connection((host, parts.port or 6379), timeout=timeout)
        if parts.scheme == "rediss":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        self._sock = sock
        self._reader = sock.makefile("rb")
        password = urllib.parse.unquote(parts.password or "")
        user = urllib.parse.unquote(parts.username or "")
        try:
            if password:
                # One argument for the default user: what every Redis version takes.
                self._command("AUTH", *([user] if user not in ("", "default") else []), password)
            if parts.path.strip("/"):
                self._command("SELECT", parts.path.strip("/"))
        except Exception:
            self.close()
            raise

    def _command(self, *args: str) -> object:
        frame = [b"*%d\r\n" % len(args)]
        for arg in args:
            data = arg.encode("utf-8")
            frame.append(b"$%d\r\n%s\r\n" % (len(data), data))
        self._sock.sendall(b"".join(frame))
        line = self._reader.readline(65536)
        if not line.endswith(b"\r\n"):
            raise ConnectionError("Redis closed the connection")
        kind, text = line[:1], line[1:-2].decode("utf-8", "replace")
        if kind == b"-":
            raise RespError(text.split(" ", 1)[0])
        if kind == b":":
            return int(text)
        if kind == b"+":
            return text
        raise ConnectionError("unexpected Redis reply")

    def ping(self) -> object:
        return self._command("PING")

    def delete(self, *keys: str) -> object:
        return self._command("DEL", *keys)

    def close(self) -> None:
        self._reader.close()
        self._sock.close()


def open_redis(url: str) -> RespClient:
    return RespClient(url)


def _failure(exc: Exception) -> str:
    """What went wrong, never the error's own text (it could hold the URL)."""
    return f"{type(exc).__name__} {exc}" if isinstance(exc, RespError) else type(exc).__name__


def connect_redis(url: str, factory: Callable[[str], object]) -> object:
    """Before anything is written: a restore that cannot reach Redis would
    leave the 410 lock in place behind a cleared row."""
    client = None
    try:
        client = factory(url)
        client.ping()
    except Exception as exc:  # protocol, socket and DNS errors alike; never their text (the URL)
        _close(client)
        raise RestoreError(
            f"Redis API ({redis_host(url)}) не отвечает ({_failure(exc)}). Ничего не записано: проверьте "
            f"REDIS_URL (нужен {REDIS_HINT}) или уберите его, если аккаунт не удалён, и запустите ещё раз — "
            f"или {RESTORE_IN_APP}"
        ) from None
    return client


def clear_lock(client: object, user_id: str, host: str) -> None:
    keys = [k.format(id=user_id) for k in LOCK_KEYS]
    try:
        client.delete(*keys)
    except Exception as exc:
        raise RestoreError(
            f"Redis API ({host}): флаг удаления не снять ({_failure(exc)}). Пароль новый и в Keychain. "
            f"Запустите скрипт ещё раз с тем же REDIS_URL — или {RESTORE_IN_APP}"
        ) from None
    finally:
        _close(client)


def _close(client: object) -> None:
    close = getattr(client, "close", None)
    if callable(close):
        try:
            close()
        except OSError:
            pass  # the run's outcome stands


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
    p.add_argument(
        "--email",
        default=REVIEW_EMAIL,
        help=f"the review account (default {REVIEW_EMAIL}); refused unless it is on {REVIEW_DOMAIN} "
        f"and in {REVIEW_EMAILS_VAR} of mobile/eas.json",
    )
    p.add_argument("--dry-run", action="store_true", help="look the account up and say what would happen; write nothing")
    p.add_argument("--env-file", type=Path, default=ENV_FILE, help=argparse.SUPPRESS)
    return p


def deletion_plan(email: str, deleted_at: str, past_window: bool, have_redis: bool) -> str:
    if past_window:
        return (f"dry run: {email} помечен на удаление {deleted_at}; {GRACE_DAYS} дней прошли — восстановить нельзя, "
                "после очистки скрипт создаст аккаунт заново")
    redis_state = "REDIS_URL задан" if have_redis else f"нужен REDIS_URL ({REDIS_HINT}), без него запуск остановится"
    return (f"dry run: {email} помечен на удаление {deleted_at} — снял бы пометку в users и флаг удаления в Redis, "
            f"как «Восстановить аккаунт» ({redis_state})")


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    transport: Optional[Transport] = None,
    run: Optional[Callable[..., object]] = None,
    platform: Optional[str] = None,
    redis_factory: Optional[Callable[[str], object]] = None,
) -> int:
    args = build_parser().parse_args(argv)
    transport = transport or urllib_transport
    run = run or subprocess.run
    platform = platform or sys.platform
    redis_factory = redis_factory or open_redis
    try:
        email = require_review_email(args.email)  # before any request, dry run included
        cfg = resolve_config(merged_env(os.environ, args.env_file))
        if not args.dry_run and platform != "darwin":
            raise ConfigError("the password goes into the macOS Keychain — run this on the founder's Mac (macOS)")
        password = generate_password()
        if password_problems(password):  # cannot happen; never send one that breaks the rules
            raise ConfigError("generated password breaks the rules: " + "; ".join(password_problems(password)))

        api = AdminApi(cfg.url, cfg.key, transport=transport)
        print(f"→ Supabase {cfg.url} ({supabase_keys.key_kind(cfg.key)} key), аккаунт {email}")
        user = api.find_user(email)
        user_id = str(user.get("id") or "") if user else ""
        if user and not user_id:
            raise ApiError("the account was found but has no id")
        deleted_at = api.deletion_requested_at(user_id) if user else None
        since = parse_timestamp(deleted_at) if deleted_at else None
        past_window = since is not None and since <= grace_cutoff()

        if args.dry_run:
            if user:
                print(f"dry run: сменил бы пароль {email} (id {user_id}), снял бы блокировку и обновил Keychain «{KEYCHAIN_SERVICE}»")
                if deleted_at:
                    print(deletion_plan(email, deleted_at, past_window, bool(cfg.redis_url)))
            else:
                print(f"dry run: создал бы {email} (адрес подтверждён) и сохранил пароль в Keychain «{KEYCHAIN_SERVICE}»")
            print("ничего не записано")
            return 0

        if past_window:
            raise RestoreError(
                f"{email} помечен на удаление {deleted_at}: {GRACE_DAYS} дней прошли, аккаунт удалит очистка "
                "(вместе со входом). После неё запустите скрипт ещё раз — он создаст аккаунт заново. Ничего не записано"
            )
        if deleted_at and not cfg.redis_url:
            raise ConfigError(
                f"{email} помечен на удаление ({deleted_at}): пока в Redis стоит флаг удаления, API отвечает ему 410, "
                f"и новый пароль его не снимет. Нужен REDIS_URL ({REDIS_HINT}): REDIS_URL='…' python3 "
                f"scripts/create_review_account.py — или {RESTORE_IN_APP}. Ничего не записано"
            )
        lock = connect_redis(cfg.redis_url, redis_factory) if user and cfg.redis_url else None

        if user:
            api.update_user(user_id, password)
            print(f"✓ {email}: новый пароль (id {user_id}), адрес подтверждён, блокировки нет")
        else:
            created = api.create_user(email, password)
            new_id = created.get("id") if isinstance(created, dict) else None
            print(f"✓ {email}: аккаунт создан (id {new_id or '?'}), адрес подтверждён")
        store_in_keychain(email, password, run)
        print(f"✓ пароль в Keychain: служба «{KEYCHAIN_SERVICE}», аккаунт {email} (на экран не выводится)")
        if deleted_at and not api.cancel_deletion(user_id, grace_cutoff().isoformat()):
            raise RestoreError(
                f"{email}: окно {GRACE_DAYS} дней закрылось — аккаунт удаляет очистка, флаг удаления не трогали. "
                "Пароль новый и в Keychain, но после очистки он не подойдёт: тогда запустите скрипт ещё раз — "
                "он создаст аккаунт заново"
            )
        if lock is not None:
            # On a live row too: a restore that cleared the row but not the
            # flag (its 503 path) still answers 410.
            clear_lock(lock, user_id, redis_host(cfg.redis_url))
            if deleted_at:
                print(f"✓ {email}: удаление отменено — пометка в users и флаг в Redis сняты, как «Восстановить аккаунт»")
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
    except RestoreError as exc:
        print(f"restore error: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
