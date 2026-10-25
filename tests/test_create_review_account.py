"""scripts/create_review_account.py — the store reviewers' sign-in account.

The founder runs the script against production himself; nothing here touches
a network or the real Keychain. What is pinned: the generated password passes
the project's GoTrue password rules, the admin API payloads have the right
shape (confirmed address, rotation lifts a ban), an existing account is found
and rotated instead of duplicated, an address that is not a review account
(not on @cleanway.ai, or not in the build's EXPO_PUBLIC_REVIEW_EMAILS) is
refused before any request, a dry run writes nothing, the password
reaches only the HTTPS body and the Keychain's stdin — never argv, stdout or
an error message — and the server key comes from the same variables the
backend reads. An account a reviewer deleted (still inside the 30-day grace)
is restored as the app's "Restore my account" button does it — signed in
with the new password, POST /api/v1/user/account/restore, signed out — or,
past the window, the run stops before writing anything.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import string
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "create_review_account.py"


def _load() -> ModuleType:
    name = "create_review_account"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cra = _load()

URL = "https://proj.supabase.co"
# Assembled at runtime and low-entropy so secret scanners do not take the
# fixtures for leaked keys.
SECRET = "_".join(["sb", "secret", "x" * 20])
PUBLISHABLE = "_".join(["sb", "publishable", "y" * 20])


def _jwt(role: str) -> str:
    def b64(o: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'HS256'})}.{b64({'role': role, 'iss': 'supabase'})}.c2ln"


# ─── the password ─────────────────────────────────────────────────


def test_rules_cover_the_project_auth_config():
    """GoTrue wants one character of every ":"-group of the project's
    password_required_characters (scripts/supabase_mail.py HARDENED_EXPECTED;
    "letters:digits" today). Every generated password mixes lower, upper and
    digits, which satisfies that rule and the stricter lower:upper:digits one,
    and the length floor is above the project's password_min_length."""
    rule = cra.HARDENED_EXPECTED["password_required_characters"]
    assert cra.PROJECT_GROUPS == tuple(rule.split(":"))
    assert cra.REQUIRED_GROUPS == (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    for group in cra.PROJECT_GROUPS:
        assert any(set(req) <= set(group) for req in cra.REQUIRED_GROUPS), group
    assert cra.MIN_PASSWORD_LENGTH >= 24
    assert cra.MIN_PASSWORD_LENGTH >= cra.HARDENED_EXPECTED["password_min_length"]


def test_a_stricter_project_rule_is_checked_too(monkeypatch):
    monkeypatch.setattr(cra, "PROJECT_GROUPS", cra.PROJECT_GROUPS + ("!@#",))
    assert "no character of a required group" in cra.password_problems("aB3" * 10)


def test_generated_passwords_meet_the_rules_and_never_repeat():
    seen = set()
    for _ in range(300):
        pw = cra.generate_password()
        assert len(pw) == cra.PASSWORD_LENGTH >= 24
        assert cra.password_problems(pw) == []
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        # Letters and digits only: nothing a shell, the Keychain command line
        # or a paste into a store console could mangle.
        assert set(pw) <= set(string.ascii_letters + string.digits)
        seen.add(pw)
    assert len(seen) == 300


def test_every_class_is_present_even_when_the_rng_is_lopsided():
    class FirstChoice:
        """Always picks the first character and never shuffles."""

        def choice(self, seq):
            return seq[0]

        def shuffle(self, seq):
            return None

    pw = cra.generate_password(rng=FirstChoice())
    assert cra.password_problems(pw) == []


def test_short_passwords_are_refused():
    with pytest.raises(ValueError):
        cra.generate_password(length=cra.MIN_PASSWORD_LENGTH - 1)


@pytest.mark.parametrize(
    ("password", "needle"),
    [
        ("Ab1" * 4, "short"),
        ("abcdefghijklmnopqrstuvwxyz0123456789", "upper"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "lower"),
        ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJ", "digit"),
        ("abcdefghijklmnopqrstuvwxyzABCDEFGH12!", "letters and digits"),
    ],
)
def test_password_problems_name_the_rule_not_the_password(password, needle):
    problems = cra.password_problems(password)
    assert any(needle in p for p in problems), problems
    assert all(password not in p for p in problems)


# ─── payloads ─────────────────────────────────────────────────────


def test_create_payload_confirms_the_address():
    assert cra.create_payload("review@cleanway.ai", "Pw1") == {
        "email": "review@cleanway.ai",
        "password": "Pw1",
        "email_confirm": True,
    }


def test_update_payload_rotates_confirms_and_lifts_a_ban():
    assert cra.update_payload("Pw2") == {"password": "Pw2", "email_confirm": True, "ban_duration": "none"}


def test_the_review_address_is_ours():
    assert cra.REVIEW_EMAIL == "review@cleanway.ai"
    assert cra.KEYCHAIN_SERVICE == "Cleanway app review account"


# ─── configuration ────────────────────────────────────────────────


def test_secret_key_wins_and_is_sent_as_apikey_only():
    cfg = cra.resolve_config({"SUPABASE_URL": URL + "/", "SUPABASE_SECRET_KEY": SECRET, "SUPABASE_SERVICE_KEY": _jwt("service_role")})
    assert cfg.url == URL
    assert cfg.key == SECRET
    headers = cra.AdminApi(cfg.url, cfg.key, transport=lambda *a: (200, {})).headers
    assert headers["apikey"] == SECRET
    assert "Authorization" not in headers


def test_legacy_service_role_key_still_works():
    key = _jwt("service_role")
    cfg = cra.resolve_config({"SUPABASE_URL": URL, "SUPABASE_SERVICE_KEY": key})
    headers = cra.AdminApi(cfg.url, cfg.key, transport=lambda *a: (200, {})).headers
    assert headers["apikey"] == key
    assert headers["Authorization"] == f"Bearer {key}"


@pytest.mark.parametrize(
    ("env", "needle"),
    [
        ({"SUPABASE_SECRET_KEY": SECRET}, "SUPABASE_URL"),
        ({"SUPABASE_URL": "http://proj.supabase.co", "SUPABASE_SECRET_KEY": SECRET}, "https"),
        ({"SUPABASE_URL": "https://YOUR_PROJECT.supabase.co", "SUPABASE_SECRET_KEY": SECRET}, "SUPABASE_URL"),
        ({"SUPABASE_URL": URL}, "SUPABASE_SECRET_KEY"),
        ({"SUPABASE_URL": URL, "SUPABASE_SECRET_KEY": PUBLISHABLE}, "server key"),
        ({"SUPABASE_URL": URL, "SUPABASE_SERVICE_KEY": _jwt("anon")}, "server key"),
    ],
)
def test_bad_configuration_is_a_config_error_that_names_variables_not_values(env, needle):
    with pytest.raises(cra.ConfigError) as exc:
        cra.resolve_config(env)
    assert needle in str(exc.value)
    for value in env.values():
        if value.startswith("sb_") or value.startswith("eyJ"):
            assert value not in str(exc.value)


def test_env_file_is_read_and_the_shell_wins(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(f"SUPABASE_URL={URL}\nSUPABASE_SECRET_KEY=\"{SECRET}\"\nSMTP_PASS=unrelated\n", encoding="utf-8")
    merged = cra.merged_env({"SUPABASE_URL": "https://other.supabase.co", "HOME": "/x"}, env_file)
    assert merged == {"SUPABASE_URL": "https://other.supabase.co", "SUPABASE_SECRET_KEY": SECRET}


@pytest.mark.parametrize("email", ["", "review", "review@cleanway", "a b@cleanway.ai"])
def test_bad_email_flag_is_refused(email):
    with pytest.raises(cra.ConfigError):
        cra.check_email(email)


def test_email_flag_is_normalised():
    assert cra.check_email("  Review@Cleanway.AI ") == "review@cleanway.ai"


def test_the_shipped_build_allowlists_the_review_address():
    assert cra.REVIEW_EMAIL in cra.build_allowlist()
    assert cra.require_review_email(" Review@Cleanway.AI ") == cra.REVIEW_EMAIL
    for other in ("someone-else@cleanway.ai", "customer@gmail.com"):
        with pytest.raises(cra.ConfigError) as exc:
            cra.require_review_email(other)
        assert "nothing was sent" in str(exc.value)


# ─── fakes ────────────────────────────────────────────────────────


class FakeGoTrue:
    """GoTrue admin API stand-in: a user table and a request log — plus the
    PostgREST `users` table (id → deletion_requested_at, None: not deleted),
    the password grant and sign-out, and the API's POST /user/account/restore
    (`restore`: (status, body) answers to give in turn, then the real one)."""

    def __init__(self, users=None, fail=None, rows=None, restore=(), token_fail=None):
        self.users = list(users or [])
        self.requests = []
        self.fail = fail  # (method, status, body) to answer instead
        self.rows = dict(rows or {})
        self.passwords = {}  # user id → the password the admin API set
        self.restore_answers = list(restore)
        self.token_fail = token_fail  # (status, body) for the password grant

    def __call__(self, method, url, headers, body):
        data = json.loads(body) if body else None
        self.requests.append((method, url, dict(headers), data))
        if self.fail and self.fail[0] == method:
            return self.fail[1], self.fail[2]
        if url.startswith(API + "/"):
            return self._api(method, url[len(API):], headers)
        path = url[len(URL):]
        if method == "GET" and path.startswith("/auth/v1/admin/users?"):
            query = dict(p.split("=") for p in path.split("?", 1)[1].split("&"))
            page, per_page = int(query["page"]), int(query["per_page"])
            chunk = self.users[(page - 1) * per_page: page * per_page]
            return 200, {"users": chunk, "aud": "authenticated"}
        if method == "POST" and path == "/auth/v1/admin/users":
            user = {"id": f"id-{len(self.users) + 1}", "email": data["email"]}
            self.users.append(user)
            self.passwords[user["id"]] = data["password"]
            return 200, user
        if method == "PUT" and path.startswith("/auth/v1/admin/users/"):
            self.passwords[path.rsplit("/", 1)[1]] = data["password"]
            return 200, {"id": path.rsplit("/", 1)[1]}
        if method == "POST" and path == "/auth/v1/token?grant_type=password":
            return self._sign_in(data)
        if method == "POST" and path == "/auth/v1/logout?scope=local":
            return (204, "") if headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}" else (401, {"msg": "no session"})
        if path.startswith("/rest/v1/users?"):
            return self._users_table(method, _query(url), data)
        return 404, {"msg": "not found"}

    def _sign_in(self, data):
        if self.token_fail:
            return self.token_fail
        user = next((u for u in self.users if u["email"].lower() == data["email"]), None)
        if user is None or self.passwords.get(user["id"]) != data["password"]:
            return 400, {"error_code": "invalid_credentials", "msg": "Invalid login credentials"}
        return 200, {"access_token": ACCESS_TOKEN, "token_type": "bearer", "refresh_token": "r" * 12,
                     "user": {"id": user["id"]}}

    def _users_table(self, method, query, data):
        uid = query["id"].removeprefix("eq.")
        if method == "GET":
            return 200, [{"deletion_requested_at": self.rows[uid]}] if uid in self.rows else []
        return 405, {"msg": "method not allowed"}

    def _api(self, method, path, headers):
        if (method, path) != ("POST", "/api/v1/user/account/restore"):
            return 404, {"detail": "Not Found"}
        if headers.get("Authorization") != f"Bearer {ACCESS_TOKEN}":
            return 401, {"detail": "Authorization header required"}
        if self.restore_answers:
            return self.restore_answers.pop(0)
        uid = next(u["id"] for u in self.users if self.passwords.get(u["id"]))
        deleted = self.rows.get(uid)
        if deleted and datetime.fromisoformat(deleted) <= datetime.now(timezone.utc) - timedelta(days=30):
            return 410, WINDOW_CLOSED
        self.rows[uid] = None
        return 200, {"restored": True}

    def writes(self):
        return [r for r in self.requests if r[0] != "GET"]

    def calls_to(self, path):
        return [r for r in self.requests if urllib.parse.urlsplit(r[1]).path == path]


class FakeSecurity:
    """`security` stand-in: remembers what -i was fed and answers the read-back."""

    def __init__(self, store_ok=True, readback=None):
        self.calls = []
        self.items = {}
        self.store_ok = store_ok
        self.readback = readback

    def __call__(self, argv, input=None, capture_output=False, text=False, check=False, timeout=None):
        self.calls.append((list(argv), input))
        if argv[:2] == ["security", "-i"]:
            if self.store_ok:
                # The line format the script builds: -a "acct" -s "svc" ... -w "pw"
                parts = input.split('"')
                self.items[(parts[1], parts[3])] = parts[-2]
            return _Completed(0, "security> ", "")
        if argv[:2] == ["security", "find-generic-password"]:
            acct, svc = argv[argv.index("-a") + 1], argv[argv.index("-s") + 1]
            value = self.readback if self.readback is not None else self.items.get((acct, svc))
            if value is None:
                return _Completed(44, "", "The specified item could not be found in the keychain.\n")
            return _Completed(0, value + "\n", "")
        raise AssertionError(f"unexpected command {argv}")


def _query(url):
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


class _Completed:
    def __init__(self, returncode, stdout, stderr):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    for key in cra.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / ".env"
    path.write_text(f"SUPABASE_URL={URL}\nSUPABASE_SECRET_KEY={SECRET}\n", encoding="utf-8")
    return path


def _run(env_file, *args, gotrue, security, platform="darwin", sleep=None):
    return cra.main(["--env-file", str(env_file), *args], transport=gotrue, run=security, platform=platform,
                    sleep=sleep or (lambda seconds: None))


def _passwords(gotrue):
    """What the admin API set (POST or PUT of /auth/v1/admin/users)."""
    return [r[3]["password"] for r in gotrue.writes() if "/auth/v1/admin/users" in r[1]]


# ─── the run ──────────────────────────────────────────────────────


def test_new_account_is_created_confirmed_and_stored(env_file, capsys):
    gotrue, security = FakeGoTrue(), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    (method, url, headers, body), = gotrue.writes()
    assert (method, url) == ("POST", URL + "/auth/v1/admin/users")
    assert body["email"] == "review@cleanway.ai" and body["email_confirm"] is True
    assert cra.password_problems(body["password"]) == []
    assert headers["apikey"] == SECRET
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)] == body["password"]
    out = capsys.readouterr()
    assert body["password"] not in out.out + out.err
    assert "find-generic-password" in out.out and "pbcopy" in out.out


def test_existing_account_is_rotated_not_duplicated(env_file, capsys):
    gotrue = FakeGoTrue(users=[{"id": "u-1", "email": "Review@Cleanway.ai"}])
    security = FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    (method, url, _, body), = gotrue.writes()
    assert (method, url) == ("PUT", URL + "/auth/v1/admin/users/u-1")
    assert body["email_confirm"] is True and body["ban_duration"] == "none"
    assert len(gotrue.users) == 1
    assert body["password"] not in capsys.readouterr().out


def test_rerunning_rotates_the_password_each_time(env_file):
    gotrue, security = FakeGoTrue(), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    methods = [r[0] for r in gotrue.writes()]
    assert methods == ["POST", "PUT"]
    first, second = _passwords(gotrue)
    assert first != second
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)] == second


def test_the_account_is_found_past_the_first_page(env_file, monkeypatch):
    monkeypatch.setattr(cra, "PER_PAGE", 2)
    others = [{"id": f"o-{i}", "email": f"person{i}@mail.ru"} for i in range(5)]
    gotrue = FakeGoTrue(users=others + [{"id": "u-9", "email": "review@cleanway.ai"}])
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 0
    assert sum(r[0] == "GET" and "/auth/v1/admin/users?" in r[1] for r in gotrue.requests) == 3
    assert gotrue.writes()[0][1].endswith("/auth/v1/admin/users/u-9")


def test_dry_run_reads_but_writes_nothing(env_file, capsys):
    gotrue = FakeGoTrue(users=[{"id": "u-1", "email": "review@cleanway.ai"}])
    security = FakeSecurity()
    assert _run(env_file, "--dry-run", gotrue=gotrue, security=security) == 0
    assert gotrue.writes() == []
    assert security.calls == []
    assert "u-1" in capsys.readouterr().out


def test_the_password_never_reaches_argv(env_file):
    gotrue, security = FakeGoTrue(), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    (password,) = _passwords(gotrue)
    for argv, stdin in security.calls:
        assert all(password not in a for a in argv)
    store = [c for c in security.calls if c[0][:2] == ["security", "-i"]]
    assert len(store) == 1
    line = store[0][1]
    assert line.count(password) == 1
    assert "add-generic-password -U" in line
    assert f'-s "{cra.KEYCHAIN_SERVICE}"' in line


def test_a_refused_password_is_reported_without_it(env_file, capsys):
    refusal = {"code": 422, "error_code": "weak_password", "msg": "Password is known to be weak", "weak_password": {"reasons": ["pwned"]}}
    gotrue = FakeGoTrue(fail=("POST", 422, refusal))
    security = FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 2
    (password,) = _passwords(gotrue)
    out = capsys.readouterr()
    assert "weak_password" in out.err and "pwned" in out.err
    assert password not in out.out + out.err
    assert [c for c in security.calls if c[0][:2] == ["security", "-i"]] == []


def test_an_echoed_password_in_an_error_body_is_scrubbed(env_file, capsys):
    class Echo(FakeGoTrue):
        def __call__(self, method, url, headers, body):
            if method == "POST":
                self.requests.append((method, url, dict(headers), json.loads(body)))
                return 400, {"msg": "bad request: " + body.decode()}
            return super().__call__(method, url, headers, body)

    gotrue = Echo()
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 2
    (password,) = _passwords(gotrue)
    out = capsys.readouterr()
    assert password not in out.out + out.err
    assert "(secret)" in out.err


def test_keychain_failure_is_loud_and_says_to_rerun(env_file, capsys):
    gotrue, security = FakeGoTrue(), FakeSecurity(store_ok=False)
    assert _run(env_file, gotrue=gotrue, security=security) == 3
    (password,) = _passwords(gotrue)
    out = capsys.readouterr()
    assert password not in out.out + out.err
    assert "ещё раз" in out.err


def test_keychain_readback_mismatch_is_a_failure(env_file):
    security = FakeSecurity(readback="SomethingElse123")
    assert _run(env_file, gotrue=FakeGoTrue(), security=security) == 3


def test_not_a_mac_stops_before_any_request(env_file, capsys):
    gotrue = FakeGoTrue()
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), platform="linux") == 1
    assert gotrue.requests == []
    assert "macOS" in capsys.readouterr().err


def test_missing_key_stops_before_any_request(tmp_path, monkeypatch, capsys):
    for key in cra.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    path = tmp_path / ".env"
    path.write_text(f"SUPABASE_URL={URL}\n", encoding="utf-8")
    gotrue = FakeGoTrue()
    assert _run(path, gotrue=gotrue, security=FakeSecurity()) == 1
    assert gotrue.requests == []


@pytest.mark.parametrize("dry_run", [False, True])
def test_an_address_the_build_does_not_allowlist_is_refused_before_any_request(env_file, capsys, dry_run):
    """Ours, but not in the build: the app would show it no password field, so
    there is nothing to create — and nothing is sent, not even the lookup."""
    gotrue, security = FakeGoTrue(), FakeSecurity()
    flags = ["--email", "apple-review@cleanway.ai"] + (["--dry-run"] if dry_run else [])
    assert _run(env_file, *flags, gotrue=gotrue, security=security) == 1
    assert gotrue.requests == []
    assert security.calls == []
    err = capsys.readouterr().err
    assert "EXPO_PUBLIC_REVIEW_EMAILS" in err and "apple-review@cleanway.ai" in err


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "email",
    ["customer@gmail.com", "Customer@Gmail.com", "review@cleanway.ai.evil.com", "review@mail.cleanway.ai", "review@сleanway.ai"],
)
def test_someone_elses_account_is_never_touched(env_file, capsys, email, dry_run):
    """A real person's account (banned, say, for abuse) must never get a
    password only the founder's Keychain holds, a forced confirmation, a lifted
    ban or a sign-out everywhere: refused before any request, dry run too."""
    customer = {"id": "real-customer-uuid", "email": email.lower(), "banned_until": "2999-01-01T00:00:00Z"}
    gotrue, security = FakeGoTrue(users=[customer]), FakeSecurity()
    flags = ["--email", email] + (["--dry-run"] if dry_run else [])
    assert _run(env_file, *flags, gotrue=gotrue, security=security) == 1
    assert gotrue.requests == []
    assert security.calls == []
    assert gotrue.users == [customer]
    out = capsys.readouterr()
    assert "real-customer-uuid" not in out.out + out.err


def test_an_allowlisted_address_off_our_domain_is_still_refused(env_file, monkeypatch):
    """Belt and braces: even if the build's list ever named a personal address,
    the script writes only to @cleanway.ai."""
    monkeypatch.setattr(cra, "build_allowlist", lambda path=cra.EAS_JSON: ["me@gmail.com", cra.REVIEW_EMAIL])
    gotrue = FakeGoTrue(users=[{"id": "u-me", "email": "me@gmail.com"}])
    assert _run(env_file, "--email", "me@gmail.com", gotrue=gotrue, security=FakeSecurity()) == 1
    assert gotrue.requests == []


def test_build_allowlist_reads_the_list_as_the_app_does(tmp_path):
    """Same rule as parseReviewEmails (mobile/src/utils/review-login.ts): only
    @cleanway.ai addresses, no "$…" references, no duplicates."""
    eas = tmp_path / "eas.json"
    raw = " Review@Cleanway.AI , me@gmail.com, $EXPO_PUBLIC_X, ops@mail.cleanway.ai, review@cleanway.ai, x@notcleanway.ai, bad"
    eas.write_text(json.dumps({"build": {"production": {"env": {cra.REVIEW_EMAILS_VAR: raw}}}}), encoding="utf-8")
    assert cra.build_allowlist(eas) == ["review@cleanway.ai"]
    assert cra.build_allowlist(tmp_path / "missing.json") == []


def test_the_review_address_itself_still_runs(env_file):
    gotrue = FakeGoTrue()
    assert _run(env_file, "--email", " Review@Cleanway.AI ", gotrue=gotrue, security=FakeSecurity()) == 0
    assert gotrue.writes()[0][3]["email"] == "review@cleanway.ai"


def test_copy_hint_reads_the_keychain_without_printing():
    hint = cra.copy_command("review@cleanway.ai")
    assert hint.startswith("security find-generic-password")
    assert f"-s '{cra.KEYCHAIN_SERVICE}'" in hint
    assert "-a review@cleanway.ai" in hint
    assert hint.endswith("| tr -d '\\n' | pbcopy")


# ─── an account a reviewer deleted ────────────────────────────────
#
# DELETE /user/account (api/routers/user.py) only marks the users row and sets
# the Redis lock `deleted:{id}` for the 30-day grace; the auth user stays
# until the purge. Rotating the password alone left every API call answering
# 410 and the app showing "account on hold" to the next reviewer. The script
# restores it the way the app's button does: no Redis credentials on the Mac.

API = "https://api.cleanway.ai"  # EXPO_PUBLIC_API_URL of the production profile (pinned below)
ACCESS_TOKEN = ".".join(["eyJ" + "a" * 10, "b" * 10, "c" * 10])
REVIEW_USER = {"id": "u-1", "email": "review@cleanway.ai"}
WINDOW_CLOSED = {"detail": {"error": "The 30-day restore window has ended; the account is being deleted.",
                            "code": "restore_window_closed"}}
PARTIAL = {"detail": {"error": "Restore is partially complete — please retry in a moment.", "retry_after_seconds": 5}}
RESTORE = "/api/v1/user/account/restore"


def _ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _secrets_absent(gotrue, text):
    (password,) = set(gotrue.passwords.values())
    return password not in text and ACCESS_TOKEN not in text


def test_the_restore_goes_to_the_api_the_production_app_talks_to():
    assert cra.production_api_url() == API
    assert json.loads(cra.EAS_JSON.read_text(encoding="utf-8"))["build"]["production"]["env"][cra.API_URL_VAR] == API


def test_the_restore_path_is_the_apis_route():
    from api.main import app

    assert "post" in app.openapi()["paths"][cra.RESTORE_PATH]


def test_a_deleted_review_account_is_restored_like_the_apps_button(env_file, capsys):
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 0
    put, token, restore, logout = gotrue.writes()
    assert put[:2] == ("PUT", URL + "/auth/v1/admin/users/u-1")
    # Signed in with the password it has just set, as the app's review sign-in does.
    assert token[:2] == ("POST", URL + "/auth/v1/token?grant_type=password")
    assert token[3] == {"email": "review@cleanway.ai", "password": put[3]["password"]}
    assert token[2]["apikey"] == SECRET
    # "Restore my account", on the production API, with that session.
    assert restore[:2] == ("POST", API + RESTORE)
    assert restore[2]["Authorization"] == f"Bearer {ACCESS_TOKEN}" and restore[2]["User-Agent"]
    assert "apikey" not in restore[2]  # the server key never leaves for the API
    assert logout[:2] == ("POST", URL + "/auth/v1/logout?scope=local")
    assert logout[2]["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert gotrue.rows["u-1"] is None
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)] == put[3]["password"]
    out = capsys.readouterr()
    assert _secrets_absent(gotrue, out.out + out.err)
    assert "удаление отменено" in out.out
    for _, url, _, _ in gotrue.requests:
        assert put[3]["password"] not in url and ACCESS_TOKEN not in url


def test_a_partial_restore_is_repeated(env_file, capsys):
    """The endpoint's 503: the row is cleared, the Redis lock not yet — it
    says to retry, and repeating it is safe."""
    slept = []
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}, restore=[(503, PARTIAL)])
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), sleep=slept.append) == 0
    assert len(gotrue.calls_to(RESTORE)) == 2 and slept == [5]
    assert "удаление отменено" in capsys.readouterr().out


def test_a_restore_that_keeps_failing_points_to_the_app(env_file, capsys):
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}, restore=[(503, PARTIAL)] * 5)
    security = FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 4
    assert len(gotrue.calls_to(RESTORE)) == cra.RESTORE_ATTEMPTS
    assert len(gotrue.calls_to("/auth/v1/logout")) == 1  # signed out all the same
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)]  # the new password is kept
    err = capsys.readouterr().err
    assert "Восстановить аккаунт" in err and "503" in err
    assert _secrets_absent(gotrue, err)


def test_a_window_that_closed_meanwhile_is_reported(env_file, capsys):
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}, restore=[(410, WINDOW_CLOSED)])
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 4
    assert len(gotrue.calls_to(RESTORE)) == 1 and len(gotrue.calls_to("/auth/v1/logout")) == 1
    err = capsys.readouterr().err
    assert "30" in err and "restore_window_closed" in err


@pytest.mark.parametrize("refusal", [
    (400, {"error_code": "captcha_failed", "msg": "captcha protection: request disallowed"}),
    (429, {"error_code": "over_request_rate_limit", "msg": "Request rate limit reached"}),
])
def test_a_refused_sign_in_points_to_the_app(env_file, capsys, refusal):
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}, token_fail=refusal)
    security = FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 4
    assert gotrue.calls_to(RESTORE) == []
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)] == _passwords(gotrue)[0]
    err = capsys.readouterr().err
    assert refusal[1]["error_code"] in err and "Восстановить аккаунт" in err
    assert _passwords(gotrue)[0] not in err


def test_a_failed_sign_out_does_not_fail_the_restore(env_file, capsys):
    class NoLogout(FakeGoTrue):
        def __call__(self, method, url, headers, body):
            if "/auth/v1/logout" in url:
                self.requests.append((method, url, dict(headers), None))
                return 500, {"msg": "boom"}
            return super().__call__(method, url, headers, body)

    gotrue = NoLogout(users=[REVIEW_USER], rows={"u-1": _ago(2)})
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 0
    assert gotrue.rows["u-1"] is None
    out = capsys.readouterr()
    assert "удаление отменено" in out.out and _secrets_absent(gotrue, out.out + out.err)


def test_past_the_grace_window_nothing_is_written(env_file, capsys):
    """The purge deletes it (the auth user too); only then can a run create it anew."""
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(31)}), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 4
    assert gotrue.writes() == [] and security.calls == []
    assert "30" in capsys.readouterr().err


def test_a_deleted_account_without_the_apps_api_url_stops_before_any_write(env_file, monkeypatch, tmp_path, capsys):
    eas = tmp_path / "eas.json"
    eas.write_text(json.dumps({"build": {"production": {"env": {cra.REVIEW_EMAILS_VAR: cra.REVIEW_EMAIL}}}}),
                   encoding="utf-8")
    monkeypatch.setattr(cra, "EAS_JSON", eas)
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security) == 1
    assert gotrue.writes() == [] and security.calls == []
    assert cra.API_URL_VAR in capsys.readouterr().err


def test_a_live_account_is_only_rotated(env_file):
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": None})
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 0
    assert [w[0] for w in gotrue.writes()] == ["PUT"]


def test_a_new_account_is_not_looked_up_in_users(env_file):
    gotrue = FakeGoTrue()
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity()) == 0
    assert not any("/rest/v1/" in r[1] or "/auth/v1/token" in r[1] for r in gotrue.requests)


def test_dry_run_reports_a_pending_deletion_and_writes_nothing(env_file, capsys):
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeSecurity()
    assert _run(env_file, "--dry-run", gotrue=gotrue, security=security) == 0
    assert gotrue.writes() == [] and security.calls == []
    out = capsys.readouterr().out
    assert "помечен на удаление" in out and "Восстановить аккаунт" in out and API in out


@pytest.mark.parametrize("args,users", [((), [REVIEW_USER]), (("--dry-run",), [REVIEW_USER]), ((), [])])
def test_a_dev_redis_url_in_env_changes_nothing(env_file, args, users):
    """Review of PR #334: REDIS_URL was read from .env, and the dev value of
    .env.example (a local Redis) failed every run with a config error. The
    script needs no Redis at all now."""
    env_file.write_text(env_file.read_text(encoding="utf-8") + "REDIS_URL=redis://localhost:6379\n", encoding="utf-8")
    gotrue = FakeGoTrue(users=list(users), rows={"u-1": None})
    assert _run(env_file, *args, gotrue=gotrue, security=FakeSecurity()) == 0


def test_the_grace_window_is_the_apis():
    from api.routers import user as user_router
    from api.services import account_purge

    assert cra.GRACE_DAYS == user_router._DELETION_GRACE_DAYS == account_purge.GRACE_DAYS


@pytest.mark.parametrize(("value", "expected"), [
    ("2026-10-23T10:00:00.123456+00:00", datetime(2026, 10, 23, 10, 0, 0, 123456, timezone.utc)),
    ("2026-10-23T10:00:00.12+00:00", datetime(2026, 10, 23, 10, 0, 0, 120000, timezone.utc)),
    ("2026-10-23 14:00:00+04", datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)),
    ("2026-10-23T10:00:00Z", datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)),
    ("2026-10-23T10:00:00", datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)),
    ("not a date", None),
])
def test_postgres_timestamps_parse_on_any_python(value, expected):
    assert cra.parse_timestamp(value) == expected
