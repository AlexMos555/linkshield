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
is restored the way POST /user/account/restore does it — the users row and
the API's Redis lock — or the run stops before writing anything.
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
    PostgREST `users` table: id → deletion_requested_at (None: not deleted)."""

    def __init__(self, users=None, fail=None, rows=None):
        self.users = list(users or [])
        self.requests = []
        self.fail = fail  # (method, status, body) to answer instead
        self.rows = dict(rows or {})

    def __call__(self, method, url, headers, body):
        data = json.loads(body) if body else None
        self.requests.append((method, url, dict(headers), data))
        if self.fail and self.fail[0] == method:
            return self.fail[1], self.fail[2]
        path = url[len(URL):]
        if method == "GET" and path.startswith("/auth/v1/admin/users?"):
            query = dict(p.split("=") for p in path.split("?", 1)[1].split("&"))
            page, per_page = int(query["page"]), int(query["per_page"])
            chunk = self.users[(page - 1) * per_page: page * per_page]
            return 200, {"users": chunk, "aud": "authenticated"}
        if method == "POST" and path == "/auth/v1/admin/users":
            user = {"id": f"id-{len(self.users) + 1}", "email": data["email"]}
            self.users.append(user)
            return 200, user
        if method == "PUT" and path.startswith("/auth/v1/admin/users/"):
            return 200, {"id": path.rsplit("/", 1)[1]}
        if path.startswith("/rest/v1/users?"):
            return self._users_table(method, _query(url), data)
        return 404, {"msg": "not found"}

    def _users_table(self, method, query, data):
        uid = query["id"].removeprefix("eq.")
        if method == "GET":
            return 200, [{"deletion_requested_at": self.rows[uid]}] if uid in self.rows else []
        if method == "PATCH":
            # The restore's own guard: only a deletion still inside the window.
            cutoff = datetime.fromisoformat(query["or"].split('gt."', 1)[1].rstrip('")'))
            if uid not in self.rows or (self.rows[uid] and datetime.fromisoformat(self.rows[uid]) <= cutoff):
                return 200, []
            self.rows[uid] = data["deletion_requested_at"]
            return 200, [{"id": uid}]
        return 405, {"msg": "method not allowed"}

    def writes(self):
        return [r for r in self.requests if r[0] != "GET"]


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


class FakeRedis:
    """The API's Redis stand-in (sync, like redis-py), and the factory the
    script calls with REDIS_URL."""

    def __init__(self, keys=(), down=False):
        self.store = dict.fromkeys(keys, "1")
        self.down = down
        self.urls = []
        self.calls = []

    def __call__(self, url):
        self.urls.append(url)
        return self

    def ping(self):
        self.calls.append(("ping",))
        if self.down:
            raise ConnectionRefusedError(61, "Connection refused")
        return True

    def delete(self, *keys):
        self.calls.append(("delete", *keys))
        if self.down:
            raise ConnectionRefusedError(61, "Connection refused")
        return sum(self.store.pop(k, None) is not None for k in keys)


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


def _run(env_file, *args, gotrue, security, platform="darwin", redis=None):
    return cra.main(["--env-file", str(env_file), *args], transport=gotrue, run=security, platform=platform,
                    redis_factory=redis or FakeRedis())


def _passwords(gotrue):
    return [r[3]["password"] for r in gotrue.writes()]


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
# 410 and the app showing "account on hold" to the next reviewer.

REDIS_PASSWORD = "q" * 12
REDIS_URL = f"redis://default:{REDIS_PASSWORD}@proxy.example.net:6379"
REVIEW_USER = {"id": "u-1", "email": "review@cleanway.ai"}


def _ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _with_redis(env_file, url=REDIS_URL):
    env_file.write_text(env_file.read_text(encoding="utf-8") + f"REDIS_URL={url}\n", encoding="utf-8")


def test_a_deleted_review_account_is_restored_with_the_rotation(env_file, capsys):
    _with_redis(env_file)
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)})
    redis = FakeRedis(keys=["deleted:u-1", "notdeleted:u-1", "tier:u-1", "deleted:someone-else"])
    security = FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security, redis=redis) == 0
    put, patch = gotrue.writes()
    assert put[:2] == ("PUT", URL + "/auth/v1/admin/users/u-1")
    # What POST /user/account/restore sends: the row, pinned to the grace window.
    assert patch[0] == "PATCH" and patch[3] == {"deletion_requested_at": None}
    query = _query(patch[1])
    assert query["id"] == "eq.u-1" and query["select"] == "id"
    assert query["or"].startswith("(deletion_requested_at.is.null,deletion_requested_at.gt.")
    assert patch[2]["apikey"] == SECRET and patch[2]["Prefer"] == "return=representation"
    assert gotrue.rows["u-1"] is None
    assert redis.urls == [REDIS_URL]
    assert redis.store == {"deleted:someone-else": "1"}  # the lock and its caches, nobody else's
    assert security.items[("review@cleanway.ai", cra.KEYCHAIN_SERVICE)] == put[3]["password"]
    out = capsys.readouterr()
    assert put[3]["password"] not in out.out + out.err
    assert REDIS_PASSWORD not in out.out + out.err
    assert "удаление отменено" in out.out


def test_a_deleted_account_without_the_apis_redis_stops_before_any_write(env_file, capsys):
    gotrue, redis, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeRedis(), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security, redis=redis) == 1
    assert gotrue.writes() == [] and security.calls == [] and redis.calls == []
    assert gotrue.rows["u-1"] is not None  # still there for the next run to find
    err = capsys.readouterr().err
    assert "REDIS_URL" in err and "Восстановить аккаунт" in err


def test_an_unreachable_redis_stops_before_any_write(env_file, capsys):
    _with_redis(env_file)
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security, redis=FakeRedis(down=True)) == 4
    assert gotrue.writes() == [] and security.calls == []
    err = capsys.readouterr().err
    assert "ConnectionRefusedError" in err and "proxy.example.net" in err
    assert REDIS_PASSWORD not in err


def test_past_the_grace_window_nothing_is_written(env_file, capsys):
    """The purge deletes it (the auth user too); only then can a run create it anew."""
    _with_redis(env_file)
    gotrue, redis, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(31)}), FakeRedis(), FakeSecurity()
    assert _run(env_file, gotrue=gotrue, security=security, redis=redis) == 4
    assert gotrue.writes() == [] and security.calls == [] and redis.calls == []
    assert "30" in capsys.readouterr().err


def test_a_window_that_closes_mid_run_leaves_the_lock_alone(env_file):
    """The row's guard decides, as in the restore endpoint: no row back, no
    Redis change — the purge has the account."""
    class Closing(FakeGoTrue):
        def _users_table(self, method, query, data):
            if method == "PATCH":
                return 200, []
            return super()._users_table(method, query, data)

    _with_redis(env_file)
    gotrue, redis = Closing(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeRedis(keys=["deleted:u-1"])
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), redis=redis) == 4
    assert redis.store == {"deleted:u-1": "1"}


def test_a_live_account_needs_no_redis(env_file):
    gotrue, redis = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": None}), FakeRedis()
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), redis=redis) == 0
    assert [w[0] for w in gotrue.writes()] == ["PUT"]
    assert redis.calls == []


def test_with_redis_a_lock_left_on_a_live_row_is_cleared(env_file):
    """A restore that cleared the row but not the lock (its 503 path) still
    answers 410; the run clears the lock without touching the row."""
    _with_redis(env_file)
    gotrue, redis = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": None}), FakeRedis(keys=["deleted:u-1"])
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), redis=redis) == 0
    assert [w[0] for w in gotrue.writes()] == ["PUT"]
    assert redis.store == {}


def test_dry_run_reports_a_pending_deletion_and_writes_nothing(env_file, capsys):
    gotrue, redis, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeRedis(), FakeSecurity()
    assert _run(env_file, "--dry-run", gotrue=gotrue, security=security, redis=redis) == 0
    assert gotrue.writes() == [] and security.calls == [] and redis.calls == []
    out = capsys.readouterr().out
    assert "помечен на удаление" in out and "REDIS_URL" in out


@pytest.mark.parametrize("url", [
    f"redis://:{REDIS_PASSWORD}@localhost:6379",
    "redis://127.0.0.1:6379/0",
    f"redis://default:{REDIS_PASSWORD}@redis.railway.internal:6379",
    f"https://default:{REDIS_PASSWORD}@proxy.example.net:6379",
])
def test_a_redis_url_that_cannot_be_the_apis_is_refused_before_any_request(env_file, capsys, url):
    """A local Redis would "clear" nothing while the production lock stays."""
    _with_redis(env_file, url)
    gotrue = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)})
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), redis=FakeRedis()) == 1
    assert gotrue.requests == []
    err = capsys.readouterr().err
    assert "REDIS_URL" in err and REDIS_PASSWORD not in err


def test_a_new_account_never_asks_redis(env_file):
    _with_redis(env_file)
    gotrue, redis = FakeGoTrue(), FakeRedis()
    assert _run(env_file, gotrue=gotrue, security=FakeSecurity(), redis=redis) == 0
    assert redis.calls == [] and not any("/rest/v1/" in r[1] for r in gotrue.requests)


def test_the_grace_window_and_the_lock_are_the_apis():
    import inspect

    from api.routers import user as user_router
    from api.services import account_purge

    assert cra.GRACE_DAYS == user_router._DELETION_GRACE_DAYS == account_purge.GRACE_DAYS
    written = inspect.getsource(user_router.delete_account) + inspect.getsource(user_router.restore_account)
    for key in cra.LOCK_KEYS:
        assert f'"{key.replace("{id}", "{user.id}")}"' in written, key


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


class _RespServer:
    """A Redis stand-in on 127.0.0.1 that speaks the protocol: it logs each
    command and answers like Redis (AUTH with the password only)."""

    def __init__(self, password="pw"):
        import socket
        import threading

        self.password, self.commands = password, []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        conn, _ = self._listener.accept()
        reader = conn.makefile("rb")
        authed = not self.password
        while True:
            head = reader.readline()
            if not head:
                break
            args = []
            for _ in range(int(head[1:-2])):
                size = int(reader.readline()[1:-2])
                args.append(reader.read(size + 2)[:-2].decode())
            self.commands.append(args)
            name = args[0].upper()
            if name == "AUTH":
                authed = args[-1] == self.password
                conn.sendall(b"+OK\r\n" if authed else b"-WRONGPASS invalid username-password pair\r\n")
            elif not authed:
                conn.sendall(b"-NOAUTH Authentication required.\r\n")
            elif name in ("PING", "SELECT"):
                conn.sendall(b"+PONG\r\n" if name == "PING" else b"+OK\r\n")
            elif name == "DEL":
                conn.sendall(b":%d\r\n" % (len(args) - 1))
        reader.close()
        conn.close()

    def close(self):
        self._listener.close()
        self._thread.join(2)


def test_the_resp_client_authenticates_selects_pings_and_deletes():
    server = _RespServer(password="pw")
    client = cra.open_redis(f"redis://default:pw@127.0.0.1:{server.port}/2")
    try:
        assert client.ping() == "PONG"
        assert client.delete("deleted:u-1", "notdeleted:u-1", "tier:u-1") == 3
    finally:
        client.close()
        server.close()
    assert server.commands == [["AUTH", "pw"], ["SELECT", "2"], ["PING"],
                               ["DEL", "deleted:u-1", "notdeleted:u-1", "tier:u-1"]]


def test_a_wrong_redis_password_is_named_by_its_code_only(env_file, capsys):
    server = _RespServer(password="right")
    wrong = "w" * 12
    _with_redis(env_file, f"redis://default:{wrong}@proxy.example.net:6379")
    gotrue, security = FakeGoTrue(users=[REVIEW_USER], rows={"u-1": _ago(2)}), FakeSecurity()
    local = f"redis://default:{wrong}@127.0.0.1:{server.port}"
    try:
        code = _run(env_file, gotrue=gotrue, security=security, redis=lambda _url: cra.open_redis(local))
    finally:
        server.close()
    assert code == 4 and gotrue.writes() == [] and security.calls == []
    err = capsys.readouterr().err
    assert "RespError WRONGPASS" in err and wrong not in err
