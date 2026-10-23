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
backend reads.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import string
import sys
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
    """GoTrue admin API stand-in: a user table and a request log."""

    def __init__(self, users=None, fail=None):
        self.users = list(users or [])
        self.requests = []
        self.fail = fail  # (method, status, body) to answer instead

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
        return 404, {"msg": "not found"}

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


def _run(env_file, *args, gotrue, security, platform="darwin"):
    return cra.main(["--env-file", str(env_file), *args], transport=gotrue, run=security, platform=platform)


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
    assert [r[0] for r in gotrue.requests].count("GET") == 3
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
