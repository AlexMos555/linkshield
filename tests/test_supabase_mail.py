"""scripts/supabase_mail.py — the Supabase Auth mail wiring (SMTP, templates, DNS).

The script is the founder's one-shot path from "2 emails per hour" to a
working sign-in, so what it decides is pinned here: provider presets, that a
dry run never writes, that the password is re-sent whenever anything else
changes and never printed, that the shipped templates carry the code and no
link, and that the DNS checklist matches the live records we measured.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "supabase_mail.py"


def _load() -> ModuleType:
    name = "supabase_mail"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sm = _load()

TOKEN = "sbp_test_token"
PASS = "app-password-xyz"


def _env(**over: str) -> dict[str, str]:
    base = {"SUPABASE_ACCESS_TOKEN": TOKEN, "SMTP_PASS": PASS}
    base.update(over)
    return base


# ─── presets ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("provider", "env", "host", "port", "user"),
    [
        ("yandex", {}, "smtp.yandex.ru", "465", "no-reply@cleanway.ai"),
        ("yandex", {"SMTP_SENDER": "hello@cleanway.ai"}, "smtp.yandex.ru", "465", "hello@cleanway.ai"),
        ("yandex", {"SMTP_USER": "robot@cleanway.ai", "SMTP_PORT": "587"}, "smtp.yandex.ru", "587", "robot@cleanway.ai"),
        ("resend", {}, "smtp.resend.com", "465", "resend"),
        ("custom", {"SMTP_HOST": "mail.example.ru", "SMTP_PORT": "2525", "SMTP_USER": "u"}, "mail.example.ru", "2525", "u"),
    ],
)
def test_presets_fill_what_env_leaves_blank(provider, env, host, port, user):
    s = sm.resolve_smtp(provider, _env(**env))
    assert (s.host, s.port, s.user, s.password) == (host, port, user, PASS)
    assert s.sender_name == "Cleanway"
    assert s.rate_limit_per_hour == 200
    assert s.min_interval_s == 60


def test_resend_accepts_the_legacy_key_name():
    env = {"SUPABASE_ACCESS_TOKEN": TOKEN, "RESEND_API_KEY": "re_123"}
    assert sm.resolve_smtp("resend", env).password == "re_123"


@pytest.mark.parametrize(
    ("provider", "env", "needle"),
    [
        ("yandex", {"SMTP_PASS": ""}, "SMTP_PASS is empty"),
        ("yandex", {"SMTP_SENDER": "not-an-email"}, "SMTP_SENDER"),
        ("yandex", {"SMTP_PORT": "ssl"}, "SMTP_PORT"),
        ("yandex", {"SMTP_RATE_LIMIT": "0"}, "SMTP_RATE_LIMIT"),
        ("yandex", {"SMTP_MIN_INTERVAL": "soon"}, "SMTP_MIN_INTERVAL"),
        ("custom", {}, "SMTP_HOST and SMTP_PORT"),
        ("custom", {"SMTP_HOST": "h", "SMTP_PORT": "25"}, "SMTP_USER"),
        ("sendgrid", {}, "unknown provider"),
    ],
)
def test_config_errors_name_the_variable(provider, env, needle):
    with pytest.raises(sm.ConfigError, match=needle):
        sm.resolve_smtp(provider, _env(**env))


def test_warnings_catch_yandex_login_sender_mismatch_and_slow_interval():
    s = sm.resolve_smtp("yandex", _env(SMTP_USER="robot@cleanway.ai", SMTP_MIN_INTERVAL="120"))
    warnings = sm.smtp_warnings(s)
    assert any("From" in w for w in warnings)
    assert any("62" in w for w in warnings)
    assert sm.smtp_warnings(sm.resolve_smtp("yandex", _env())) == []


# ─── desired config + diff ────────────────────────────────────────


def test_desired_config_pins_port_as_string_and_otp_contract():
    body = sm.smtp_desired_config(sm.resolve_smtp("yandex", _env()))
    assert body["smtp_port"] == "465" and isinstance(body["smtp_port"], str)
    assert body["mailer_otp_length"] == 6
    assert body["mailer_otp_exp"] == 3600
    assert body["external_email_enabled"] is True
    assert body["smtp_pass"] == PASS


def _live(**over):
    base = {
        "external_email_enabled": True,
        "smtp_host": "smtp.yandex.ru",
        "smtp_port": 465,  # the API has returned an int here; compare as text
        "smtp_user": "no-reply@cleanway.ai",
        "smtp_pass": "whatever-the-api-echoes",
        "smtp_admin_email": "no-reply@cleanway.ai",
        "smtp_sender_name": "Cleanway",
        "smtp_max_frequency": 60,
        "rate_limit_email_sent": 200,
        "mailer_otp_length": 6,
        "mailer_otp_exp": 3600,
    }
    base.update(over)
    return base


def test_identical_config_is_a_noop_and_never_compares_the_secret():
    desired = sm.smtp_desired_config(sm.resolve_smtp("yandex", _env()))
    assert sm.config_changes(_live(), desired) == {}


def test_any_change_resends_the_password_alongside():
    desired = sm.smtp_desired_config(sm.resolve_smtp("yandex", _env()))
    changes = sm.config_changes(_live(rate_limit_email_sent=30), desired)
    assert changes == {"rate_limit_email_sent": 200, "smtp_pass": PASS}


def test_force_sends_only_the_password_when_nothing_else_differs():
    desired = sm.smtp_desired_config(sm.resolve_smtp("yandex", _env()))
    assert sm.config_changes(_live(), desired, force=True) == {"smtp_pass": PASS}


def test_first_wiring_from_builtin_mailer_sends_everything():
    desired = sm.smtp_desired_config(sm.resolve_smtp("yandex", _env()))
    changes = sm.config_changes({"smtp_host": None, "rate_limit_email_sent": 2}, desired)
    assert changes == desired


def test_redact_hides_secret_values_but_keeps_presence():
    shown = sm.redact({"smtp_pass": PASS, "security_captcha_secret": "", "smtp_host": "h"})
    assert shown == {"smtp_pass": "(set)", "security_captcha_secret": "(empty)", "smtp_host": "h"}
    assert PASS not in json.dumps(shown)


def test_api_error_text_is_scrubbed_of_the_secret():
    assert sm._scrub(f"bad password {PASS}", {"smtp_pass": PASS}) == "bad password (secret)"


# ─── templates ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kind", "subject", "html", "needle"),
    [
        ("magic_link", "Код", "<p>no code</p>", "{{ .Token }}"),
        ("magic_link", "Код", "<p>{{ .Token }} <a href='{{ .ConfirmationURL }}'>x</a></p>", "no {{ .ConfirmationURL }}"),
        ("confirmation", "", "<p>{{ .Token }}</p>", "empty subject"),
        ("confirmation", "two\nlines", "<p>{{ .Token }}</p>", "one line"),
        ("recovery", "x", "<p>{{ .Token }}</p>", "needs {{ .ConfirmationURL }}"),
        ("email_change", "x", "<a href='http://cleanway.ai'>{{ .ConfirmationURL }}</a>", "http://"),
    ],
)
def test_template_rules(kind, subject, html, needle):
    assert any(needle in p for p in sm.validate_template(kind, subject, html))


@pytest.mark.parametrize(
    ("kind", "html"),
    [
        ("magic_link", "<p>{{ .Token }}</p>"),
        ("confirmation", "<p>{{ .Token }}</p>"),
        ("recovery", "<a href='{{ .ConfirmationURL }}'>go</a>"),
        ("email_change", "<a href='{{ .ConfirmationURL }}'>{{ .NewEmail }}</a>"),
    ],
)
def test_template_rules_accept_valid(kind, html):
    assert sm.validate_template(kind, "Тема", html) == []


def test_shipped_templates_load_and_follow_the_rules():
    fields = sm.load_templates()
    assert set(fields) == {
        f"mailer_subjects_{k}" for k in sm.TEMPLATE_TYPES
    } | {f"mailer_templates_{k}_content" for k in sm.TEMPLATE_TYPES}
    for kind in ("magic_link", "confirmation"):
        html = fields[f"mailer_templates_{kind}_content"]
        assert "{{ .Token }}" in html
        assert "<a " not in html, "code emails carry no links or buttons"
        assert "Никому не сообщайте" in html
        assert "1 час" in html
        assert "Спам" not in html  # the spam hint lives in the app/site, not in mail that may not arrive
    assert all("\n" not in fields[f"mailer_subjects_{k}"] for k in sm.TEMPLATE_TYPES)


def test_shipped_text_versions_mirror_the_html_variables():
    for kind in sm.TEMPLATE_TYPES:
        html = (sm.TEMPLATES_DIR / f"{kind}.html").read_text(encoding="utf-8")
        text = (sm.TEMPLATES_DIR / f"{kind}.txt").read_text(encoding="utf-8")
        for var in ("{{ .Token }}", "{{ .ConfirmationURL }}", "{{ .Email }}", "{{ .NewEmail }}"):
            assert (var in html) == (var in text), (kind, var)


def test_missing_template_file_is_a_config_error(tmp_path):
    with pytest.raises(sm.ConfigError, match="missing"):
        sm.load_templates(tmp_path)


# ─── DNS ──────────────────────────────────────────────────────────


def test_yandex_records_replace_the_apex_spf_and_mx_is_optional_unless_asked():
    recs = {(r.rtype, r.name): r for r in sm.dns_records("yandex")}
    spf = recs[("TXT", "cleanway.ai")]
    assert spf.value == "v=spf1 include:_spf.yandex.net -all" or any(
        r.value == "v=spf1 include:_spf.yandex.net -all" for r in sm.dns_records("yandex")
    )
    mx = recs[("MX", "cleanway.ai")]
    assert mx.value == "mx.yandex.net." and mx.priority == 10 and mx.required is False
    assert recs[("TXT", "mail._domainkey.cleanway.ai")].required is True
    assert {r for r in sm.dns_records("yandex", with_mx=True) if r.rtype == "MX"}.pop().required is True


def test_resend_records_use_the_send_subdomain_and_region():
    recs = sm.dns_records("resend", resend_region="eu-west-1")
    by = {(r.rtype, r.name): r for r in recs}
    assert by[("MX", "send.cleanway.ai")].value == "feedback-smtp.eu-west-1.amazonses.com"
    assert by[("TXT", "send.cleanway.ai")].value == "v=spf1 include:amazonses.com ~all"
    assert by[("TXT", "resend._domainkey.cleanway.ai")].needle == "p="
    assert ("MX", "cleanway.ai") not in by  # Resend hosts no inboxes; only with --with-mx
    assert by[("TXT", "_dmarc.cleanway.ai")].required is False


def test_dns_check_matches_live_shapes():
    live = {
        ("cleanway.ai", "TXT"): ['"v=spf1 include:_spf.yandex.net -all"', '"yandex-verification: abc123"'],
        ("mail._domainkey.cleanway.ai", "TXT"): ['"v=DKIM1; k=rsa; " "p=MIIB..."'],
        ("cleanway.ai", "MX"): ["10 mx.yandex.net."],
        ("_dmarc.cleanway.ai", "TXT"): ['"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"'],
    }
    results = sm.check_dns(sm.dns_records("yandex", with_mx=True), resolve=lambda n, t: live.get((n, t), []))
    assert all(found for _, found in results)


def test_dns_check_reports_the_measured_2026_10_04_state():
    live = {
        ("cleanway.ai", "TXT"): ["v=spf1 -all"],
        ("_dmarc.cleanway.ai", "TXT"): ["v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"],
    }
    results = dict((r.name + "/" + r.rtype, found) for r, found in sm.check_dns(sm.dns_records("yandex"), resolve=lambda n, t: live.get((n, t), [])))
    assert results["mail._domainkey.cleanway.ai/TXT"] is False
    assert results["_dmarc.cleanway.ai/TXT"] is True
    assert results["cleanway.ai/MX"] is False


# ─── environment ──────────────────────────────────────────────────


def test_env_file_reader_handles_quotes_comments_and_export(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\n\nSUPABASE_ACCESS_TOKEN=\"sbp_x\"\nexport SMTP_PASS='p w'\nSMTP_SENDER=a@b.ru\nBROKEN LINE\n",
        encoding="utf-8",
    )
    assert sm.read_env_file(env_file) == {"SUPABASE_ACCESS_TOKEN": "sbp_x", "SMTP_PASS": "p w", "SMTP_SENDER": "a@b.ru"}
    assert sm.read_env_file(tmp_path / "absent") == {}


def test_process_env_wins_and_only_known_keys_pass():
    merged = sm.merged_env({"SMTP_PASS": "from-shell", "HOME": "/x"}, {"SMTP_PASS": "from-file", "SMTP_SENDER": "a@b.ru", "FOO": "1"})
    assert merged == {"SMTP_PASS": "from-shell", "SMTP_SENDER": "a@b.ru"}


# ─── verify ───────────────────────────────────────────────────────


def _templates_with_token():
    return {f"mailer_templates_{k}_content": "<p>{{ .Token }}</p>" for k in ("magic_link", "confirmation")}


@pytest.mark.parametrize(
    ("config", "ok"),
    [
        ({"smtp_host": None, "rate_limit_email_sent": 2}, False),
        ({**_live(), **_templates_with_token()}, True),
        ({**_live(mailer_otp_length=8), **_templates_with_token()}, False),
        ({**_live(mailer_otp_exp=86400), **_templates_with_token()}, False),
        ({**_live(), "mailer_templates_magic_link_content": "<p>link only</p>"}, False),
        ({**_live(rate_limit_email_sent=2), **_templates_with_token()}, False),
    ],
)
def test_verify_report_verdict(config, ok):
    verdict, lines = sm.verify_report(config)
    assert verdict is ok
    assert not any("whatever-the-api-echoes" in line for line in lines)


# ─── CLI: dry run never writes, --apply writes the diff ───────────


class _FakeApi:
    """Stands in for the Management API; state lives on the class so it
    survives across main() invocations within one test, like the real project."""

    calls: list = []
    state: dict = {}

    def __init__(self, token, project_ref):
        assert token == TOKEN
        self.project_ref = project_ref

    def get(self):
        return dict(_FakeApi.state)

    def patch(self, body):
        _FakeApi.calls.append(dict(body))
        _FakeApi.state.update(body)
        return dict(_FakeApi.state)


@pytest.fixture
def fake_api(monkeypatch, tmp_path):
    _FakeApi.calls = []
    _FakeApi.state = {"smtp_host": None, "rate_limit_email_sent": 2, "mailer_otp_length": 6, "mailer_otp_exp": 3600}
    monkeypatch.setattr(sm, "ManagementApi", _FakeApi)
    env_file = tmp_path / ".env"
    env_file.write_text(f"SUPABASE_ACCESS_TOKEN={TOKEN}\nSMTP_PASS={PASS}\n", encoding="utf-8")
    for key in sm.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    return env_file


def test_dry_run_reads_but_never_patches(fake_api, capsys):
    assert sm.main(["--env-file", str(fake_api)]) == 1  # verify says NOT ready — nothing was written
    assert _FakeApi.calls == []
    out = capsys.readouterr().out
    assert "dry run" in out
    assert PASS not in out and TOKEN not in out


def test_apply_writes_smtp_then_templates_and_ends_green(fake_api, capsys):
    assert sm.main(["--apply", "--env-file", str(fake_api)]) == 0
    assert len(_FakeApi.calls) == 2
    smtp_call, template_call = _FakeApi.calls
    assert smtp_call["smtp_host"] == "smtp.yandex.ru" and smtp_call["smtp_pass"] == PASS
    assert smtp_call["smtp_port"] == "465"
    assert "{{ .Token }}" in template_call["mailer_templates_magic_link_content"]
    out = capsys.readouterr().out
    assert "sign-in can scale" in out
    assert PASS not in out


def test_second_apply_is_a_noop(fake_api, capsys):
    assert sm.main(["--apply", "--env-file", str(fake_api)]) == 0
    first = len(_FakeApi.calls)
    assert sm.main(["--apply", "--env-file", str(fake_api)]) == 0
    assert len(_FakeApi.calls) == first
    assert "nothing to change" in capsys.readouterr().out


def test_missing_password_is_exit_1_before_any_network(fake_api, monkeypatch, capsys):
    fake_api.write_text(f"SUPABASE_ACCESS_TOKEN={TOKEN}\n", encoding="utf-8")
    assert sm.main(["--step", "smtp", "--env-file", str(fake_api)]) == 1
    assert _FakeApi.calls == []
    assert "SMTP_PASS" in capsys.readouterr().err


def test_dns_step_needs_no_token(monkeypatch, tmp_path, capsys):
    for key in sm.ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    assert sm.main(["--step", "dns", "--provider", "resend", "--env-file", str(tmp_path / "none")]) == 0
    assert "send.cleanway.ai" in capsys.readouterr().out
