"""Security anomaly alerts: count security events, email the founder once.

Call sites on the request path report an event:

    from api.services import security_alerts
    await security_alerts.record("user_export", key=user.id)

Each event has one or more rules (`RULES`): a threshold inside a fixed window,
either for the whole service or per key (a user, a rate-limit category, a
webhook provider). The counter is one atomic INCR (+ EXPIRE on first write)
per rule in Redis, shared by every replica. The caller that takes a counter
to exactly its threshold tries a cooldown lock (SET NX EX); whoever gets the
lock sends the alert, so two replicas never both email and a sustained attack
emails at most once per cooldown.

Delivery: always a CRITICAL log line (`security_alert ...`, also picked up by
Sentry), plus an email to SECURITY_ALERT_EMAIL from alerts@cleanway.ai
through Resend (RESEND_API_KEY) — sent in the background, never awaited by
the request.

Guarantees: record() never raises into the request (Redis down, slow or
failing is logged and ignored), costs one Redis round trip per rule, and
keeps no personal data: user ids are HMAC-hashed before they reach Redis or
the alert. What each alert means: docs/runbooks/security-incident.md.

Environment:
  SECURITY_ALERT_EMAIL                     recipient; unset = log only
  SECURITY_ALERT_FROM                      default alerts@cleanway.ai
  SECURITY_ALERTS_ENABLED                  "false" turns counting off
  SECURITY_ALERT_THRESHOLD_<EVENT>         service-wide threshold (0 = off)
  SECURITY_ALERT_THRESHOLD_<EVENT>_PER_KEY per-key threshold (0 = off)
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, replace
from typing import Optional

logger = logging.getLogger("cleanway.security_alerts")

RUNBOOK = "https://github.com/AlexMos555/linkshield/blob/main/docs/runbooks/security-incident.md"
REDIS_TIMEOUT_S = 0.5
_FIVE_MIN = 300
_HOUR = 3600
_DAY = 86400


@dataclass(frozen=True)
class Rule:
    threshold: int
    window_s: int = _FIVE_MIN
    per_key: bool = False
    # Public keys (a rate-limit category, a webhook provider) are shown as
    # they are; anything else (user ids) is hashed.
    public_key: bool = False
    cooldown_s: int = _HOUR


RULES: dict[str, tuple[Rule, ...]] = {
    "auth_invalid_token": (Rule(200),),
    "reauth_required": (Rule(50), Rule(10, window_s=_HOUR, per_key=True)),
    "user_export": (Rule(20), Rule(4, window_s=_HOUR, per_key=True)),
    "account_delete": (Rule(5),),
    "webhook_signature_invalid": (Rule(5, per_key=True, public_key=True),),
    "ssrf_blocked": (Rule(50),),
    "paid_budget_exhausted": (
        Rule(1, window_s=_DAY, per_key=True, public_key=True, cooldown_s=_DAY),
    ),
    "rate_limited": (Rule(1000, per_key=True, public_key=True),),
    "admin_or_service_key_use": (Rule(30), Rule(5, window_s=_HOUR, per_key=True)),
    # Not an attack but money: a payment the provider keeps retrying that
    # never reaches the account. The first failure per provider is an email,
    # then at most one an hour while the retries keep failing.
    "webhook_processing_failed": (
        Rule(1, window_s=_HOUR, per_key=True, public_key=True, cooldown_s=_HOUR),
    ),
}

# (what it means, what to check) — the email body, in the founder's language.
EVENT_INFO: dict[str, tuple[str, str]] = {
    "auth_invalid_token": (
        "Много запросов с поддельными или битыми токенами входа (JWT).",
        "Перебор токенов или утёкший/подделанный ключ. Посмотрите логи jwt_invalid / "
        "jwt_unknown_signing_key / jwt_algorithm_refused в Railway: с каких путей идут запросы.",
    ),
    "reauth_required": (
        "Много попыток опасных действий (удаление аккаунта, сессия расширения) со старым токеном.",
        "Кто-то со старым (возможно украденным) токеном пытается удалить аккаунт или открыть "
        "сессию. Проверьте audit_log и при необходимости завершите сессии пользователя в Supabase.",
    ),
    "user_export": (
        "Необычно много выгрузок данных пользователей (/user/export).",
        "Массовая выгрузка — признак захвата аккаунтов. Сверьте audit_log и логи Railway; "
        "при подозрении завершите сессии затронутых пользователей в Supabase.",
    ),
    "account_delete": (
        "Необычно много удалений аккаунтов.",
        "Захваченные аккаунты могут удаляться массово. Проверьте audit_log "
        "(account.delete_requested); у пользователей есть 30 дней на восстановление.",
    ),
    "webhook_signature_invalid": (
        "Вебхуки платёжного провайдера приходят с неверной подписью.",
        "Подделка вебхуков или сменился секрет у провайдера. Сверьте секрет в Railway с "
        "дашбордом Stripe / RevenueCat / партнёра; если секрет мог утечь — перевыпустите.",
    ),
    "ssrf_blocked": (
        "Много попыток заставить сервер ходить во внутреннюю сеть (SSRF).",
        "Кто-то прощупывает внутренние адреса (Railway, metadata). Блокировка сработала; "
        "проверьте логи «SSRF attempt blocked» и redirect_hop_blocked; блок источника — "
        "раздел «Остановить или прикрыть API» в runbook.",
    ),
    "paid_budget_exhausted": (
        "Дневной бюджет платного источника (IPQS / LLM) исчерпан.",
        "Кто-то сжигает платные проверки, или просто вырос трафик. Посмотрите логи "
        "paid_budget_exhausted и ip_rate_limit_exceeded; бюджет обнулится в полночь UTC.",
    ),
    "rate_limited": (
        "Всплеск отказов по лимиту запросов (429) в одной категории.",
        "Скорее всего бот или DDoS. Посмотрите логи ip_rate_limit_exceeded в Railway; "
        "при длительной атаке — раздел «Остановить или прикрыть API» в runbook.",
    ),
    "webhook_processing_failed": (
        "Платёжный вебхук пришёл с верной подписью, но мы не смогли его обработать.",
        "Оплата или отмена не дошла до аккаунта; провайдер будет повторять доставку. Посмотрите "
        "в логах Railway webhook_processing_failed (Stripe) или revenuecat_webhook_failed: поле "
        "error. Чаще всего недоступна база (Supabase) или ключ — проверьте /health/deep. Когда "
        "причина устранена, повтор провайдера применит событие сам; в RevenueCat можно нажать Retry.",
    ),
    "admin_or_service_key_use": (
        "Сервисный ключ Supabase часто используется от имени запросов (выпуск сессий расширения).",
        "Возможен захват аккаунта для получения долгоживущей сессии. Проверьте логи "
        "extension_session_*; при подозрении завершите сессии пользователя в Supabase.",
    ),
}


@dataclass(frozen=True)
class Alert:
    event: str
    count: int
    threshold: int
    window_s: int
    per_key: bool
    key_label: Optional[str]


# ─── configuration ───────────────────────────────────────────────


def _enabled() -> bool:
    return os.environ.get("SECURITY_ALERTS_ENABLED", "true").strip().lower() not in ("0", "false", "no", "off")


def _env_threshold(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(int(raw), 0)
    except ValueError:
        logger.warning("security_alert_threshold_invalid name=%s", name)
        return default


def rules_for(event: str) -> tuple[Rule, ...]:
    """The rules for `event` with environment overrides applied."""
    out = []
    for rule in RULES.get(event, ()):
        env = f"SECURITY_ALERT_THRESHOLD_{event.upper()}" + ("_PER_KEY" if rule.per_key else "")
        out.append(replace(rule, threshold=_env_threshold(env, rule.threshold)))
    return tuple(out)


# ─── keys ────────────────────────────────────────────────────────


def _key_label(rule: Rule, key: Optional[str]) -> Optional[str]:
    if not rule.per_key or key is None:
        return None
    if rule.public_key:
        return str(key)[:64]
    from api.services.audit_log import hash_ip  # HMAC with the audit key

    return hash_ip(str(key))


def _suffix(rule: Rule, label: Optional[str]) -> str:
    scope = f"k{rule.window_s}" if rule.per_key else f"all{rule.window_s}"
    return f"{scope}:{label}" if label else scope


def counter_key(event: str, rule: Rule, label: Optional[str]) -> str:
    return f"secalert:n:{event}:{_suffix(rule, label)}"


def lock_key(event: str, rule: Rule, label: Optional[str]) -> str:
    return f"secalert:lock:{event}:{_suffix(rule, label)}"


# ─── recording ───────────────────────────────────────────────────

_last_unavailable_log = 0.0


def _log_unavailable(event: str, exc: BaseException) -> None:
    # At most once a minute per process: with Redis down every request
    # would otherwise add a line.
    global _last_unavailable_log
    now = time.monotonic()
    if now - _last_unavailable_log >= 60:
        _last_unavailable_log = now
        logger.warning(
            "security_alert_counter_unavailable event=%s error=%s", event, type(exc).__name__
        )


async def _count(r, event: str, rule: Rule, label: Optional[str]) -> Optional[Alert]:
    from api.services.rate_limiter import _incr_with_ttl_on_first

    count = await asyncio.wait_for(
        _incr_with_ttl_on_first(r, counter_key(event, rule, label), rule.window_s), REDIS_TIMEOUT_S
    )
    # Only the caller that lands exactly on the threshold (INCR is atomic
    # across replicas) tries the lock: one SET NX per window crossing.
    if count != rule.threshold:
        return None
    locked = await asyncio.wait_for(
        r.set(lock_key(event, rule, label), "1", nx=True, ex=rule.cooldown_s), REDIS_TIMEOUT_S
    )
    if not locked:
        return None
    return Alert(event=event, count=count, threshold=rule.threshold, window_s=rule.window_s,
                 per_key=rule.per_key, key_label=label)


async def record(event: str, *, key: Optional[str] = None) -> None:
    """Count one `event` (optionally for `key`); alert when a rule trips.
    Never raises."""
    try:
        if not _enabled():
            return
        rules = [r for r in rules_for(event) if r.threshold > 0 and (key is not None or not r.per_key)]
        if not rules:
            if event not in RULES:
                logger.warning("security_alert_unknown_event event=%s", event[:64])
            return
        from api.services.cache import get_redis

        r = await asyncio.wait_for(get_redis(), REDIS_TIMEOUT_S)
        for rule in rules:
            alert = await _count(r, event, rule, _key_label(rule, key))
            if alert is not None:
                _dispatch(alert)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        _log_unavailable(event, exc)


# ─── delivery ────────────────────────────────────────────────────

_pending: set[asyncio.Task] = set()


def _dispatch(alert: Alert) -> None:
    logger.critical(
        "security_alert event=%s count=%d window_s=%d scope=%s key=%s",
        alert.event, alert.count, alert.window_s,
        "per_key" if alert.per_key else "all", alert.key_label or "-",
    )
    task = asyncio.get_running_loop().create_task(_safe_deliver(alert))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


async def _safe_deliver(alert: Alert) -> None:
    try:
        await _deliver(alert)
    except Exception as exc:
        logger.error("security_alert_delivery_failed event=%s error=%s", alert.event, type(exc).__name__)


async def drain() -> None:
    """Wait for alerts being sent (tests, shutdown)."""
    while _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)


def build_message(alert: Alert) -> tuple[str, str]:
    minutes = max(alert.window_s // 60, 1)
    subject = f"Cleanway security: {alert.event} ({alert.count} in {minutes} min)"
    meaning, check = EVENT_INFO.get(alert.event, ("Неизвестное событие безопасности.", "Посмотрите логи Railway."))
    scope = (
        f"Для одного ключа ({alert.key_label}) — {alert.count} за {minutes} мин."
        if alert.per_key
        else f"По всему сервису — {alert.count} за {minutes} мин."
    )
    body = "\n".join([
        f"Событие: {alert.event}",
        meaning,
        scope,
        "",
        f"Что проверить: {check}",
        "",
        "Логи Railway (сервис web): фильтр «security_alert» и имя события выше.",
        f"Порядок действий: docs/runbooks/security-incident.md — {RUNBOOK}",
        "",
        "Следующее письмо по этому событию придёт не раньше чем через час "
        "(для бюджета платных источников — через сутки).",
    ])
    return subject, body


def _email_provider():
    from api.services import email as email_service

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    if api_key:
        return email_service.ResendProvider(api_key=api_key)
    return email_service.get_provider()


async def _deliver(alert: Alert) -> None:
    to = os.environ.get("SECURITY_ALERT_EMAIL", "").strip()
    subject, body = build_message(alert)
    if not to:
        logger.critical("security_alert_not_emailed: SECURITY_ALERT_EMAIL is not set (%s)", subject)
        return
    from html import escape

    result = await _email_provider().send(
        to=to,
        from_addr=os.environ.get("SECURITY_ALERT_FROM", "").strip() or "alerts@cleanway.ai",
        from_name="Cleanway Security",
        subject=subject,
        html=f"<pre style=\"font-family:sans-serif;white-space:pre-wrap\">{escape(body)}</pre>",
        text=body,
        headers={"Auto-Submitted": "auto-generated", "X-Cleanway-Alert": alert.event},
    )
    if not result.ok:
        logger.error("security_alert_email_failed event=%s error=%s", alert.event, result.error)
