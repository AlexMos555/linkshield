# Cleanway — что нужно сделать тебе (актуально на 2026-07-01)

> Это консолидированный план после всей работы этой сессии. Приоритет — по срочности
> к пятничному Chrome Web Store submit (2026-07-03). Технически всё готово; оставшееся —
> руками/аккаунтами, которые есть только у тебя.

---

## Как мы сюда пришли (что сделано за сессию, коротко)

- Починены все 15 ship-blocker'ов из полного аудита (extension paths, i18n, dead links).
- Честная recalibration: убран недоказуемый «93.5%», wired live 61.5% recall из latest.json.
- Privacy: `docs/PRIVACY.md` (code-grounded), domain-scrub в Sentry на всех 3 поверхностях,
  HMAC IP-hash, feature-log OFF by default.
- Scam-explainer (#15) wired в block-page. `/dns` reframe как «один слой».
- Benchmark bypass token + quality gate (cron больше не таймаутит).
- CI-гарды: extension-path integrity, i18n drift, stale-claims.
- 966 backend тестов зелёные, CI зелёный, все builds чистые.

**Вывод:** продукт готов к submit. Ниже — только то, что должен сделать ты.

---

## 🔴 ДО ПЯТНИЦЫ (обязательно)

### 1. Runtime-тест расширения (самое важное — единственное непроверенное)
**Что:** Загрузить распакованное расширение и вручную проверить ключевые фичи.
**Где:** `chrome://extensions` → Developer mode ON → Load unpacked → выбрать папку
`/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/extension`
**Проверить:**
- Открой любой сайт → на ссылках появляются бейджи, popup показывает verdict.
- Зайди на заведомо-фишинговый URL (возьми свежий с urlhaus.abuse.ch/browse/) →
  должна появиться блок-страница, и через ~4 сек — абзац «What kind of scam is this?»
  (это новый scam-explainer, #15).
- Options → Family Hub → создай инвайт, проверь что QR-код рисуется (это чинили — было 404).
- Проверь счётчик угроз в popup инкрементится.
**Зачем:** Я проверил все пути грепом и статикой, но живьём в браузере не запускал — это
единственное, что нельзя автоматизировать без тебя. Если что-то сломано — я чиню по твоему
отчёту в тот же день. **Делать ДО submit'а.**
**Время:** 20 мин.

### 2. Скриншоты для листинга (нужно 5 штук, их ещё НЕТ)
**Что:** 5 скриншотов расширения @ 1280×800 px для Chrome Web Store.
**Как:** после шага 1 расширение уже загружено — сделай скрины: (1) popup с verdict,
(2) бейджи на ссылках, (3) блок-страница фишинга, (4) scam-explainer, (5) Family Hub / Options.
**Зачем:** CWS требует минимум 1, реально нужно 4-5 для доверия. Без них листинг слабый.
**Время:** 20 мин (совмести с шагом 1).

### 3. Rotate Anthropic API key + Railway env
**Что:** Пересоздать Anthropic ключ, положить в Railway.
**Где:** console.anthropic.com/settings/keys → создать новый → Railway → Variables →
`ANTHROPIC_API_KEY` = новый.
**Проверка:** `POST https://api.cleanway.ai/api/v1/explain` вернёт `"source": "llm"`.
**Зачем:** Старый ключ светился в транскрипте ранее (был deferred «до недели submit» —
неделя настала). Без ключа scam-explainer и LLM judge работают на template-fallback
(не сломано, но LLM-версия лучше).
**Время:** 5 мин.

### 4. Twitter @cleanwayai — заклаймить ИЛИ убрать ссылки
**Что:** Проверить свободен ли handle. Если да — зарегать. Если занят — сказать мне, уберу
из кода (сейчас в metadata `site: "@cleanwayai"`, кликается в 404).
**Где:** twitter.com/cleanwayai
**Зачем:** OG/Twitter-карточки при шаринге ссылки ссылаются на этот handle. Битая ссылка
= плохо для доверия при Show HN / press.
**Время:** 10 мин.

### 5. Browser walkthrough в Chrome incognito (10 локалей)
**Что:** Пройтись по cleanway.ai в инкогнито, переключая языки.
**Проверить:** /pricing (toggle), /check/google.com, /transparency/methodology на /ru /es /de,
/dns (новая секция «Where DNS fits»), /family.
**Зачем:** Я много правил i18n на этой сессии — визуально глазами по локалям не смотрели.
Ищем «сырые» ключи (типа `Hero.badge` вместо текста), кривой layout на арабском (RTL).
Баги пиши мне — чиню.
**Время:** 20 мин.

---

## 🎯 ПЯТНИЦА 2026-07-03 — Chrome Web Store submit (главное событие)

### 6. Собственно submit
**Где:** chrome.google.com/webstore/devconsole
**Шаги:**
1. Купить dev-аккаунт ($5 однократно).
2. Upload `dist/store-artifacts/cleanway-0.1.1-chrome.zip` (⚠️ имя такое, не `cleanway-extension.zip`).
3. Листинг: copy-paste из `docs/marketing/chrome-web-store-listing.md` (текст честный, готов).
4. Загрузить 5 скриншотов из шага 2.
5. Submit → статус «In review».
**Зачем:** это и есть distribution — без листинга ноль пользователей. Всё остальное к этому.
**Совет:** можно сабмитить как **Unlisted** сначала (доступ только по прямой ссылке) —
разблокирует раздачу друзьям/тесты, пока идёт review, без публичного риска.
**Время:** 45 мин.

---

## 🟡 НЕ БЛОКЕРЫ (можно после, но полезно)

### 7. BENCHMARK_BYPASS_TOKEN (включает weekly auto-refresh цифр)
**Что:** Сгенерить `openssl rand -hex 32`, вставить ОДНО значение в два места:
Railway env `BENCHMARK_BYPASS_TOKEN` + GitHub Actions secret `BENCHMARK_BYPASS_TOKEN`.
**Зачем:** без него weekly-бенчмарк не может обновлять latest.json (rate-limit не даёт
набрать выборку в timeout). С ним — цифра recall на лендинге авто-обновляется каждую неделю.
Сейчас честный 61.5% и так стоит, просто не рефрешится.
**Время:** 3 мин.

### 8. Microsoft for Startups Founders Hub
**Где:** foundershub.startups.microsoft.com/signup
**Зачем:** $150K Azure + $500K OpenAI/Anthropic кредитов. Approval ~2 недели, поэтому
подавай раньше.
**Время:** 15 мин.

### 9. Firefox AMO + Edge listings (те же zip, бесплатно)
**Что:** `dist/store-artifacts/cleanway-0.1.1-firefox.zip` → addons.mozilla.org,
`cleanway-0.1.1-edge.zip` → Edge dev console.
**Зачем:** покрывает ещё ~30% браузерного рынка теми же артефактами. Дев-аккаунты бесплатные.
**Время:** 30 мин каждый.

---

## 🟢 ПОЗЖЕ (после approval / для роста)

- AV-Comparatives Q3 submit (независимая валидация recall; €4-8K; badge к концу Q4).
- n=3 grandparent usability study (после CWS approval).
- Cold-email Bitdefender / NordSecurity / 1Password (partnerships; template в press-pitch.md).
- OSS decisions (license / org / repo brand — docs/OPEN-SOURCE.md).
- Show HN post (я обновлю числа, ты ревьюишь; вторник 9 AM PT).
- Native-speaker QA для hi/ar/id (сейчас English-fallback в некоторых namespace'ах).
- Sign iOS .mobileconfig (чтоб не показывал «Unverified»).

---

## ❌ Что НЕ делать сейчас (сознательно)
- Не ретренить ML-модель (AUC 0.9983 отличный; риск регрессии перед launch; модель не bottleneck).
- Не строить новые фичи (top-20 + #21 закрыты; distribution — вот bottleneck).
- Не лезть в B2B/SOC2 (wrong audience для exit-трека).
- Не жечь paid ads до аналитики.

---

**Порядок на сегодня:** шаг 1 (runtime-тест) + 2 (скрины) вместе → 3 (Anthropic) → 4 (Twitter)
→ 5 (walkthrough). По результатам 1 и 5 — если найдёшь баги, кидай мне, чиню в тот же день.
Пятница — submit.
