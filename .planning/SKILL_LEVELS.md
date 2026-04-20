# Skill Levels — UX Specifications

> Locked 2026-04-14. 4 режима UX: Kids / Regular / Granny / Pro.
> Это НЕ разные продукты — один продукт с 4 рендер-режимами.

## Философия

Один юзер = один аккаунт = один Supabase user_id. Но **один юзер может иметь несколько устройств с разными skill levels** (например: свой телефон — Pro, у бабушки — Granny, у ребёнка — Kids).

Per-device setting, синхронизируется через Supabase settings table, может изменяться владельцем аккаунта удалённо (через Family Hub) или локально на устройстве.

## Default logic

- **Первая установка, никаких hints** → Regular Mode
- **Onboarding шаг 3 "Для кого устройство?"** → выбор mode
- **Settings → Skill Level** → change anytime
- **Family Hub admin** → может назначить mode удалённо для устройств семьи

---

## Level 1: 🧒 Kids Mode

### Целевая аудитория
Дети 7-14 лет. Первые смартфоны, первый интернет. Родители беспокоятся.

### UX принципы
- **Gamified** — блок угрозы это достижение, не "угроза"
- **Упрощённая лексика** — "Плохой сайт", "Хороший сайт", "Неизвестный" (вместо "score 67")
- **Parental controls видимые** — ребёнок знает что родитель видит активность (прозрачность > скрытность)
- **Safe Search enforcement** (через extension API где возможно)
- **Screen time awareness** — не наш основной фокус, но показываем родителям

### Визуальные элементы
- **Цвета:** ярко-зелёный (безопасно), жёлтый (осторожно), красный (плохо)
- **Иконки:** эмодзи и cartoon-style (не серьёзные геометрические)
- **Шрифт:** дружелюбный, чуть крупнее default (16px base vs 14px Regular)
- **Анимации:** приветственные при +XP, confetti при достижениях

### Главный экран (popup)
```
┌────────────────────────────┐
│  🛡️ LinkShield         🏆 │ ← shield + trophy (achievements)
├────────────────────────────┤
│                            │
│       😊                   │
│   БЕЗОПАСНО!               │ ← big emotional status
│   Эта страница хорошая     │
│                            │
│   ⭐ 250 XP                │ ← progress
│   3 плохих сайта заблокировано│
│                            │
├────────────────────────────┤
│ 🏆 Достижения              │
│ 📊 Моя защита              │
└────────────────────────────┘
```

### Достижения (gamification)
- 🥇 "Первая ловушка!" — первый блок
- 🛡️ "Неделя в безопасности" — 7 дней без угроз (или каждый день hit шит)
- 🔥 "10 ловушек — твой счёт!" — 10 блоков
- 🌟 "Эксперт по безопасности" — 50 блоков
- 🤝 "Помог другу" — поделился ссылкой о LinkShield
- 🧠 "Школа безопасности" — прошёл обучающий модуль (если сделаем)

### Block page (Kids)
```
┌────────────────────────────┐
│                            │
│        🚫                  │
│    ПЛОХОЙ САЙТ!            │
│                            │
│ Этот сайт хочет тебя       │
│ обмануть. Например:        │
│                            │
│ 🎮 "Скачай игру бесплатно" │
│ 💰 "Получи подарок"        │
│                            │
│ Настоящие такого не пишут! │
│                            │
│  [⬅ ВЕРНУТЬСЯ НАЗАД]      │
│                            │
│ +50 XP за то что не попал 🎉│
└────────────────────────────┘
```

### Parental dashboard (доступ из родительского аккаунта Family)
- Activity log: когда блок, на каком сайте (домен без URL)
- Daily summary по email
- Настройки: allow/deny список, time limits
- "Panic button" — lock device если что-то серьёзное

### Что скрыто в Kids Mode
- Все технические детали угроз
- Settings complexity (только язык и тема + pairing с родителем)
- Privacy Audit details (только grade A-F)
- Payment/upgrade UI (только у родителя)

---

## Level 2: 👤 Regular Mode (default)

### Целевая аудитория
Обычный взрослый 18-60. Пользуется интернетом для работы/жизни, не tech-savvy.

### UX принципы
- **1 главный статус** — сразу видно всё ли ок
- **Минимум кнопок** на первом экране (2 secondary + "more" menu)
- **Plain language** — жаргон заменён на понятные слова
- **Visual clarity** — цвет/иконка передают состояние мгновенно
- **Trust signals** — "Ваши данные не покидают устройство" всегда видно

### Главный экран (popup)
```
┌────────────────────────────┐
│  🛡️ LinkShield        ⚙️  │
├────────────────────────────┤
│                            │
│         ✅                 │
│   СТРАНИЦА БЕЗОПАСНА       │ ← огромный статус
│   Ссылки проверены         │
│                            │
├────────────────────────────┤
│ 🔍 Что собирает этот сайт  │ ← action 1
│ 📊 Моя неделя              │ ← action 2
├────────────────────────────┤
│ Ещё ▼                      │ ← раскрывает rest
│                            │
│ 🔒 Ваши данные не покидают │ ← privacy trust footer
│    это устройство          │
└────────────────────────────┘
```

### При опасности (danger state)
```
┌────────────────────────────┐
│  🛡️ LinkShield        ⚙️  │
├────────────────────────────┤
│                            │
│         ⚠️                 │
│   ОПАСНЫЙ САЙТ!            │ ← красный
│   Этот сайт пытается       │
│   украсть ваши данные      │
│                            │
│ [🛡️ Закрыть вкладку]      │ ← big primary action
│                            │
├────────────────────────────┤
│ ℹ️  Почему опасно:        │ ← plain explanation
│ Сайт притворяется вашим    │
│ банком. Домен создан 2 дня │
│ назад в Нигерии.           │
└────────────────────────────┘
```

### Block page (Regular)
```
┌─────────────────────────────┐
│                             │
│         🚫 СТОП              │ ← огромное красное
│                             │
│ Этот сайт притворяется      │
│ вашим банком (Сбербанк)     │
│ чтобы украсть пароль.       │
│                             │
│ Что произойдёт если ввести: │
│ 1. Вас попросят пароль      │
│ 2. Мошенник получит доступ  │
│ 3. Украдёт деньги с счёта   │
│                             │
│ [🏠 ВЕРНУТЬСЯ НАЗАД]        │ ← primary
│                             │
│ Открыть сайт (3...) ←       │ ← secondary + countdown
└─────────────────────────────┘
```

### Словарь замен жаргона (Regular Mode)

| Техническое | Regular |
|---|---|
| Phishing | Мошеннический сайт |
| Suspicious | Подозрительный |
| Malicious | Опасный |
| Audit this page | Что собирает этот сайт |
| Tracker | Следящий код |
| Fingerprinting | Отпечаток браузера |
| Cookie | Следящий файл |
| Breach Check | Проверка утечки email |
| Security Score | Уровень защиты |
| Percentile | Безопаснее X% пользователей |
| ML model | Умная проверка |
| Bloom filter | (скрыто) |
| SSL cert invalid | Сайт не защищён |
| DNS anomaly | Подозрительный адрес |

### Ключевые отличия от современных конкурентов
- Guardio: показывает score 85 → мы: "Подозрительный"
- Aura: "Phishing detected" → мы: "Сайт-мошенник"
- Netcraft: технический dashboard → мы: 1 статус + 2 кнопки

---

## Level 3: 👵 Granny Mode

### Целевая аудитория
Пожилые 60+, слабовидящие, технически неуверенные. Первый контакт с сервисом.

### UX принципы
- **Огромный шрифт** — × 1.5 до 2.0 от Regular
- **Максимум 2 цвета** — ярко-зелёный (OK) и ярко-красный (DANGER). Жёлтый нет — бабушка не различит.
- **Голос** — все важные события озвучиваются
- **"Спросить внука"** — кнопка на видном месте, отправляет запрос помощи члену семьи через Family Hub
- **Никаких toggles** — всё что может испортить защиту скрыто
- **Тактильная обратная связь** (mobile) — вибрация на блок

### Главный экран (popup)
```
┌─────────────────────────────┐
│                             │
│                             │
│          ✅                 │ ← огромная иконка (100px)
│                             │
│    ВСЁ В ПОРЯДКЕ            │ ← 32pt шрифт
│                             │
│    Этот сайт безопасный     │ ← 18pt
│                             │
├─────────────────────────────┤
│                             │
│  [📞 СПРОСИТЬ ВНУКА]        │ ← большая кнопка
│                             │
│  [⚙️ Настройки]             │ ← маленькая
└─────────────────────────────┘
```

### Block page (Granny)
```
┌─────────────────────────────┐
│                             │
│          🚫                 │ ← огромная (150px)
│                             │
│        СТОП!                │ ← 48pt, жирный, красный
│                             │
│  Этот сайт — МОШЕННИКИ!     │ ← 24pt
│                             │
│  Они хотят украсть          │
│  ваши деньги.               │
│                             │
│  НЕ вводите ничего!         │
│  Закройте эту страницу!     │
│                             │
│  [🏠 ЗАКРЫТЬ]                │ ← огромная зелёная
│                             │
│  [📞 ПОЗВАТЬ ВНУКА]          │ ← жёлтая, средняя
└─────────────────────────────┘

🔊 Голос (громко):
"Внимание! Этот сайт — мошенники!
Они хотят украсть ваши деньги.
Ничего не вводите, закройте страницу.
Если сомневаетесь — нажмите 'Позвать внука'."
```

### Voice alerts
- Web Speech API (`window.speechSynthesis`) в extension
- expo-speech в mobile
- Локализован на 10 языков
- Volume / voice speed регулируется в settings
- Может быть выключен (но по умолчанию ON)

### "Позвать внука" (Ask Grandchild)
- Кнопка отправляет push-уведомление в Family Hub admin
- Admin (внук / сын / дочь) получает: "Бабушка на устройстве {device_name} столкнулась с опасным сайтом {domain}. Нужна помощь?"
- Admin может ответить через chat в Family Hub
- В Business version (B2B): можно настроить IT-support

### Что скрыто в Granny Mode
- Settings сложные (остаются: язык, размер шрифта, громкость голоса)
- Privacy Audit в принципе (скрыто — слишком сложно)
- Statistics
- History (последние 7 записей видны, не 30 дней)
- Upgrade UI (управляется из Family admin аккаунта)
- Jargon полностью

### Assistive features
- High contrast mode toggle
- Screen reader compatibility (всё labeled)
- Простая клавиатурная навигация (только Tab + Enter)
- Минимум скроллинга (всё на одном экране)

---

## Level 4: 🛠️ Pro Mode

### Целевая аудитория
Tech-savvy пользователи, security researchers, bug bounty hunters, curious nerds, developers.

### UX принципы
- **Полная информация** — все 42+ сигналов видны
- **Raw data доступен** — feature vector, ML confidence, model version
- **Keyboard shortcuts** для всего
- **API-like UX** — можно экспортировать в JSON/CSV
- **Technical terminology** — phishing, fingerprinting, SSL, DNS, etc. — корректно используются

### Главный экран (popup — густо информативный)
```
┌─────────────────────────────────────┐
│ LinkShield Pro    [⚙️][📊][🧪][≣]  │
├─────────────────────────────────────┤
│ example.com                         │
│ Score: 87/100 (HIGH RISK)           │
│ Level: phishing (ML p=0.94)         │
│ Signals: 11/42 triggered            │
│                                     │
│ ├─ Lexical (3)                      │
│ │  ├─ entropy: 4.21 (suspicious)    │
│ │  ├─ digit_ratio: 0.15             │
│ │  └─ suspicious_ngram: yes         │
│ ├─ DNS (2)                          │
│ │  ├─ ttl: 60s (very low)           │
│ │  └─ no_mx: true                   │
│ ├─ Cert (1)                         │
│ │  └─ age: 2d                       │
│ ├─ Blocklist (2)                    │
│ │  ├─ phishtank: HIT                │
│ │  └─ threatfox: HIT                │
│ └─ ML (3)                           │
│    ├─ prediction: 0.94              │
│    ├─ confidence: high              │
│    └─ model_version: v4.2.1         │
│                                     │
│ [View raw JSON] [Feature vector]    │
│ [Report false positive]             │
└─────────────────────────────────────┘
```

### Exports / Developer Tools
- "Download report as JSON" — полный feature vector + all signals + model probabilities
- CSV export of check history
- API playground: check any URL manually
- Bloom filter inspector (view hashes, test domain)
- ML inference viewer (which features influenced the decision most)

### Block page (Pro)
- Показывает всё как в Regular, но + полный breakdown сигналов ниже
- "View technical details" expandable section
- Links: "Report to threat intel" — кнопка для репорта в PhishTank/URLhaus

### Ключевые отличия от Regular
- Больше информации визуально (можно переключить на compact)
- Technical vocabulary (phishing, TLS, DNS, etc.)
- Raw data exposure
- Keyboard shortcuts

---

## Family Hub management (пересекается со всеми levels)

Admin (Family plan owner) видит dashboard:

```
┌──────────────────────────────────────┐
│ Family: Ивановы                      │
├──────────────────────────────────────┤
│ 👤 Иван (admin)                      │
│   └─ MacBook Pro · Regular · 2h назад │
│                                       │
│ 👵 Мама                              │
│   └─ iPhone 12 · Granny · 15m назад  │
│      [Change to Regular]              │
│                                       │
│ 🧒 Петя (12 лет)                     │
│   └─ iPhone SE · Kids · now          │
│      Last block: scam-roblox.com (1h) │
│                                       │
│ 🧒 Маша (9 лет)                      │
│   └─ iPad · Kids · 3h назад          │
│                                       │
│ [+ Add family member]                 │
└──────────────────────────────────────┘
```

Admin может:
- Изменить skill level удалённо
- Получить уведомление при блоке на устройстве семьи
- Ответить на "Спросить внука" запрос
- Видеть aggregate stats (не browsing content) per member

---

## Implementation notes

### State storage
```typescript
// Supabase: user_settings table
{
  user_id: uuid,
  device_id: text,
  skill_level: 'kids' | 'regular' | 'granny' | 'pro',
  language: 'en' | 'es' | 'hi' | ...,
  voice_enabled: boolean, // Granny mode
  font_scale: 1.0 | 1.5 | 2.0, // Granny mode
  updated_at: timestamp
}
```

### Rendering
React component `<SkillLevelProvider>` wraps app, reads setting, provides context. Sub-components check `useSkillLevel()` to render mode-specific UI.

### Testing
- Snapshot tests per level per key screen
- E2E: install → settings → switch level → verify UI changes
- Accessibility: Granny Mode должен проходить WCAG AA, voice работает в 10 языках
