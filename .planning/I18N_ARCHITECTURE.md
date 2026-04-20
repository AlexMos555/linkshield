# I18N Architecture — LinkShield

> Locked 2026-04-14. Applies to all 3 clients (landing, extension × 3, mobile) + backend error messages.

## Supported languages (10)

| # | Code | Language | Speakers | Market Priority | RTL | Notes |
|---|---|---|---|---|---|---|
| 1 | `en` | English | Default (universal) | T1 | No | Fallback язык |
| 2 | `es` | Spanish | ~580M | T1/T3 | No | LATAM + Spain |
| 3 | `hi` | Hindi | ~600M | T4 | No | Deva script, большой fraud-market |
| 4 | `pt` | Portuguese | ~280M | T1/T3 | No | Brazil (pt-BR) dominant |
| 5 | `ru` | Russian | ~258M | T2 | No | Наша базовая аудитория |
| 6 | `ar` | Arabic | ~422M | T3 | **Yes** | MEA, нужен RTL layout |
| 7 | `fr` | French | ~280M | T1 | No | France + Africa |
| 8 | `de` | German | ~135M | T1 | No | DACH, security-aware |
| 9 | `it` | Italian | ~85M | T1 | No | Italy + Switzerland |
| 10 | `id` | Indonesian | ~270M | T4 | No | SEA, growing market |

**Исключено:** Chinese (требует отдельной CIDR инфры и locale — в V4).

## Libraries (per client)

### Landing (Next.js 15 App Router)
- **`next-intl`** — native App Router поддержка, server components friendly
- Структура: `landing/messages/{locale}.json`
- Routing: `/[locale]/page.tsx` → `/en`, `/es`, `/ru`, etc.
- Defaults: `/` → редирект на detected locale из `Accept-Language`
- Static generation для всех locales (SEO)

### Extension (Chrome/Firefox/Safari)
- **`i18next` + `react-i18next`** если перепишем на React, иначе **vanilla `i18next`**
- Fallback: `chrome.i18n.getMessage()` для extension name/description в manifest (только en)
- Структура: `extension/src/i18n/{locale}.json`
- Load at popup/welcome mount, cache в `chrome.storage.local`
- Dynamic locale switch в settings без reload

### Mobile (React Native / Expo)
- **`expo-localization`** для detection
- **`i18next` + `react-i18next`** для rendering (same как extension для переиспользования переводов)
- Структура: `mobile/i18n/{locale}.json`
- Persistent locale в SQLite local settings
- Sync с Supabase при изменении

### Backend (FastAPI)
- Error messages: `api/i18n/{locale}.json`
- Resolve по `Accept-Language` header
- Fallback → en
- Только error messages и email templates (всё остальное — клиентская ответственность)

## Translation pipeline

### Source of truth
**English (`en.json`)** — единственный language где strings пишутся вручную разработчиком. Остальные 9 производны.

### Translation flow
1. **Initial drops** — DeepL API через скрипт `scripts/translate.py`
   ```
   python scripts/translate.py --source en --target es,hi,pt,ru,ar,fr,de,it,id
   ```
   - Читает `en.json` из каждого клиента
   - Отправляет в DeepL API (glossary настроен на LinkShield-specific terms)
   - Пишет `{locale}.json`
2. **Human review (обязательно):**
   - **Russian** и **English** — самостоятельно (основная аудитория)
   - Остальные 8 — через native-reviewers (найти на Fiverr / Upwork при росте)
3. **Fallback логика:** missing key в `{locale}.json` → fallback на `en.json` → fallback на key name (dev-only, prod должен warn в Sentry)

### Glossary (DeepL custom)
Термины которые должны переводиться одинаково везде:
- "LinkShield" → не переводить (brand)
- "Granny Mode" → локализованный эквивалент ("Режим Бабушки", "Modo Abuela", "ただし дедовский режим" — no wait, это японский не нужен)
- "Family Hub" → "Семейный Хаб", etc.
- "Scam site" (regular mode) → простая локальная версия
- "Phishing site" (pro mode) → технический термин

## Default и fallback

### Detection order
1. User explicit preference в settings (сохранено)
2. OS/browser locale (`navigator.language` / `Accept-Language` / `expo-localization`)
3. GeoIP country → primary language of country
4. `en` fallback

### Currency detection (отдельно от языка!)
Язык и валюта не связаны. Пример: юзер в Германии может выбрать английский UI, но цены всё равно показываем в EUR с T1 регионом. См. PRICING_MATRIX.md.

## File structure

```
LinkShield/
├── landing/
│   ├── messages/
│   │   ├── en.json
│   │   ├── es.json
│   │   └── ... (10 total)
│   └── app/
│       └── [locale]/...
├── extension/
│   └── src/i18n/
│       ├── en.json
│       └── ... (10 total)
├── extension-firefox/
│   └── src/i18n/ (symlink to extension/src/i18n)
├── extension-safari/
│   └── src/i18n/ (symlink to extension/src/i18n)
├── mobile/
│   └── i18n/
│       ├── en.json
│       └── ... (10 total)
├── api/
│   └── i18n/
│       ├── en.json
│       └── ... (10 total, error messages only)
└── scripts/
    └── translate.py
```

## Translation key naming convention

```json
{
  "popup": {
    "status": {
      "safe": "This page is safe",
      "warning": "Warning — some suspicious links",
      "danger": "This is a scam site"
    },
    "actions": {
      "audit": "What this site collects",
      "report": "My week"
    }
  },
  "block_page": {
    "title": "STOP",
    "explanation": "This site pretends to be {brand} to steal your password",
    "scheme_example": "You will be asked to enter data → scammer gets your password → steals money",
    "buttons": {
      "back": "Go back (recommended)",
      "proceed": "I understand the risk"
    }
  },
  "skill_levels": {
    "kids": "Kids",
    "regular": "Regular",
    "granny": "For parents & grandparents",
    "pro": "Pro"
  },
  "pricing": {
    "free": "Free",
    "personal": "Personal",
    "family": "Family",
    "business": "Business",
    "threat_threshold_nudge": "LinkShield has saved you {count} times. Consider supporting the project + protect your family with {plan} plan."
  }
}
```

## RTL Support (Arabic)

- `dir="rtl"` on `<html>` when locale === 'ar'
- CSS: use `margin-inline-start/end` instead of `margin-left/right`
- Flexbox: `flex-direction: row` auto-reverses
- Icons: conditional flip для directional ones (arrows, progress bars)
- Line height: увеличить на 10-15% для Arabic (символы требуют больше vertical space)
- Font stack для Arabic: `"Noto Sans Arabic", -apple-system, sans-serif`

## Плюрализация (CLDR)

DeepL не даёт plurals корректно — надо вручную для ключевых:
- "1 scam blocked" / "3 scams blocked" / "23 scams blocked"
- i18next `count` parameter + plural rules per locale
- Особенно важно для ru/ar (сложные plural формы)

## Testing

- Unit tests: каждый translated key должен существовать во всех 10 файлах (pytest fixture)
- E2E: каждый UI screen должен рендериться в каждом locale без overflow/broken layout
- RTL visual regression для арабского

## Rollout plan (Phase C)

1. Extract hardcoded strings в en.json для всех клиентов (грэп `grep -r '"[A-Z][a-z]'`)
2. Запустить translate.py для остальных 9 languages
3. Ручная вычитка ru/en
4. i18next setup в extension + mobile + next-intl в landing
5. Locale selector в settings (показывает native names: English / Русский / العربية / हिन्दी / ...)
6. RTL тесты для арабского
7. Ship
