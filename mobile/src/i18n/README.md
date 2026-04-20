# Mobile i18n

## How to use in components

```tsx
import { useTranslation } from "react-i18next";

export function StatusCard() {
  const { t } = useTranslation();
  return (
    <View>
      <Text>{t("extension.popup.status_safe_title")}</Text>
      <Text>{t("extension.popup.status_safe_subtitle", { domain: "example.com" })}</Text>
    </View>
  );
}
```

## How to change language at runtime

```tsx
import { changeLocale } from "@/i18n";
await changeLocale("ru");  // switches UI immediately + sets RTL if needed
```

## Adding / updating strings

Never edit `mobile/i18n/*.json` directly — they're regenerated.

1. Edit `packages/i18n-strings/src/en.json` (source of truth for English)
2. Add translations to the other 9 language files
3. Run `python3 scripts/build-i18n.py` — regenerates `mobile/i18n/` + extension `_locales/` + `landing/messages/`
4. Reload Expo dev server

## Key structure

The build script flattens the nested source into dotted flat keys for react-i18next:

```
extension.popup.status_safe_title    # was: source.extension.popup.status_safe_title.text
extension.block_page.title           # "STOP" / "СТОП" / "ALTO" / ...
extension.welcome.hero_title
extension.common.trust_footer
landing.nav.features                 # yes, shared with landing site
```

## RTL (Arabic)

Active automatically on `locale === "ar"` via `I18nManager.forceRTL(true)`. A full JS reload is required to visually apply — `Updates.reloadAsync()` from `expo-updates` if installed, otherwise manual relaunch.
