/**
 * LinkShield mobile i18n setup.
 *
 * Single source of truth: packages/i18n-strings/src/{locale}.json → rebuilt
 * via `scripts/build-i18n.py` into mobile/i18n/{locale}.json.
 *
 * Runtime:
 *   1. expo-localization detects device language
 *   2. Falls back to English if user's language not in SUPPORTED_LOCALES
 *   3. User can override manually via Settings (persisted in SecureStore)
 *   4. RTL (Arabic) forces I18nManager.forceRTL + app reload
 */
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import * as Localization from "expo-localization";
import { I18nManager } from "react-native";

import en from "../../i18n/en.json";
import ru from "../../i18n/ru.json";
import es from "../../i18n/es.json";
import pt from "../../i18n/pt.json";
import fr from "../../i18n/fr.json";
import de from "../../i18n/de.json";
import it from "../../i18n/it.json";
import id from "../../i18n/id.json";
import hi from "../../i18n/hi.json";
import ar from "../../i18n/ar.json";

export const SUPPORTED_LOCALES = [
  "en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar",
] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const LOCALE_NAMES: Record<SupportedLocale, string> = {
  en: "English",
  ru: "Русский",
  es: "Español",
  pt: "Português",
  fr: "Français",
  de: "Deutsch",
  it: "Italiano",
  id: "Bahasa Indonesia",
  hi: "हिन्दी",
  ar: "العربية",
};

const RTL_LOCALES: readonly SupportedLocale[] = ["ar"] as const;

const RESOURCES = {
  en: { translation: en },
  ru: { translation: ru },
  es: { translation: es },
  pt: { translation: pt },
  fr: { translation: fr },
  de: { translation: de },
  it: { translation: it },
  id: { translation: id },
  hi: { translation: hi },
  ar: { translation: ar },
};

function detectInitialLocale(): SupportedLocale {
  const deviceLang = Localization.getLocales()[0]?.languageCode;
  if (deviceLang && (SUPPORTED_LOCALES as readonly string[]).includes(deviceLang)) {
    return deviceLang as SupportedLocale;
  }
  return "en";
}

export function applyRTL(locale: SupportedLocale): void {
  const shouldRTL = RTL_LOCALES.includes(locale);
  if (I18nManager.isRTL !== shouldRTL) {
    I18nManager.allowRTL(shouldRTL);
    I18nManager.forceRTL(shouldRTL);
    // App reload required for RTL change to visually take effect. We don't
    // trigger it here — caller decides (e.g. after user changes in Settings,
    // show "Restart the app to apply" prompt + call Updates.reloadAsync()).
  }
}

const initialLocale = detectInitialLocale();

i18n
  .use(initReactI18next)
  .init({
    resources: RESOURCES,
    lng: initialLocale,
    fallbackLng: "en",
    // Flat keys with dots: t("extension.popup.status_safe_title")
    keySeparator: ".",
    nsSeparator: false,
    interpolation: {
      escapeValue: false, // React Native already escapes
    },
    react: {
      useSuspense: false, // keep startup synchronous
    },
  });

applyRTL(initialLocale);

export async function changeLocale(locale: SupportedLocale): Promise<void> {
  await i18n.changeLanguage(locale);
  applyRTL(locale);
}

export default i18n;
