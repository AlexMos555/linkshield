/**
 * Cleanway mobile i18n setup.
 *
 * Single source of truth: packages/i18n-strings/src/{locale}.json → rebuilt
 * via `scripts/build-i18n.py` into mobile/i18n/{locale}.json.
 *
 * Runtime:
 *   1. expo-localization lists the device's preferred languages; the first
 *      one in SUPPORTED_LOCALES wins (src/utils/device-locale.ts)
 *   2. Falls back to English if none of them is
 *   3. RTL (Arabic) forces I18nManager.forceRTL + app reload
 *      (an in-app language override is NOT built yet — changeLocale exists
 *      for it, but no screen calls it; the device locale decides)
 */
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import * as Localization from "expo-localization";
import * as SecureStore from "expo-secure-store";
import { setNotificationLocale } from "../../modules/cleanway-vpn";
import { I18nManager } from "react-native";
import { firstSupportedLocale } from "../utils/device-locale";

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

/** The first of the phone's preferred languages the app has, else English. */
function detectInitialLocale(): SupportedLocale {
  return firstSupportedLocale(Localization.getLocales(), SUPPORTED_LOCALES) ?? "en";
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
    // Plurals: i18next 24+ only knows the v4 suffixes (_one/_other/_few…);
    // the v3 `compatibilityJSON` pin is gone. Hermes on Android has no
    // Intl.PluralRules, and there i18next silently uses a one/other rule
    // instead of logging an error. Every plural key keeps its base key, so a
    // category a locale does not carry (ru _few, ar _two) falls back to it.
    interpolation: {
      escapeValue: false, // React Native already escapes
    },
    react: {
      useSuspense: false, // keep startup synchronous
    },
  });

applyRTL(initialLocale);
// Seed the native notification locale with whatever we start in.
setNotificationLocale(initialLocale);

/**
 * Key for the user's explicit language choice (Settings → Language). It
 * overrides the device locale — the point of a manual picker on an RU-first
 * product is that a phone whose system language is not Russian can still run
 * the app in Russian.
 */
const LOCALE_OVERRIDE_KEY = "cleanway.locale";

/** True when switching to `next` flips the layout direction (needs a reload). */
export function localeChangeNeedsReload(next: SupportedLocale): boolean {
  return RTL_LOCALES.includes(next) !== I18nManager.isRTL;
}

export async function changeLocale(locale: SupportedLocale): Promise<void> {
  await i18n.changeLanguage(locale);
  applyRTL(locale);
  // Native notifications read this, so they match the in-app language.
  setNotificationLocale(locale);
  try {
    await SecureStore.setItemAsync(LOCALE_OVERRIDE_KEY, locale);
  } catch {
    // A persisted preference that fails to save is not worth crashing over;
    // the device locale remains the fallback next launch.
  }
}

/**
 * Apply the saved language override, if any. Called once at app start after
 * the synchronous device-locale init — a brief device-locale frame is
 * acceptable, and in the common case (device already in the chosen language)
 * there is no visible change.
 */
export async function restoreSavedLocale(): Promise<void> {
  try {
    const saved = await SecureStore.getItemAsync(LOCALE_OVERRIDE_KEY);
    if (saved && (SUPPORTED_LOCALES as readonly string[]).includes(saved) && saved !== i18n.language) {
      await i18n.changeLanguage(saved as SupportedLocale);
      applyRTL(saved as SupportedLocale);
      setNotificationLocale(saved as SupportedLocale);
    }
  } catch {
    // No saved preference or storage unavailable: keep the device locale.
  }
}

export default i18n;
