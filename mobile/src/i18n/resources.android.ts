/**
 * Android's strings per locale: the base files every platform gets (see
 * resources.ts) plus mobile/i18n/android/{locale}.json — the VpnService
 * disclosure, the "permission taken back" notice and the Always-on VPN rows,
 * which only Android shows. Metro picks this file over resources.ts on
 * Android only, so those strings never reach the iPhone's bundle.
 *
 * It repeats the base imports instead of importing ./resources: on Android
 * that path resolves back to this file.
 */
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
import enAndroid from "../../i18n/android/en.json";
import ruAndroid from "../../i18n/android/ru.json";
import esAndroid from "../../i18n/android/es.json";
import ptAndroid from "../../i18n/android/pt.json";
import frAndroid from "../../i18n/android/fr.json";
import deAndroid from "../../i18n/android/de.json";
import itAndroid from "../../i18n/android/it.json";
import idAndroid from "../../i18n/android/id.json";
import hiAndroid from "../../i18n/android/hi.json";
import arAndroid from "../../i18n/android/ar.json";

export const RESOURCES = {
  en: { translation: { ...en, ...enAndroid } },
  ru: { translation: { ...ru, ...ruAndroid } },
  es: { translation: { ...es, ...esAndroid } },
  pt: { translation: { ...pt, ...ptAndroid } },
  fr: { translation: { ...fr, ...frAndroid } },
  de: { translation: { ...de, ...deAndroid } },
  it: { translation: { ...it, ...itAndroid } },
  id: { translation: { ...id, ...idAndroid } },
  hi: { translation: { ...hi, ...hiAndroid } },
  ar: { translation: { ...ar, ...arAndroid } },
};
