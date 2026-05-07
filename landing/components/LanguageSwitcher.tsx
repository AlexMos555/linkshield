"use client";

import { useLocale, useTranslations } from "next-intl";
import { usePathname } from "next/navigation";
import { useTransition, type ChangeEvent } from "react";
import { LOCALE_NAMES, routing, type Locale } from "@/i18n/routing";

/**
 * Compact language switcher for the nav bar.
 * Swaps the current URL's locale segment on change.
 */
export function LanguageSwitcher() {
  const t = useTranslations("LanguageSwitcher");
  const current = useLocale() as Locale;
  const pathname = usePathname();
  const [isPending, startTransition] = useTransition();

  function onChange(event: ChangeEvent<HTMLSelectElement>) {
    const next = event.target.value as Locale;
    if (next === current) return;

    // Replace the current locale segment with the new one.
    // `pathname` always starts with `/` and includes the locale prefix when
    // `localePrefix: "as-needed"` is active AND current locale != default.
    // When on default locale ('en'), pathname has no /en prefix.
    const segments = pathname.split("/").filter(Boolean);
    const hasLocaleSegment =
      segments.length > 0 && routing.locales.includes(segments[0] as Locale);
    const rest = hasLocaleSegment ? segments.slice(1) : segments;

    let newPath: string;
    if (next === routing.defaultLocale) {
      newPath = rest.length === 0 ? "/" : "/" + rest.join("/");
    } else {
      newPath = "/" + [next, ...rest].join("/");
    }

    // ── The locale-cookie tug-of-war ──
    // Without this line, switching to the *default* locale (English) from
    // any non-default page silently fails:
    //   1. User on /es/check → cookie NEXT_LOCALE=es is set.
    //   2. Switcher computes newPath = "/check" (English has no prefix).
    //   3. router.replace("/check") → middleware sees cookie=es, decides
    //      "user prefers Spanish", 307-redirects back to /es/check.
    //   4. UI looks broken; English is the only locale that "doesn't work".
    // Setting the cookie here BEFORE navigation tells middleware which
    // locale we actually want, breaking the loop.
    if (typeof document !== "undefined") {
      document.cookie = `NEXT_LOCALE=${next}; Path=/; Max-Age=31536000; SameSite=Lax`;
    }

    // Hard navigation (window.location) instead of router.replace so the
    // updated cookie is sent on the very next request. router.replace
    // would do a client-side transition that doesn't re-issue the
    // request with the new cookie until the next full reload, which
    // causes a one-page-old flicker of the previous locale.
    startTransition(() => {
      if (typeof window !== "undefined") {
        window.location.assign(newPath);
      }
    });
  }

  return (
    <label className="inline-flex items-center gap-2 text-sm text-slate-400">
      <span className="sr-only">{t("label")}</span>
      <select
        value={current}
        onChange={onChange}
        disabled={isPending}
        aria-label={t("label")}
        className="bg-slate-800 border border-slate-700 text-slate-200 rounded-lg px-3 py-1.5 text-sm outline-none hover:border-slate-500 transition disabled:opacity-50"
      >
        {routing.locales.map((loc) => (
          <option key={loc} value={loc}>
            {LOCALE_NAMES[loc]}
          </option>
        ))}
      </select>
    </label>
  );
}
