"use client";

import { useLocale, useTranslations } from "next-intl";
import { useRouter, usePathname } from "next/navigation";
import { useTransition, type ChangeEvent } from "react";
import { LOCALE_NAMES, routing, type Locale } from "@/i18n/routing";

/**
 * Compact language switcher for the nav bar.
 * Swaps the current URL's locale segment on change.
 */
export function LanguageSwitcher() {
  const t = useTranslations("LanguageSwitcher");
  const current = useLocale() as Locale;
  const router = useRouter();
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

    startTransition(() => {
      router.replace(newPath);
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
