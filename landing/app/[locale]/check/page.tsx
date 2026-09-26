import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";

import CheckForm from "@/components/CheckForm";
import { routing, type Locale } from "@/i18n/routing";
import { toCheckHost } from "@/lib/check-host";
import { localePath } from "@/lib/locale-path";

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export default async function CheckSearch({
  searchParams,
  params,
}: {
  searchParams: Promise<{ q?: string }>;
  params: Promise<{ locale: string }>;
}) {
  const { q } = await searchParams;
  const locale = resolveLocale((await params).locale);

  // `?q=` comes only from old links and bookmarks: CheckForm never submits
  // natively, it navigates straight to /check/<site>. Reduce it to the site
  // name here too; anything else is dropped.
  const host = q ? toCheckHost(q) : null;
  if (host) {
    // Keep the reader's language: a bare /check/... would be re-guessed by the
    // middleware and could land a Russian reader on the English scorecard.
    redirect(localePath(locale, `/check/${host}`));
  }

  const t = await getTranslations({ locale, namespace: "Check" });

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center", maxWidth: 500, padding: 24 }}>
        <h1 style={{ fontSize: 32, fontWeight: 800, color: "#f8fafc", marginBottom: 16 }}>
          {t("index_title")}
        </h1>
        <p style={{ color: "#94a3b8", marginBottom: 24 }}>
          {t("index_subtitle")}
        </p>
        <CheckForm
          locale={locale}
          placeholder={t("input_placeholder")}
          label={t("input_label")}
          submit={t("submit")}
          invalid={t("invalid_input")}
          initiallyInvalid={Boolean(q) && !host}
          autoFocus
        />
        <p style={{ fontSize: 12, color: "#475569", marginTop: 16 }}>
          {t("index_footer")}
        </p>
      </div>
    </div>
  );
}
