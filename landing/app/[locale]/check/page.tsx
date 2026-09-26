import { redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
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

  if (q) {
    // Normalize: strip protocol, path
    let domain = q.toLowerCase().trim();
    if (domain.startsWith("http")) {
      try {
        domain = new URL(domain).hostname;
      } catch {}
    }
    domain = domain.replace(/\/$/, "");
    // Keep the reader's language: a bare /check/... would be re-guessed by the
    // middleware and could land a Russian reader on the English scorecard.
    redirect(localePath(locale, `/check/${encodeURIComponent(domain)}`));
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
        <form action={localePath(locale, "/check")} method="get" style={{ display: "flex", gap: 8 }}>
          <input
            name="q"
            placeholder={t("input_placeholder")}
            aria-label={t("input_label")}
            autoFocus
            style={{ flex: 1, minWidth: 0, padding: "14px 18px", borderRadius: 10, border: "1px solid #334155", background: "#1e293b", color: "#e2e8f0", fontSize: 16, outline: "none" }}
          />
          <button type="submit" style={{ background: "#22c55e", color: "#052e16", border: "none", padding: "14px 24px", borderRadius: 10, fontWeight: 700, fontSize: 16, cursor: "pointer" }}>
            {t("submit")}
          </button>
        </form>
        <p style={{ fontSize: 12, color: "#475569", marginTop: 16 }}>
          {t("index_footer")}
        </p>
      </div>
    </div>
  );
}
