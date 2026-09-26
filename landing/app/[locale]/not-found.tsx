import { useLocale, useTranslations } from "next-intl";

import { localePath } from "@/lib/locale-path";

/** Localized 404 for every path under a locale (see [...rest]/page.tsx). */
export default function LocaleNotFound() {
  const t = useTranslations("NotFound");
  const locale = useLocale();
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <main style={{ textAlign: "center", padding: 24 }}>
        <div aria-hidden="true" style={{ fontSize: 64, marginBottom: 16 }}>&#x1F6E1;</div>
        <h1 style={{ fontSize: 40, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>{t("title")}</h1>
        <p style={{ fontSize: 18, color: "#94a3b8", marginBottom: 32 }}>{t("body")}</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 16, justifyContent: "center" }}>
          <a href={localePath(locale, "/")} style={{ background: "#22c55e", color: "#052e16", padding: "12px 28px", borderRadius: 10, fontWeight: 700, textDecoration: "none" }}>
            {t("home")}
          </a>
          <a href={localePath(locale, "/check")} style={{ background: "#1e293b", color: "#e2e8f0", padding: "12px 28px", borderRadius: 10, fontWeight: 600, textDecoration: "none", border: "1px solid #334155" }}>
            {t("check")}
          </a>
        </div>
      </main>
    </div>
  );
}
