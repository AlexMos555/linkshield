/**
 * Support page — the address stores require and users need.
 *
 * mobile/STORE_LISTING.md declared cleanway.ai/support as the support URL,
 * which 404'd (a store-rejection trigger, launch-blocker B5). This is that
 * page: the questions a first-time Tele2 subscriber actually asks (install,
 * no internet, "another app wants the VPN off", wrongly blocked site, what do
 * you collect, "Cleanway support" calling), linked from /android.
 *
 * The contact block is honest about the mailbox (lib/support.ts): cleanway.ai
 * has no MX record yet, so until NEXT_PUBLIC_SUPPORT_EMAIL_LIVE is switched on
 * the page says mail can't reach us instead of promising a reply.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/support` : `${SITE_URL}/${locale}/support`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Support" });
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  return {
    title: `${t("title")} — Cleanway`,
    description: t("subtitle"),
    alternates: { canonical: urlFor(safeLocale), languages },
  };
}

const contactBox: React.CSSProperties = {
  background: "#111827",
  border: "1px solid #1f2937",
  borderRadius: 14,
  padding: 24,
  marginBottom: 40,
};

export default async function SupportPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Support" });

  const faqs: Array<[string, string]> = [
    [t("q_install"), t("a_install")],
    [t("q_no_internet"), t("a_no_internet")],
    [t("q_app_vpn"), t("a_app_vpn")],
    [t("q_off"), t("a_off")],
    [t("q_fp"), t("a_fp")],
    [t("q_vpn"), t("a_vpn")],
    [t("q_privacy"), t("a_privacy")],
    [t("q_calls"), t("a_calls")],
  ];

  return (
    <main
      style={{
        maxWidth: 760,
        margin: "40px auto",
        padding: "0 24px 80px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
      }}
    >
      <header style={{ marginBottom: 32 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 34, marginBottom: 10 }}>{t("title")}</h1>
        <p style={{ color: "#94a3b8", fontSize: 17 }}>{t("subtitle")}</p>
      </header>

      {SUPPORT_EMAIL_LIVE ? (
        <section style={contactBox} data-testid="support-email">
          <div style={{ color: "#e2e8f0", fontSize: 15, marginBottom: 8 }}>{t("email_label")}</div>
          <a
            href={`mailto:${SUPPORT_EMAIL}`}
            style={{ color: "#34d399", fontSize: 22, fontWeight: 600, textDecoration: "none" }}
          >
            {SUPPORT_EMAIL}
          </a>
          <p style={{ color: "#94a3b8", fontSize: 14, marginTop: 12, marginBottom: 0 }}>{t("email_hint")}</p>
        </section>
      ) : (
        <section style={{ ...contactBox, border: "1px solid #78350f" }} data-testid="support-email-not-live">
          <div style={{ color: "#fbbf24", fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
            {t("email_not_live_title")}
          </div>
          <p style={{ color: "#cbd5e1", fontSize: 15, margin: 0 }}>{t("email_not_live_body")}</p>
        </section>
      )}

      <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 20 }}>{t("faq_title")}</h2>
      <dl style={{ margin: 0 }}>
        {faqs.map(([q, a], i) => (
          <div
            key={i}
            style={{
              paddingBottom: 20,
              marginBottom: 20,
              borderBottom: i < faqs.length - 1 ? "1px solid #1f2937" : "none",
            }}
          >
            <dt style={{ color: "#f1f5f9", fontSize: 17, fontWeight: 600, marginBottom: 8 }}>{q}</dt>
            <dd style={{ margin: 0, color: "#cbd5e1", fontSize: 15.5 }}>{a}</dd>
          </div>
        ))}
      </dl>

      <p style={{ marginTop: 32, fontSize: 15, display: "flex", flexWrap: "wrap", gap: "8px 20px" }}>
        <a href={localePath(safeLocale, "/android")} style={{ color: "#34d399", textDecoration: "underline" }}>
          {t("android_link")}
        </a>
        <a href={localePath(safeLocale, "/privacy-policy")} style={{ color: "#34d399", textDecoration: "underline" }}>
          {t("privacy_link")}
        </a>
      </p>
    </main>
  );
}
