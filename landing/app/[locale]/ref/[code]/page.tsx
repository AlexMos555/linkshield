/**
 * /ref/<code> — where an invite link from a friend lands.
 *
 * It used to be English in every language and promised "7 days free" of
 * "ML-powered" protection, "enter code in extension settings to activate your
 * trial" (no extension is published, and no checkout reads the referral
 * credit), plus "0 data stored". Now it says, in the reader's language, what
 * Cleanway does today and that the code needs no entering.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { InstallButtons } from "@/components/InstallButtons";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { routing, type Locale } from "@/i18n/routing";
import { DEFAULT_OG_IMAGE, localeUrl } from "@/lib/seo";

type Props = { params: Promise<{ code: string; locale: string }> };

// Codes are short and alphanumeric (api/routers/referral.py, the extension's
// options page). Anything else is not shown: the page must not print
// arbitrary text from its URL under the Cleanway name.
const CODE = /^[A-Za-z0-9]{4,16}$/;

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { code, locale } = await params;
  const safeLocale = resolveLocale(locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Ref" });
  const title = t("meta_title");
  const description = t("meta_description");
  // The link preview is how the invitee first sees this page (Telegram,
  // WhatsApp): in their language, with the share image.
  const url = CODE.test(code) ? localeUrl(safeLocale, `/ref/${code}`) : undefined;
  return {
    title,
    description,
    openGraph: { title, description, url, siteName: "Cleanway", type: "website", locale: safeLocale, images: [DEFAULT_OG_IMAGE] },
    twitter: { card: "summary_large_image", title, description, images: [DEFAULT_OG_IMAGE.url] },
    // One URL per invite code: personal links, not search landing pages.
    robots: { index: false, follow: true },
  };
}

export default async function ReferralPage({ params }: Props) {
  const { code, locale } = await params;
  const safeLocale = resolveLocale(locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Ref" });
  const hero = await getTranslations({ locale: safeLocale, namespace: "Hero" });
  const shownCode = CODE.test(code) ? code.toUpperCase() : null;

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <main style={{ textAlign: "center", maxWidth: 480, padding: 24 }}>
        <div aria-hidden="true" style={{ fontSize: 64, marginBottom: 16 }}>&#x1F6E1;</div>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>
          {t("heading")}
        </h1>
        <p style={{ color: "#94a3b8", fontSize: 16, lineHeight: 1.6, marginBottom: 24 }}>
          {t("body")}
        </p>

        {shownCode && (
          <div data-testid="ref-code" style={{ background: "#1e293b", borderRadius: 12, padding: 20, marginBottom: 24, border: "1px solid #22c55e40" }}>
            <div style={{ fontSize: 14, color: "#8796ab", marginBottom: 4 }}>{t("code_label")}</div>
            <div style={{ fontSize: 24, fontWeight: 800, color: "#22c55e", letterSpacing: 2 }}>{shownCode}</div>
            <div style={{ fontSize: 13, color: "#94a3b8", marginTop: 8 }}>{t("code_note")}</div>
          </div>
        )}

        <PrimaryInstallLink androidLabel={hero("cta_android")} style={{
          display: "inline-block", background: "#22c55e", color: "#052e16",
          padding: "14px 32px", borderRadius: 10, fontWeight: 700, fontSize: 16, textDecoration: "none",
          marginBottom: 12,
        }}>
          {hero("cta_primary")}
        </PrimaryInstallLink>

        <div style={{ marginTop: 16, marginBottom: 16 }}>
          <InstallButtons platforms={["android", "ios"]} size="sm" />
        </div>
        <div>
          <InstallButtons platforms={["chrome", "firefox", "edge", "safari"]} size="sm" />
        </div>
      </main>
    </div>
  );
}
