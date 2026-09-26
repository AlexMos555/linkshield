/**
 * Android download / install page — the front door of the Tele2 funnel
 * (launch-blocker B3, docs/TELE2_LAUNCH_PLAN.md).
 *
 * A Tele2 subscriber lands here on their phone. One clear CTA to download the
 * signed APK, plain-language steps, and — because a sideloaded install is
 * where a careful person gives up — the three warnings they will actually
 * meet on the way (Chrome's download warning, Samsung's Auto Blocker, Play
 * Protect), each with what to tap and why it's safe (report #13). Screenshots
 * appear next to each warning once the files exist (lib/install-screenshots.ts).
 *
 * Everything claimed here must be true today (report #11): known scam sites
 * are blocked; a brand-new one can still open; site names do reach our
 * server; only RuStore is on the way (Google Play is blocked by targetSdk).
 *
 * The APK URL is env-driven (NEXT_PUBLIC_APK_URL) so the founder points it at
 * the CDN/GitHub-Release once the signed APK is hosted, with no code change.
 * Until then the button renders as a "coming soon" pill rather than a dead link.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";
import { installScreenshotSrc, type InstallScreenshotSlot } from "@/lib/install-screenshots";
import { localePath } from "@/lib/locale-path";

const SITE_URL = "https://cleanway.ai";
const APK_URL = process.env.NEXT_PUBLIC_APK_URL || "";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/android` : `${SITE_URL}/${locale}/android`;
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
  const t = await getTranslations({ locale: safeLocale, namespace: "Android" });
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  const canonical = urlFor(safeLocale);
  // The link preview in Telegram / WhatsApp / VK is how most people will see
  // this page first, so it gets its own localized title and description and
  // the wordless brand image (no "Add to Chrome" button on an Android page).
  return {
    title: t("og_title"),
    description: t("og_description"),
    alternates: { canonical, languages },
    openGraph: {
      title: t("og_title"),
      description: t("og_description"),
      url: canonical,
      siteName: "Cleanway",
      type: "website",
      locale: safeLocale,
      images: [{ url: "/opengraph-image", width: 1200, height: 630, alt: "Cleanway" }],
    },
    twitter: {
      card: "summary_large_image",
      title: t("og_title"),
      description: t("og_description"),
      images: ["/opengraph-image"],
    },
  };
}

const card: React.CSSProperties = {
  background: "#0f1a2e",
  border: "1px solid #1e293b",
  borderRadius: 14,
  padding: 20,
  marginBottom: 16,
};

const cardTitle: React.CSSProperties = { color: "#e2e8f0", fontSize: 16, fontWeight: 600, marginBottom: 8 };
const cardBody: React.CSSProperties = { margin: 0, color: "#cbd5e1", fontSize: 14.5 };
const link: React.CSSProperties = { color: "#34d399", textDecoration: "underline" };

interface Warning {
  slot: InstallScreenshotSlot;
  title: string;
  body: string;
  after?: string;
  alt: string;
}

function WarningCard({ warning, locale }: { warning: Warning; locale: string }) {
  const src = installScreenshotSrc(locale, warning.slot);
  return (
    <section style={card} data-testid={`install-warning-${warning.slot}`}>
      <div style={cardTitle}>{warning.title}</div>
      <p style={cardBody}>{warning.body}</p>
      {warning.after && <p style={{ ...cardBody, marginTop: 10 }}>{warning.after}</p>}
      {src && (
        // A plain <img>: these are phone screenshots the founder drops into
        // public/, sized by the file itself; nothing for next/image to optimize.
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={src}
          alt={warning.alt}
          loading="lazy"
          style={{ display: "block", maxWidth: "100%", maxHeight: 520, marginTop: 14, borderRadius: 10, border: "1px solid #1e293b" }}
        />
      )}
    </section>
  );
}

export default async function AndroidPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Android" });

  const benefits = [t("benefit_1"), t("benefit_2"), t("benefit_3"), t("benefit_4")];
  const steps = [t("step_1"), t("step_2"), t("step_3"), t("step_4")];
  // In the order a person meets them: download, open the file, install.
  const warnings: Warning[] = [
    { slot: "chrome-download-warning", title: t("warn_chrome_title"), body: t("warn_chrome_body"), alt: t("screenshot_alt_chrome") },
    { slot: "samsung-auto-blocker", title: t("warn_samsung_title"), body: t("warn_samsung_body"), after: t("warn_samsung_after"), alt: t("screenshot_alt_samsung") },
    { slot: "play-protect-warning", title: t("warn_protect_title"), body: t("warn_protect_body"), alt: t("screenshot_alt_protect") },
  ];

  return (
    <main
      style={{
        maxWidth: 760,
        margin: "40px auto",
        padding: "0 24px 90px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
      }}
    >
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 34, marginBottom: 10 }}>{t("title")}</h1>
        <p style={{ color: "#94a3b8", fontSize: 17 }}>{t("subtitle")}</p>
      </header>

      {/* Primary CTA */}
      <div style={{ marginBottom: 20 }}>
        {APK_URL ? (
          <a
            href={APK_URL}
            data-testid="android-download"
            style={{
              display: "block",
              textAlign: "center",
              background: "#22c55e",
              color: "#052e16",
              fontSize: 19,
              fontWeight: 700,
              padding: "18px 24px",
              borderRadius: 14,
              textDecoration: "none",
            }}
          >
            {t("download_cta")}
          </a>
        ) : (
          <div
            style={{
              textAlign: "center",
              background: "#111827",
              border: "1px solid #1f2937",
              color: "#94a3b8",
              fontSize: 16,
              padding: "18px 24px",
              borderRadius: 14,
            }}
          >
            {t("download_soon")}
          </div>
        )}
        <p style={{ color: "#64748b", fontSize: 13.5, textAlign: "center", marginTop: 10 }}>
          {/* Without a hosted APK the steps below describe a button that is not
              on the page — say so plainly instead of letting the reader hunt
              for a download that does not exist yet. */}
          {APK_URL ? t("download_note") : t("download_soon_note")}
        </p>
      </div>

      {/* Benefits — and the honest limit right under them. */}
      <ul style={{ listStyle: "none", padding: 0, margin: "0 0 16px" }}>
        {benefits.map((b, i) => (
          <li key={i} style={{ display: "flex", gap: 12, marginBottom: 14 }}>
            <span style={{ color: "#34d399", fontWeight: 700, flexShrink: 0 }}>✓</span>
            <span style={{ fontSize: 15.5 }}>{b}</span>
          </li>
        ))}
      </ul>
      <p style={{ color: "#94a3b8", fontSize: 14.5, margin: "0 0 40px" }}>{t("honesty_note")}</p>

      {/* Install steps */}
      <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 18 }}>{t("steps_title")}</h2>
      <ol style={{ paddingLeft: 0, listStyle: "none", margin: "0 0 32px" }}>
        {steps.map((s, i) => (
          <li
            key={i}
            style={{ display: "flex", gap: 14, marginBottom: 16, alignItems: "flex-start" }}
          >
            <span
              style={{
                flexShrink: 0,
                width: 28,
                height: 28,
                borderRadius: 999,
                background: "#1e293b",
                color: "#e2e8f0",
                fontSize: 14,
                fontWeight: 700,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {i + 1}
            </span>
            <span style={{ fontSize: 15.5, paddingTop: 3 }}>{s}</span>
          </li>
        ))}
      </ol>

      {/* The three scary moments */}
      <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 10 }}>{t("warnings_title")}</h2>
      <p style={{ color: "#94a3b8", fontSize: 15, margin: "0 0 18px" }}>{t("warnings_intro")}</p>
      {warnings.map((warning) => (
        <WarningCard key={warning.slot} warning={warning} locale={safeLocale} />
      ))}

      {/* Unknown-sources explainer */}
      <section style={{ ...card, marginTop: 24, marginBottom: 40 }}>
        <div style={cardTitle}>{t("unknown_title")}</div>
        <p style={cardBody}>{t("unknown_body")}</p>
      </section>

      {/* Stores: RuStore only — Google Play is blocked by targetSdk. */}
      <h2 style={{ color: "#f8fafc", fontSize: 20, marginBottom: 16 }}>{t("stores_title")}</h2>
      <div
        style={{
          background: "#111827",
          border: "1px solid #1f2937",
          borderRadius: 12,
          padding: "14px 18px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 40,
        }}
      >
        <span style={{ color: "#e2e8f0", fontSize: 15, fontWeight: 600 }}>{t("rustore")}</span>
        <span style={{ color: "#64748b", fontSize: 13 }}>{t("store_soon")}</span>
      </div>

      {/* Anti-impersonation: the pattern scammers copy is "install our protection app". */}
      <section
        data-testid="never-calls"
        style={{ ...card, background: "#1c1917", border: "1px solid #78350f", marginBottom: 40 }}
      >
        <div style={{ ...cardTitle, color: "#fbbf24" }}>{t("never_calls_title")}</div>
        <p style={cardBody}>{t("never_calls_body")}</p>
      </section>

      {/* Honest framing */}
      <section style={{ borderTop: "1px solid #1f2937", paddingTop: 24 }}>
        <div style={cardTitle}>{t("privacy_title")}</div>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: 14.5 }}>{t("privacy_body")}</p>
        <p style={{ margin: "18px 0 0", fontSize: 14.5, display: "flex", flexWrap: "wrap", gap: "8px 20px" }}>
          <a href={localePath(safeLocale, "/privacy-policy")} style={link}>{t("links_privacy")}</a>
          <a href={localePath(safeLocale, "/support")} style={link}>{t("links_support")}</a>
        </p>
      </section>
    </main>
  );
}
