import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";

import RestoreClient from "./RestoreClient";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/account/restore`
    : `${SITE_URL}/${locale}/account/restore`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;

  const t = await getTranslations({ locale: safeLocale, namespace: "AccountRestore" });

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: t("page_title"),
    description: t("page_meta_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(safeLocale), languages },
    // This page only makes sense for someone who already deleted their
    // account — no value to Google's index, and surfacing it in search
    // would be confusing UX.
    robots: { index: false, follow: false },
  };
}

export default async function RestorePage({
  searchParams,
}: {
  searchParams: Promise<{ reason?: string }>;
}) {
  // `?reason=locked` is set by the auth callback / signup form / pricing
  // checkout when they detect a 410 on the user's current session. We
  // use it to render a softer headline ("Your account is on hold")
  // instead of the cold default.
  const { reason } = await searchParams;

  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        minHeight: "100vh",
      }}
    >
      <nav
        style={{
          background: "#0f172af0",
          borderBottom: "1px solid #1e293b",
          padding: "14px 24px",
        }}
      >
        <div
          style={{
            maxWidth: 800,
            margin: "0 auto",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <a
            href="/"
            style={{
              color: "#f8fafc",
              textDecoration: "none",
              fontWeight: 800,
              fontSize: 20,
            }}
          >
            Cleanway
          </a>
        </div>
      </nav>

      <main
        style={{
          maxWidth: 560,
          margin: "0 auto",
          padding: "80px 24px",
          textAlign: "center",
        }}
      >
        {/* Decorative hourglass — purely visual, not announced by
            screen readers. The state and CTA below convey the meaning. */}
        <div
          aria-hidden="true"
          style={{
            width: 96,
            height: 96,
            borderRadius: "50%",
            background: "rgba(245,158,11,0.12)",
            border: "3px solid #f59e0b",
            margin: "0 auto 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 48,
          }}
        >
          ⏳
        </div>

        <RestoreClient reason={reason ?? null} />
      </main>
    </div>
  );
}
