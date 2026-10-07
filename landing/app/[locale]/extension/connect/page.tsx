import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";

import ConnectClient from "./ConnectClient";

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "ExtensionConnect" });
  return {
    title: t("meta_title"),
    // Opened only from the extension's "Sign in", with a one-time state.
    robots: { index: false, follow: false },
    // The state rides in this page's URL: send no Referer anywhere from here.
    referrer: "no-referrer",
  };
}

type Props = {
  params: Promise<{ locale: string }>;
  searchParams: Promise<{ state?: string | string[] }>;
};

/**
 * https://cleanway.ai/<locale>/extension/connect?state=… — where the browser
 * extension's "Sign in" lands. See lib/extension-connect.ts for the flow and
 * ConnectClient.tsx for the page itself.
 */
export default async function ExtensionConnectPage({ params, searchParams }: Props) {
  const safeLocale = resolveLocale((await params).locale);
  const { state } = await searchParams;

  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        minHeight: "100vh",
      }}
    >
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 24px" }}>
        <div style={{ maxWidth: 800, margin: "0 auto" }}>
          <a href={localePath(safeLocale, "/")} style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            Cleanway
          </a>
        </div>
      </nav>
      <main style={{ maxWidth: 480, margin: "0 auto", padding: "60px 24px" }}>
        <ConnectClient state={typeof state === "string" ? state : null} />
      </main>
    </div>
  );
}
