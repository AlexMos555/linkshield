/**
 * Shared email shell — wraps every template.
 *
 * Responsibilities:
 *   - Proper HTML5 doctype, lang, dir (RTL for Arabic)
 *   - Meta tags (viewport, color-scheme, format-detection)
 *   - Preheader (invisible preview text shown in inbox list)
 *   - Header with LinkShield branding
 *   - Footer with unsubscribe + address (CAN-SPAM compliance)
 *   - Signed unsubscribe URL so click can be processed without login
 *
 * Design constraints (email clients are from 1998):
 *   - Table-based layouts (React Email components handle this)
 *   - Inline styles (no <style> tags in some clients)
 *   - Max width 600px (Outlook renders >600px weirdly)
 *   - No JS, no external fonts (privacy/render consistency)
 */
import * as React from "react";
import {
  Body,
  Container,
  Head,
  Hr,
  Html,
  Link,
  Preview,
  Section,
  Text,
} from "@react-email/components";
import { isRTL, t, type Locale } from "../helpers/i18n.js";

export interface ShellProps {
  locale: Locale;
  preheader: string;
  children: React.ReactNode;
  /** Signed URL for one-click unsubscribe (List-Unsubscribe-Post + List-Unsubscribe header) */
  unsubscribeUrl?: string;
  /** View-in-browser fallback URL — optional, rendered if provided */
  viewInBrowserUrl?: string;
}

const main = {
  backgroundColor: "#f8fafc",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans Arabic', sans-serif",
  color: "#0f172a",
  lineHeight: 1.5,
};

const container = {
  maxWidth: "600px",
  margin: "0 auto",
  padding: "32px 24px",
};

const header = {
  paddingBottom: "16px",
  borderBottom: "1px solid #e2e8f0",
  marginBottom: "24px",
};

const brand = {
  fontSize: "20px",
  fontWeight: 700,
  color: "#0f172a",
  margin: 0,
  letterSpacing: "-0.02em",
};

const viewInBrowser = {
  fontSize: "11px",
  color: "#94a3b8",
  textAlign: "center" as const,
  marginBottom: "12px",
};

const footer = {
  marginTop: "32px",
  paddingTop: "16px",
  borderTop: "1px solid #e2e8f0",
  fontSize: "11px",
  color: "#64748b",
  textAlign: "center" as const,
};

const footerLink = {
  color: "#64748b",
  textDecoration: "underline",
  margin: "0 6px",
};

export function Shell({
  locale,
  preheader,
  children,
  unsubscribeUrl,
  viewInBrowserUrl,
}: ShellProps): React.ReactElement {
  const rtl = isRTL(locale);
  return (
    <Html lang={locale} dir={rtl ? "rtl" : "ltr"}>
      <Head>
        <meta charSet="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="color-scheme" content="light dark" />
        <meta name="supported-color-schemes" content="light dark" />
        <meta name="format-detection" content="telephone=no,address=no,email=no" />
        <title>{t(locale, "email.common.trust_footer")}</title>
      </Head>
      <Preview>{preheader}</Preview>
      <Body style={main}>
        <Container style={container}>
          {viewInBrowserUrl && (
            <Text style={viewInBrowser}>
              <Link href={viewInBrowserUrl} style={footerLink}>
                {t(locale, "email.common.view_in_browser")}
              </Link>
            </Text>
          )}

          <Section style={header}>
            <Text style={brand}>🛡️&nbsp;LinkShield</Text>
          </Section>

          {children}

          <Hr style={{ borderColor: "#e2e8f0", margin: "32px 0 16px" }} />

          <Section style={footer}>
            <Text style={{ ...footer, marginBottom: "8px" }}>
              {t(locale, "email.common.trust_footer")}
            </Text>
            <Text style={{ ...footer, margin: "4px 0" }}>
              {unsubscribeUrl && (
                <Link href={unsubscribeUrl} style={footerLink}>
                  {t(locale, "email.common.unsubscribe_link")}
                </Link>
              )}
              <span style={{ color: "#cbd5e1" }}>·</span>
              <Link href="https://linkshield.example/support" style={footerLink}>
                {t(locale, "email.common.support_link")}
              </Link>
            </Text>
            <Text style={{ ...footer, fontSize: "10px", color: "#94a3b8" }}>
              {t(locale, "email.common.footer_legal")}
            </Text>
            <Text style={{ ...footer, fontSize: "10px", color: "#94a3b8" }}>
              {t(locale, "email.common.footer_address")}
            </Text>
          </Section>
        </Container>
      </Body>
    </Html>
  );
}

/** Primary green action button (CTA) — inline table structure for Outlook compat */
export function Cta({ href, label }: { href: string; label: string }): React.ReactElement {
  return (
    <Section style={{ textAlign: "center", margin: "24px 0" }}>
      <Link
        href={href}
        style={{
          backgroundColor: "#22c55e",
          color: "#052e16",
          padding: "14px 28px",
          borderRadius: "10px",
          fontSize: "16px",
          fontWeight: 700,
          textDecoration: "none",
          display: "inline-block",
        }}
      >
        {label}
      </Link>
    </Section>
  );
}
