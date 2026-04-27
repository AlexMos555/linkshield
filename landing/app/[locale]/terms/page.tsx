import type { Metadata } from "next";

import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string, path: string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}${path}` : `${SITE_URL}/${locale}${path}`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const canonical = urlFor(safeLocale, "/terms");

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, "/terms");
  languages["x-default"] = urlFor(routing.defaultLocale, "/terms");

  const title = "Terms of Service — Cleanway";
  const description =
    "Cleanway terms of service: account responsibilities, billing, acceptable use, refund policy, governing law.";

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title,
      description,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      locale: safeLocale,
    },
    twitter: {
      card: "summary",
      title,
      description,
      site: "@cleanwayai",
    },
    robots: { index: true, follow: true },
  };
}

export default function Terms() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <div style={{ maxWidth: 760, margin: "0 auto", padding: "60px 24px" }}>
        <a href="/" style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>&larr; Back to Cleanway</a>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", margin: "24px 0 8px" }}>Terms of Service</h1>
        <p style={{ color: "#64748b", marginBottom: 40 }}>Last updated: April 7, 2026</p>

        <S t="1. Service Description">
          <p>Cleanway provides phishing protection through browser extensions, mobile applications, and web APIs. The service checks domain names against threat intelligence databases and provides risk assessments.</p>
        </S>

        <S t="2. Accounts">
          <p>You must provide accurate information when creating an account. You are responsible for maintaining the security of your account credentials. One person or entity per account.</p>
        </S>

        <S t="3. Free and Paid Plans">
          <p>Cleanway offers free and paid subscription plans. Free plans include limited API checks per day. Paid plans provide unlimited checks and additional features.</p>
          <p>Paid subscriptions are billed monthly or annually through Stripe, Apple In-App Purchase, or Google Play Billing. All subscriptions include a 14-day free trial.</p>
          <p>You may cancel your subscription at any time. Cancellation takes effect at the end of the current billing period. No refunds are provided for partial billing periods.</p>
        </S>

        <S t="4. Acceptable Use">
          <p>You agree NOT to:</p>
          <ul>
            <li>Use the API to test or validate phishing domains for malicious purposes</li>
            <li>Attempt to reverse-engineer the scoring algorithm or ML model</li>
            <li>Circumvent rate limits or create multiple free accounts</li>
            <li>Resell, redistribute, or commercially exploit API access</li>
            <li>Use the service to generate false security reports about legitimate businesses</li>
            <li>Submit automated bulk requests beyond your plan limits</li>
            <li>Interfere with the service or its infrastructure</li>
          </ul>
          <p>Violation may result in immediate account suspension.</p>
        </S>

        <S t="5. Accuracy and Limitations">
          <p>Cleanway provides risk assessments based on multiple data sources and machine learning. These assessments are advisory and not definitive.</p>
          <p><strong>We do not guarantee:</strong></p>
          <ul>
            <li>100% detection of all phishing or malicious sites</li>
            <li>Zero false positives (safe sites incorrectly flagged)</li>
            <li>Real-time detection of newly created phishing sites</li>
            <li>Protection against all forms of online fraud</li>
          </ul>
          <p>Cleanway is one layer of protection and should be used alongside other security practices (strong passwords, 2FA, caution with suspicious emails).</p>
        </S>

        <S t="6. Privacy">
          <p>Your use of Cleanway is governed by our <a href="/privacy-policy" style={{ color: "#60a5fa" }}>Privacy Policy</a>. In summary: your browsing data stays on your device, and our servers store only account information.</p>
        </S>

        <S t="7. Intellectual Property">
          <p>Cleanway and its original content, features, and functionality are owned by Cleanway and protected by international copyright, trademark, and other intellectual property laws.</p>
          <p>The browser extension client-side code is open source. The server-side scoring engine, ML models, and threat intelligence aggregation are proprietary.</p>
        </S>

        <S t="8. Limitation of Liability">
          <p>Cleanway is provided &quot;as is&quot; without warranties of any kind. To the maximum extent permitted by law, Cleanway shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of data, loss of profits, or business interruption.</p>
          <p>Our total liability for any claim shall not exceed the amount you paid for the service in the 12 months preceding the claim.</p>
        </S>

        <S t="9. Termination">
          <p>We may suspend or terminate your account if you violate these terms. You may delete your account at any time from Settings. Upon termination, all server-side data is deleted within 30 days.</p>
        </S>

        <S t="10. Changes">
          <p>We may update these terms. Material changes will be communicated via email or in-app notification at least 30 days in advance. Continued use after changes constitutes acceptance.</p>
        </S>

        <S t="11. Governing Law">
          <p>These terms are governed by the laws of the jurisdiction in which Cleanway operates, without regard to conflict of law provisions.</p>
        </S>

        <S t="12. Contact">
          <p>Questions about these terms: <a href="mailto:legal@cleanway.ai" style={{ color: "#60a5fa" }}>legal@cleanway.ai</a></p>
        </S>
      </div>
    </div>
  );
}

function S({ t, children }: { t: string; children: React.ReactNode }) {
  return (
    <section style={{ marginBottom: 32 }}>
      <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 12 }}>{t}</h2>
      <div style={{ fontSize: 15, lineHeight: 1.8, color: "#94a3b8" }}>{children}</div>
    </section>
  );
}
