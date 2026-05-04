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
  const canonical = urlFor(safeLocale, "/privacy-policy");

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, "/privacy-policy");
  languages["x-default"] = urlFor(routing.defaultLocale, "/privacy-policy");

  const title = "Privacy Policy — Cleanway";
  const description =
    "Cleanway's privacy policy. Your browsing data lives only on your device — our servers store only emails and subscription status, never URLs.";

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

export default function PrivacyPolicy() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <div style={{ maxWidth: 760, margin: "0 auto", padding: "60px 24px" }}>
        <a href="/" style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>&larr; Back to Cleanway</a>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", margin: "24px 0 8px" }}>Privacy Policy</h1>
        <p style={{ color: "#64748b", marginBottom: 40 }}>Last updated: May 4, 2026</p>

        <Section title="1. What Cleanway Does">
          <p>Cleanway is a phishing protection service that checks domain names against threat intelligence databases. We provide a browser extension, mobile app, and API.</p>
        </Section>

        <Section title="2. Our Core Privacy Principle">
          <p><strong>Your browsing data lives only on your device.</strong></p>
          <p>Our servers know WHO you are (your account). Your device knows WHAT you do (your browsing). We never combine the two. If our servers are breached, attackers get emails and subscription status &mdash; not a single URL you visited.</p>
        </Section>

        <Section title="3. What Data We Collect">
          <h4 style={{ color: "#22c55e", marginTop: 16 }}>Data stored on our servers</h4>
          <ul>
            <li>Email address (for account management and magic-link sign-in)</li>
            <li>Authentication provider (Google, Apple, or email magic link)</li>
            <li>Subscription status and tier (free, personal, family, business)</li>
            <li>Device list (anonymous device hash, platform, last seen)</li>
            <li>Weekly aggregate numbers only: total checks, total blocks, total trackers, security score number</li>
            <li>Lifetime threats-blocked counter (a number, no domains) — used to surface upgrade prompts after the freemium threshold</li>
            <li>Family membership (who is in your family group, public keys, role)</li>
            <li>Family alert ciphertexts (end-to-end encrypted; see §6)</li>
            <li>User settings (notification preferences, theme, skill level, font scale)</li>
          </ul>

          <h4 style={{ color: "#f59e0b", marginTop: 16 }}>Data stored only on your device (never sent to our servers)</h4>
          <ul>
            <li>Full URL check history with scores and reasons</li>
            <li>Privacy Audit results for every site you visit</li>
            <li>Security Score breakdown and factor details</li>
            <li>Weekly Report raw data and trends</li>
            <li>Tracker encounter log</li>
            <li>Plaintext family alert content (decrypted locally)</li>
            <li>Your Family Hub private key (never leaves the device)</li>
          </ul>

          <h4 style={{ color: "#ef4444", marginTop: 16 }}>Data we NEVER collect</h4>
          <ul>
            <li>Full URLs you visit</li>
            <li>Page content or screenshots</li>
            <li>Form data you enter on websites</li>
            <li>Browsing history</li>
            <li>IP addresses (not logged)</li>
            <li>Cookies from other sites</li>
          </ul>
        </Section>

        <Section title="4. How Domain Checking Works">
          <p>When you visit a page, our extension extracts domain names from links and sends only the domain names (e.g., &quot;example.com&quot;) to our API for checking. We never receive the full URL, path, query parameters, or page content.</p>
          <p>95% of checks happen locally on your device via a bloom filter, without contacting our servers at all.</p>
          <p>Our server logs contain: domain name, risk score, and timestamp. These logs do NOT contain your user ID, IP address, or any information that could link a domain check to your identity.</p>
        </Section>

        <Section title="5. Third-Party Services">
          <p>To check domain safety, we query the following third-party threat intelligence services with the domain name only:</p>
          <ul>
            <li>Google Safe Browsing API</li>
            <li>PhishTank</li>
            <li>URLhaus (abuse.ch)</li>
            <li>PhishStats</li>
            <li>ThreatFox (abuse.ch)</li>
            <li>Spamhaus DBL</li>
            <li>SURBL</li>
            <li>AlienVault OTX</li>
            <li>IPQualityScore</li>
          </ul>
          <p>These services receive only the domain name. They do not receive your identity, IP address, or any browsing context.</p>
        </Section>

        <Section title="6. Family Hub (end-to-end encryption)">
          <p>Family Hub alerts are end-to-end encrypted using <strong>curve25519 + XSalsa20-Poly1305</strong> (the libsodium <code>nacl.box</code> primitive). Each family member&apos;s device generates a keypair locally. The public half is uploaded to our server so siblings can encrypt to it; the private half <strong>never leaves the device</strong>.</p>
          <p>What our server can see:</p>
          <ul>
            <li>That you belong to a specific family group (the relationship graph)</li>
            <li>Your public key + version</li>
            <li>The ciphertext bytes of each alert (we cannot decrypt them)</li>
            <li>The 24-byte nonce + sender public key per envelope</li>
            <li>Timestamps and recipient routing (which encrypted blob is addressed to which user)</li>
            <li>The alert type label (e.g., <code>block</code>) — chosen by your client; defaults to a single neutral value</li>
          </ul>
          <p>What our server <strong>cannot</strong> see — even if compromised:</p>
          <ul>
            <li>Which domain was blocked</li>
            <li>The threat score, level, or reasoning</li>
            <li>Any free-form fields the sender attached</li>
          </ul>
          <p><strong>Invite tokens</strong> (code + 4-digit PIN) are stored as <code>sha256</code> + <code>bcrypt</code> hashes respectively. The raw values are shown to the inviter exactly once at creation time; we cannot retrieve them later.</p>
          <p>If you delete your account or remove yourself from a family, we revoke your public key and remove pending alerts addressed to you. Past alerts already decrypted on your device remain on that device.</p>
        </Section>

        <Section title="7. Payments">
          <p>Payments are processed by Stripe. We do not store credit card numbers, bank account details, or other financial information. We receive only a Stripe customer ID + the result of each charge (succeeded / failed / refunded). Stripe&apos;s privacy policy applies to payment processing.</p>
          <p>Regional pricing is determined by your <em>billing country</em> (declared during Stripe checkout), not your IP address. We do not track or geolocate your traffic to set prices.</p>
        </Section>

        <Section title="7a. Error tracking (Sentry)">
          <p>When the extension, mobile app, or our website encounters a software error, we send a stack trace + browser/OS metadata to Sentry to help us fix bugs. We mask all DOM text and form inputs in any session replay so the contents of pages you visit are never captured.</p>
          <p>Error reports are kept for 90 days then deleted. You can opt out by setting <code>NEXT_PUBLIC_SENTRY_DSN</code> to an empty string in a self-hosted build, or by blocking the Sentry domain in your network rules.</p>
        </Section>

        <Section title="8. Data Retention">
          <ul>
            <li>Account data: retained until you delete your account</li>
            <li>Weekly aggregates: retained for 1 year, then deleted</li>
            <li>Family alerts: automatically deleted after 7 days</li>
            <li>On-device history: 30-day rolling retention (managed by your device)</li>
            <li>Server logs: retained for 30 days for debugging, then deleted</li>
          </ul>
        </Section>

        <Section title="9. Your Rights (GDPR)">
          <ul>
            <li><strong>Access:</strong> You can export all your server-side data from Settings.</li>
            <li><strong>Deletion:</strong> Delete your account from Settings. All server data is permanently removed within 30 days.</li>
            <li><strong>Portability:</strong> Export your on-device data as JSON from the extension settings.</li>
            <li><strong>Correction:</strong> Update your email or display name from Settings.</li>
            <li><strong>Objection:</strong> You can disable anonymous usage statistics from extension settings.</li>
          </ul>
        </Section>

        <Section title="10. Children">
          <p>Cleanway is not directed at children under 13. We do not knowingly collect personal data from children under 13. Family Hub parental features are managed by the account holder (parent/guardian).</p>
        </Section>

        <Section title="11. Changes to This Policy">
          <p>We will notify you of material changes via email or in-app notification at least 30 days before they take effect.</p>
        </Section>

        <Section title="12. Contact">
          <p>Email: <a href="mailto:privacy@cleanway.ai" style={{ color: "#60a5fa" }}>privacy@cleanway.ai</a></p>
        </Section>
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginBottom: 32 }}>
      <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 12 }}>{title}</h2>
      <div style={{ fontSize: 15, lineHeight: 1.8, color: "#94a3b8" }}>{children}</div>
      <style>{`section ul { padding-left: 20px; } section li { margin-bottom: 4px; }`}</style>
    </section>
  );
}
