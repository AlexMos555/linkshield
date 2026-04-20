export default function PrivacyPolicy() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <div style={{ maxWidth: 760, margin: "0 auto", padding: "60px 24px" }}>
        <a href="/" style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>&larr; Back to LinkShield</a>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", margin: "24px 0 8px" }}>Privacy Policy</h1>
        <p style={{ color: "#64748b", marginBottom: 40 }}>Last updated: April 7, 2026</p>

        <Section title="1. What LinkShield Does">
          <p>LinkShield is a phishing protection service that checks domain names against threat intelligence databases. We provide a browser extension, mobile app, and API.</p>
        </Section>

        <Section title="2. Our Core Privacy Principle">
          <p><strong>Your browsing data lives only on your device.</strong></p>
          <p>Our servers know WHO you are (your account). Your device knows WHAT you do (your browsing). We never combine the two. If our servers are breached, attackers get emails and subscription status &mdash; not a single URL you visited.</p>
        </Section>

        <Section title="3. What Data We Collect">
          <h4 style={{ color: "#22c55e", marginTop: 16 }}>Data stored on our servers</h4>
          <ul>
            <li>Email address (for account management)</li>
            <li>Authentication provider (Google, Apple, or email)</li>
            <li>Subscription status and tier (free, personal, family)</li>
            <li>Device list (anonymous device hash, platform, last seen)</li>
            <li>Weekly aggregate numbers only: total checks, total blocks, total trackers, security score number</li>
            <li>Family membership (who is in your family group)</li>
            <li>User settings (notification preferences, theme)</li>
          </ul>

          <h4 style={{ color: "#f59e0b", marginTop: 16 }}>Data stored only on your device (never sent to our servers)</h4>
          <ul>
            <li>Full URL check history with scores and reasons</li>
            <li>Privacy Audit results for every site you visit</li>
            <li>Security Score breakdown and factor details</li>
            <li>Weekly Report raw data and trends</li>
            <li>Tracker encounter log</li>
            <li>Family alert content (end-to-end encrypted)</li>
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

        <Section title="6. Family Hub">
          <p>Family alerts are end-to-end encrypted using AES-256-GCM. Our servers relay encrypted blobs between family members but cannot decrypt them. We see: family group membership, encrypted payload, and timestamps. We cannot see: threat details, domain names, or alert content.</p>
        </Section>

        <Section title="7. Payments">
          <p>Payments are processed by Stripe. We do not store credit card numbers, bank account details, or other financial information. Stripe&apos;s privacy policy applies to payment processing.</p>
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
          <p>LinkShield is not directed at children under 13. We do not knowingly collect personal data from children under 13. Family Hub parental features are managed by the account holder (parent/guardian).</p>
        </Section>

        <Section title="11. Changes to This Policy">
          <p>We will notify you of material changes via email or in-app notification at least 30 days before they take effect.</p>
        </Section>

        <Section title="12. Contact">
          <p>Email: <a href="mailto:privacy@linkshield.io" style={{ color: "#60a5fa" }}>privacy@linkshield.io</a></p>
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
