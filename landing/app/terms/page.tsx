export default function Terms() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <div style={{ maxWidth: 760, margin: "0 auto", padding: "60px 24px" }}>
        <a href="/" style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>&larr; Back to LinkShield</a>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", margin: "24px 0 8px" }}>Terms of Service</h1>
        <p style={{ color: "#64748b", marginBottom: 40 }}>Last updated: April 7, 2026</p>

        <S t="1. Service Description">
          <p>LinkShield provides phishing protection through browser extensions, mobile applications, and web APIs. The service checks domain names against threat intelligence databases and provides risk assessments.</p>
        </S>

        <S t="2. Accounts">
          <p>You must provide accurate information when creating an account. You are responsible for maintaining the security of your account credentials. One person or entity per account.</p>
        </S>

        <S t="3. Free and Paid Plans">
          <p>LinkShield offers free and paid subscription plans. Free plans include limited API checks per day. Paid plans provide unlimited checks and additional features.</p>
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
          <p>LinkShield provides risk assessments based on multiple data sources and machine learning. These assessments are advisory and not definitive.</p>
          <p><strong>We do not guarantee:</strong></p>
          <ul>
            <li>100% detection of all phishing or malicious sites</li>
            <li>Zero false positives (safe sites incorrectly flagged)</li>
            <li>Real-time detection of newly created phishing sites</li>
            <li>Protection against all forms of online fraud</li>
          </ul>
          <p>LinkShield is one layer of protection and should be used alongside other security practices (strong passwords, 2FA, caution with suspicious emails).</p>
        </S>

        <S t="6. Privacy">
          <p>Your use of LinkShield is governed by our <a href="/privacy-policy" style={{ color: "#60a5fa" }}>Privacy Policy</a>. In summary: your browsing data stays on your device, and our servers store only account information.</p>
        </S>

        <S t="7. Intellectual Property">
          <p>LinkShield and its original content, features, and functionality are owned by LinkShield and protected by international copyright, trademark, and other intellectual property laws.</p>
          <p>The browser extension client-side code is open source. The server-side scoring engine, ML models, and threat intelligence aggregation are proprietary.</p>
        </S>

        <S t="8. Limitation of Liability">
          <p>LinkShield is provided &quot;as is&quot; without warranties of any kind. To the maximum extent permitted by law, LinkShield shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of data, loss of profits, or business interruption.</p>
          <p>Our total liability for any claim shall not exceed the amount you paid for the service in the 12 months preceding the claim.</p>
        </S>

        <S t="9. Termination">
          <p>We may suspend or terminate your account if you violate these terms. You may delete your account at any time from Settings. Upon termination, all server-side data is deleted within 30 days.</p>
        </S>

        <S t="10. Changes">
          <p>We may update these terms. Material changes will be communicated via email or in-app notification at least 30 days in advance. Continued use after changes constitutes acceptance.</p>
        </S>

        <S t="11. Governing Law">
          <p>These terms are governed by the laws of the jurisdiction in which LinkShield operates, without regard to conflict of law provisions.</p>
        </S>

        <S t="12. Contact">
          <p>Questions about these terms: <a href="mailto:legal@linkshield.io" style={{ color: "#60a5fa" }}>legal@linkshield.io</a></p>
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
