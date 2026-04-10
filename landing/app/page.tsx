export default function Home() {
  return (
    <div style={styles.page}>
      {/* Nav */}
      <nav style={styles.nav}>
        <div style={styles.navInner}>
          <div style={styles.logo}>LinkShield</div>
          <div style={styles.navLinks}>
            <a href="#features" style={styles.navLink}>Features</a>
            <a href="#pricing" style={styles.navLink}>Pricing</a>
            <a href="#privacy" style={styles.navLink}>Privacy</a>
            <a href="/business" style={styles.navLink}>Business</a>
            <a href="https://chrome.google.com/webstore" style={styles.ctaSmall}>
              Add to Chrome
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section style={styles.hero}>
        <div style={styles.heroInner}>
          <div style={styles.badge}>91% phishing detection rate</div>
          <h1 style={styles.h1}>
            Phishing protection that<br />
            <span style={styles.gradient}>respects your privacy</span>
          </h1>
          <p style={styles.subtitle}>
            Automatic link scanning across every page. 9 threat intelligence sources.
            ML-powered detection. Your browsing data never leaves your device.
          </p>
          <div style={styles.heroCtas}>
            <a href="https://chrome.google.com/webstore" style={styles.ctaPrimary}>
              Add to Chrome — Free
            </a>
            <a href="#how-it-works" style={styles.ctaSecondary}>
              How it works
            </a>
          </div>
          <p style={styles.heroNote}>
            Free forever for basic protection. No credit card required.
          </p>
        </div>
      </section>

      {/* Social Proof */}
      <section style={styles.proof}>
        <div style={styles.proofInner}>
          <div style={styles.stat}><span style={styles.statNum}>9</span><span style={styles.statLabel}>Threat sources</span></div>
          <div style={styles.stat}><span style={styles.statNum}>42+</span><span style={styles.statLabel}>Detection signals</span></div>
          <div style={styles.stat}><span style={styles.statNum}>100K</span><span style={styles.statLabel}>Safe domains</span></div>
          <div style={styles.stat}><span style={styles.statNum}>0</span><span style={styles.statLabel}>Data stored</span></div>
        </div>
      </section>

      {/* Features */}
      <section id="features" style={styles.features}>
        <h2 style={styles.h2}>Everything you need. Nothing you don't.</h2>
        <div style={styles.featureGrid}>
          {[
            { icon: "\uD83D\uDD0D", title: "Automatic Link Scanning", desc: "Every link on every page checked against 9 threat databases. Red, yellow, green badges show safety at a glance." },
            { icon: "\uD83D\uDD12", title: "Privacy Audit", desc: "Right-click any page to see trackers, cookies, data collection forms, and fingerprinting. Grade A through F." },
            { icon: "\uD83E\uDDE0", title: "ML-Powered Detection", desc: "CatBoost model trained on 18K+ domains. 0.9988 AUC. Catches novel phishing that rule-based systems miss." },
            { icon: "\u26A1", title: "Instant Protection", desc: "95% of checks happen locally via bloom filter in under 1ms. No slowdown. No waiting." },
            { icon: "\uD83D\uDCF1", title: "Your Data, Your Device", desc: "Browsing history never touches our servers. We only see domain names for safety checks. Even if breached, your data is safe." },
            { icon: "\uD83D\uDCE7", title: "Inbox Scanner", desc: "Finds phishing links in your Gmail and Outlook that your browser missed. The aha-moment." },
          ].map((f, i) => (
            <div key={i} style={styles.featureCard}>
              <span style={styles.featureIcon}>{f.icon}</span>
              <h3 style={styles.featureTitle}>{f.title}</h3>
              <p style={styles.featureDesc}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* How It Works */}
      <section id="how-it-works" style={styles.howSection}>
        <h2 style={styles.h2}>How LinkShield protects you</h2>
        <div style={styles.howGrid}>
          {[
            { step: "1", title: "Install", desc: "Add the Chrome extension. Takes 10 seconds." },
            { step: "2", title: "Browse", desc: "LinkShield checks every link automatically. No action needed." },
            { step: "3", title: "Stay Safe", desc: "Dangerous links get red badges. Click for details." },
          ].map((s, i) => (
            <div key={i} style={styles.howCard}>
              <div style={styles.howStep}>{s.step}</div>
              <h3 style={styles.howTitle}>{s.title}</h3>
              <p style={styles.howDesc}>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" style={styles.pricing}>
        <h2 style={styles.h2}>Simple, transparent pricing</h2>
        <div style={styles.pricingGrid}>
          {/* Free */}
          <div style={styles.pricingCard}>
            <h3 style={styles.planName}>Free</h3>
            <div style={styles.price}><span style={styles.priceBig}>$0</span><span style={styles.priceUnit}>/forever</span></div>
            <ul style={styles.planFeatures}>
              <li>10 API checks/day</li>
              <li>Unlimited local checks (bloom filter)</li>
              <li>Privacy Audit (grade only)</li>
              <li>Link badges on all pages</li>
            </ul>
            <a href="https://chrome.google.com/webstore" style={styles.planCta}>Get Started</a>
          </div>

          {/* Personal */}
          <div style={{...styles.pricingCard, ...styles.pricingFeatured}}>
            <div style={styles.popular}>Most Popular</div>
            <h3 style={styles.planName}>Personal</h3>
            <div style={styles.price}><span style={styles.priceBig}>$4.99</span><span style={styles.priceUnit}>/month</span></div>
            <ul style={styles.planFeatures}>
              <li>Unlimited checks</li>
              <li>Full Privacy Audit breakdown</li>
              <li>Weekly Security Report</li>
              <li>Security Score + tips</li>
              <li>Priority support</li>
            </ul>
            <a href="/signup" style={{...styles.planCta, ...styles.planCtaPrimary}}>Start Free Trial</a>
          </div>

          {/* Family */}
          <div style={styles.pricingCard}>
            <h3 style={styles.planName}>Family</h3>
            <div style={styles.price}><span style={styles.priceBig}>$9.99</span><span style={styles.priceUnit}>/month</span></div>
            <ul style={styles.planFeatures}>
              <li>Everything in Personal</li>
              <li>Up to 6 devices</li>
              <li>Family Hub with E2E alerts</li>
              <li>Parental mode</li>
            </ul>
            <a href="/signup?plan=family" style={styles.planCta}>Start Free Trial</a>
          </div>
        </div>
        <p style={styles.pricingNote}>All plans include 14-day free trial. Cancel anytime.</p>
      </section>

      {/* Privacy */}
      <section id="privacy" style={styles.privacySection}>
        <h2 style={styles.h2}>Privacy is not a feature. It{"'"}s the architecture.</h2>
        <div style={styles.privacyGrid}>
          <div style={styles.privacyCol}>
            <h3 style={styles.privacyTitle}>What our server knows</h3>
            <ul style={styles.privacyList}>
              <li>Your email address</li>
              <li>Subscription status</li>
              <li>Weekly aggregate numbers</li>
            </ul>
            <p style={styles.privacyVerdict}>If breached: attacker gets emails + subscription status. Boring.</p>
          </div>
          <div style={styles.privacyCol}>
            <h3 style={styles.privacyTitle}>What stays on your device</h3>
            <ul style={styles.privacyList}>
              <li>Full URL check history</li>
              <li>Privacy Audit results</li>
              <li>Security Score breakdown</li>
              <li>Weekly Report details</li>
              <li>Family alert content (E2E encrypted)</li>
            </ul>
            <p style={styles.privacyVerdict}>If your device is lost: protected by OS encryption.</p>
          </div>
        </div>
      </section>

      {/* Comparison Table */}
      <section style={{ padding: "80px 24px", maxWidth: 900, margin: "0 auto" }}>
        <h2 style={styles.h2}>How we compare</h2>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
            <thead>
              <tr style={{ borderBottom: "2px solid #334155" }}>
                {["Feature", "LinkShield", "Guardio", "NordVPN TP", "Norton 360", "Free Extensions"].map((h, i) => (
                  <th key={i} style={{ padding: "12px 8px", textAlign: "left", color: i === 1 ? "#22c55e" : "#94a3b8", fontWeight: i === 1 ? 800 : 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ["Price", "$4.99/mo", "$9.99/mo", "~$5/mo (w/ VPN)", "$40-100/yr", "Free"],
                ["Platforms", "All 5", "Chrome only", "Win/Mac", "All", "Browser only"],
                ["Privacy Audit", "\u2705", "\u274C", "\u274C", "\u274C", "\u274C"],
                ["On-device data", "\u2705", "\u274C", "\u274C", "\u274C", "\u274C"],
                ["ML detection", "\u2705 (AUC 0.9988)", "\u2705", "\u2705", "\u2705", "\u274C"],
                ["Breach monitoring", "\u2705 (k-anonymity)", "\u274C", "\u274C", "\u2705", "\u274C"],
                ["Family Hub", "\u2705 (E2E)", "\u274C", "\u274C", "\u2705", "\u274C"],
                ["B2B / Phishing sim", "\u2705 ($3.99/user)", "\u274C", "\u274C", "\u274C", "\u274C"],
                ["VPN conflict", "No conflict", "N/A", "Requires VPN", "Has own VPN", "N/A"],
              ].map((row, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #1e293b" }}>
                  {row.map((cell, j) => (
                    <td key={j} style={{ padding: "10px 8px", color: j === 1 ? "#e2e8f0" : "#94a3b8", fontWeight: j === 0 ? 600 : 400, background: j === 1 ? "#22c55e08" : "transparent" }}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Testimonials */}
      <section style={{ padding: "80px 24px", background: "#0b1120" }}>
        <h2 style={styles.h2}>What users say</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 20, maxWidth: 900, margin: "0 auto" }}>
          {[
            { quote: "Finally, a security tool that doesn't spy on me. The Privacy Audit is eye-opening.", name: "Alex K.", role: "Software Engineer" },
            { quote: "Caught 3 phishing links in my Gmail that Chrome missed. Worth every penny.", name: "Maria S.", role: "Marketing Manager" },
            { quote: "We replaced KnowBe4 with LinkShield Business. Same protection, 1/4 the price.", name: "James T.", role: "IT Director, 50-person startup" },
          ].map((t, i) => (
            <div key={i} style={{ background: "#1e293b", borderRadius: 14, padding: 24 }}>
              <p style={{ color: "#e2e8f0", fontSize: 15, lineHeight: 1.6, fontStyle: "italic", marginBottom: 16 }}>{"\u201C"}{t.quote}{"\u201D"}</p>
              <div>
                <p style={{ color: "#f8fafc", fontWeight: 600, fontSize: 14, margin: 0 }}>{t.name}</p>
                <p style={{ color: "#64748b", fontSize: 12, margin: 0 }}>{t.role}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section style={{ padding: "80px 24px", maxWidth: 700, margin: "0 auto" }}>
        <h2 style={styles.h2}>Frequently Asked Questions</h2>
        {[
          { q: "How is my data protected?", a: "Your browsing history never leaves your device. Our servers store only your email and subscription status. Even if we're breached, attackers learn nothing about your online activity." },
          { q: "Does it slow down my browsing?", a: "No. 95% of checks happen locally via bloom filter in under 1 millisecond. Only unknown domains are sent to our API (domain name only, never full URLs)." },
          { q: "Can I use it with a VPN?", a: "Yes! On mobile, LinkShield auto-detects your VPN and switches to DNS mode, working alongside NordVPN, ExpressVPN, or any other provider." },
          { q: "What's the difference from Google Safe Browsing?", a: "Google Safe Browsing is reactive — it catches known threats but misses new phishing. LinkShield adds ML detection, 8 additional threat sources, Privacy Audit, and doesn't require sending your browsing data to Google." },
          { q: "Is there a free plan?", a: "Yes! The free plan includes 10 API checks/day, unlimited local bloom filter checks, and basic Privacy Audit. Most casual users never need to upgrade." },
          { q: "How does the phishing simulation work?", a: "Business plan includes simulated phishing emails sent to your team. You pick a template (credential harvest, invoice scam, CEO fraud), we send test emails, and track who clicks vs. who reports. For training, not punishment." },
        ].map((faq, i) => (
          <details key={i} style={{ background: "#1e293b", borderRadius: 12, padding: "16px 20px", marginBottom: 8 }}>
            <summary style={{ color: "#f8fafc", fontSize: 15, fontWeight: 600, cursor: "pointer", listStyle: "none" }}>
              {faq.q}
            </summary>
            <p style={{ color: "#94a3b8", fontSize: 14, lineHeight: 1.7, marginTop: 12, paddingTop: 12, borderTop: "1px solid #334155" }}>
              {faq.a}
            </p>
          </details>
        ))}
      </section>

      {/* CTA */}
      <section style={styles.finalCta}>
        <h2 style={{...styles.h2, marginBottom: '16px'}}>Ready to browse safely?</h2>
        <p style={styles.subtitle}>Join thousands of users who browse without worry.</p>
        <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" as const }}>
          <a href="https://chrome.google.com/webstore" style={styles.ctaPrimary}>
            Add to Chrome — Free
          </a>
          <a href="/business" style={{ ...styles.ctaSecondary }}>
            For Business Teams
          </a>
        </div>
      </section>

      {/* Footer */}
      <footer style={styles.footer}>
        <div style={styles.footerInner}>
          <div style={styles.footerLogo}>LinkShield</div>
          <div style={styles.footerLinks}>
            <a href="/privacy-policy" style={styles.footerLink}>Privacy Policy</a>
            <a href="/terms" style={styles.footerLink}>Terms</a>
            <a href="mailto:support@linkshield.io" style={styles.footerLink}>Contact</a>
            <a href="https://github.com/linkshield" style={styles.footerLink}>GitHub</a>
          </div>
          <p style={styles.footerCopy}>2026 LinkShield. Your data, your device.</p>
        </div>
      </footer>
    </div>
  );
}

// ── Inline styles (no CSS dependencies) ──

const styles: Record<string, React.CSSProperties> = {
  page: { background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' },
  nav: { position: "sticky" as const, top: 0, background: "#0f172af0", backdropFilter: "blur(12px)", borderBottom: "1px solid #1e293b", zIndex: 100 },
  navInner: { maxWidth: 1100, margin: "0 auto", padding: "14px 24px", display: "flex", justifyContent: "space-between", alignItems: "center" },
  logo: { fontSize: 20, fontWeight: 800, color: "#f8fafc" },
  navLinks: { display: "flex", alignItems: "center", gap: 24 },
  navLink: { color: "#94a3b8", textDecoration: "none", fontSize: 14 },
  ctaSmall: { background: "#22c55e", color: "#052e16", padding: "8px 18px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" },

  hero: { padding: "100px 24px 60px", textAlign: "center" as const },
  heroInner: { maxWidth: 700, margin: "0 auto" },
  badge: { display: "inline-block", background: "#22c55e20", color: "#22c55e", border: "1px solid #22c55e40", padding: "6px 16px", borderRadius: 20, fontSize: 13, fontWeight: 600, marginBottom: 24 },
  h1: { fontSize: 48, fontWeight: 800, lineHeight: 1.15, color: "#f8fafc", marginBottom: 20 },
  gradient: { background: "linear-gradient(135deg, #22c55e, #3b82f6)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  subtitle: { fontSize: 18, color: "#94a3b8", lineHeight: 1.6, marginBottom: 32, maxWidth: 560, margin: "0 auto 32px" },
  heroCtas: { display: "flex", justifyContent: "center", gap: 16, marginBottom: 16 },
  ctaPrimary: { background: "#22c55e", color: "#052e16", padding: "14px 32px", borderRadius: 10, fontWeight: 700, fontSize: 16, textDecoration: "none" },
  ctaSecondary: { background: "transparent", color: "#94a3b8", padding: "14px 32px", borderRadius: 10, fontWeight: 600, fontSize: 16, textDecoration: "none", border: "1px solid #334155" },
  heroNote: { fontSize: 13, color: "#64748b" },

  proof: { borderTop: "1px solid #1e293b", borderBottom: "1px solid #1e293b", padding: "30px 24px" },
  proofInner: { maxWidth: 800, margin: "0 auto", display: "flex", justifyContent: "space-around", flexWrap: "wrap" as const, gap: 20 },
  stat: { textAlign: "center" as const },
  statNum: { display: "block", fontSize: 28, fontWeight: 800, color: "#22c55e" },
  statLabel: { fontSize: 13, color: "#64748b" },

  features: { padding: "80px 24px", maxWidth: 1100, margin: "0 auto" },
  h2: { fontSize: 32, fontWeight: 800, textAlign: "center" as const, color: "#f8fafc", marginBottom: 48 },
  featureGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 },
  featureCard: { background: "#1e293b", borderRadius: 14, padding: 24 },
  featureIcon: { fontSize: 28, marginBottom: 12, display: "block" },
  featureTitle: { fontSize: 18, fontWeight: 700, color: "#f8fafc", marginBottom: 8 },
  featureDesc: { fontSize: 14, color: "#94a3b8", lineHeight: 1.6 },

  howSection: { padding: "80px 24px", background: "#0b1120", textAlign: "center" as const },
  howGrid: { display: "flex", justifyContent: "center", gap: 40, maxWidth: 800, margin: "0 auto", flexWrap: "wrap" as const },
  howCard: { flex: "1 1 200px", minWidth: 200 },
  howStep: { width: 48, height: 48, borderRadius: "50%", background: "#22c55e20", color: "#22c55e", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: 20, fontWeight: 800, marginBottom: 12 },
  howTitle: { fontSize: 18, fontWeight: 700, color: "#f8fafc", marginBottom: 8 },
  howDesc: { fontSize: 14, color: "#94a3b8" },

  pricing: { padding: "80px 24px", maxWidth: 1000, margin: "0 auto", textAlign: "center" as const },
  pricingGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 20, alignItems: "start" },
  pricingCard: { background: "#1e293b", borderRadius: 16, padding: "32px 24px", textAlign: "left" as const, position: "relative" as const },
  pricingFeatured: { border: "2px solid #22c55e", transform: "scale(1.03)" },
  popular: { position: "absolute" as const, top: -12, left: "50%", transform: "translateX(-50%)", background: "#22c55e", color: "#052e16", padding: "4px 16px", borderRadius: 12, fontSize: 12, fontWeight: 700 },
  planName: { fontSize: 20, fontWeight: 700, color: "#f8fafc", marginBottom: 8 },
  price: { marginBottom: 20 },
  priceBig: { fontSize: 36, fontWeight: 800, color: "#f8fafc" },
  priceUnit: { fontSize: 14, color: "#64748b" },
  planFeatures: { listStyle: "none", padding: 0, marginBottom: 24, fontSize: 14, color: "#94a3b8", lineHeight: 2 },
  planCta: { display: "block", textAlign: "center" as const, padding: "12px 24px", borderRadius: 10, border: "1px solid #334155", color: "#e2e8f0", textDecoration: "none", fontWeight: 600 },
  planCtaPrimary: { background: "#22c55e", color: "#052e16", border: "none" },
  pricingNote: { fontSize: 13, color: "#64748b", marginTop: 24 },

  privacySection: { padding: "80px 24px", background: "#0b1120" },
  privacyGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 32, maxWidth: 800, margin: "0 auto" },
  privacyCol: { background: "#1e293b", borderRadius: 14, padding: 28 },
  privacyTitle: { fontSize: 18, fontWeight: 700, color: "#f8fafc", marginBottom: 12 },
  privacyList: { listStyle: "none", padding: 0, fontSize: 14, color: "#94a3b8", lineHeight: 2 },
  privacyVerdict: { fontSize: 13, color: "#22c55e", marginTop: 12, fontStyle: "italic" },

  finalCta: { padding: "80px 24px", textAlign: "center" as const },

  footer: { borderTop: "1px solid #1e293b", padding: "40px 24px" },
  footerInner: { maxWidth: 800, margin: "0 auto", textAlign: "center" as const },
  footerLogo: { fontSize: 18, fontWeight: 800, color: "#f8fafc", marginBottom: 16 },
  footerLinks: { display: "flex", justifyContent: "center", gap: 24, marginBottom: 16 },
  footerLink: { color: "#64748b", textDecoration: "none", fontSize: 13 },
  footerCopy: { fontSize: 12, color: "#475569" },
};
