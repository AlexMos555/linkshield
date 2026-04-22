export default function BusinessPage() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 24px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <a href="/" style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>Cleanway</a>
          <a href="/business#pricing" style={{ background: "#3b82f6", color: "white", padding: "8px 18px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>Start Free Trial</a>
        </div>
      </nav>

      <div style={{ maxWidth: 900, margin: "0 auto", padding: "60px 24px" }}>
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{ display: "inline-block", background: "#3b82f620", color: "#3b82f6", border: "1px solid #3b82f640", padding: "6px 16px", borderRadius: 20, fontSize: 13, fontWeight: 600, marginBottom: 24 }}>
            For Teams &amp; Organizations
          </div>
          <h1 style={{ fontSize: 42, fontWeight: 800, color: "#f8fafc", lineHeight: 1.2, marginBottom: 16 }}>
            Phishing protection +<br />
            <span style={{ background: "linear-gradient(135deg, #3b82f6, #22c55e)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              simulation training
            </span>
          </h1>
          <p style={{ fontSize: 18, color: "#94a3b8", maxWidth: 600, margin: "0 auto" }}>
            Real-time link blocking + phishing simulations.
            $3.99/user/month. No minimum seats. No sales call.
          </p>
        </div>

        {/* Comparison */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 48 }}>
          <div style={{ background: "#1e293b", borderRadius: 14, padding: 24 }}>
            <h3 style={{ fontSize: 18, fontWeight: 700, color: "#ef4444", marginBottom: 12 }}>KnowBe4</h3>
            <ul style={{ listStyle: "none", padding: 0, color: "#94a3b8", fontSize: 14, lineHeight: 2 }}>
              <li>25-seat minimum</li>
              <li>$16-35/user/year</li>
              <li>Training only — no real-time blocking</li>
              <li>Enterprise sales cycle</li>
              <li>No browser extension</li>
            </ul>
          </div>
          <div style={{ background: "#1e293b", borderRadius: 14, padding: 24, border: "1px solid #22c55e40" }}>
            <h3 style={{ fontSize: 18, fontWeight: 700, color: "#22c55e", marginBottom: 12 }}>Cleanway Business</h3>
            <ul style={{ listStyle: "none", padding: 0, color: "#94a3b8", fontSize: 14, lineHeight: 2 }}>
              <li style={{ color: "#22c55e" }}>1-seat minimum</li>
              <li style={{ color: "#22c55e" }}>$3.99/user/month ($48/year)</li>
              <li style={{ color: "#22c55e" }}>Real-time blocking + simulation</li>
              <li style={{ color: "#22c55e" }}>Self-service signup</li>
              <li style={{ color: "#22c55e" }}>Browser + mobile protection</li>
            </ul>
          </div>
        </div>

        {/* Features */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 48 }}>
          {[
            { icon: "\uD83D\uDEE1", title: "Real-Time Blocking", desc: "Every link checked before your team clicks it. 9 threat sources + ML." },
            { icon: "\uD83C\uDFA3", title: "Phishing Simulation", desc: "4 templates: generic, credential harvest, invoice scam, CEO fraud." },
            { icon: "\uD83D\uDCCA", title: "Org Dashboard", desc: "Aggregate threat stats. Individual browsing is never visible." },
            { icon: "\uD83D\uDD12", title: "SSO Support", desc: "SAML/OIDC. Your team signs in with existing credentials." },
            { icon: "\uD83D\uDCE7", title: "Email Proxy", desc: "Check links in emails before they reach the inbox." },
            { icon: "\uD83D\uDC65", title: "No Minimum Seats", desc: "Start with 1 user. Scale when ready. No contracts." },
          ].map((f, i) => (
            <div key={i} style={{ background: "#1e293b", borderRadius: 12, padding: 20 }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>{f.icon}</div>
              <h4 style={{ color: "#f8fafc", fontSize: 15, fontWeight: 700, marginBottom: 6 }}>{f.title}</h4>
              <p style={{ color: "#94a3b8", fontSize: 13, lineHeight: 1.5 }}>{f.desc}</p>
            </div>
          ))}
        </div>

        {/* Pricing */}
        <div id="pricing" style={{ background: "#1e293b", borderRadius: 16, padding: 32, textAlign: "center", marginBottom: 48 }}>
          <h2 style={{ fontSize: 24, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>$3.99/user/month</h2>
          <p style={{ color: "#94a3b8", marginBottom: 24 }}>Billed monthly. Cancel anytime. 14-day free trial.</p>
          <p style={{ color: "#64748b", fontSize: 14 }}>Includes: real-time blocking, phishing simulation, org dashboard, SSO, API access, priority support.</p>
          <a href="mailto:business@cleanway.ai" style={{ display: "inline-block", background: "#3b82f6", color: "white", padding: "14px 32px", borderRadius: 10, fontWeight: 700, fontSize: 16, textDecoration: "none", marginTop: 20 }}>
            Start Free Trial
          </a>
        </div>
      </div>
    </div>
  );
}
