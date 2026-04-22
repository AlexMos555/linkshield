import type { Metadata } from "next";

type Props = { params: Promise<{ code: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { code } = await params;
  return {
    title: "Join Cleanway — Free 7-Day Trial",
    description: "Your friend invited you to Cleanway. Get 7 days of unlimited phishing protection free.",
  };
}

export default async function ReferralPage({ params }: Props) {
  const { code } = await params;

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center", maxWidth: 480, padding: 24 }}>
        <div style={{ fontSize: 64, marginBottom: 16 }}>&#x1F6E1;</div>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>
          Your friend invited you to Cleanway
        </h1>
        <p style={{ color: "#94a3b8", fontSize: 16, lineHeight: 1.6, marginBottom: 24 }}>
          Get <strong style={{ color: "#22c55e" }}>7 days free</strong> of unlimited phishing protection.
          Automatic link scanning, privacy audit, and ML-powered threat detection.
        </p>

        <div style={{ background: "#1e293b", borderRadius: 12, padding: 20, marginBottom: 24, border: "1px solid #22c55e40" }}>
          <div style={{ fontSize: 14, color: "#64748b", marginBottom: 4 }}>Referral code</div>
          <div style={{ fontSize: 24, fontWeight: 800, color: "#22c55e", letterSpacing: 2 }}>{code}</div>
        </div>

        <a href="https://chrome.google.com/webstore" style={{
          display: "inline-block", background: "#22c55e", color: "#052e16",
          padding: "14px 32px", borderRadius: 10, fontWeight: 700, fontSize: 16, textDecoration: "none",
          marginBottom: 12,
        }}>
          Install Cleanway
        </a>

        <p style={{ fontSize: 13, color: "#64748b" }}>
          After installing, enter code <strong>{code}</strong> in extension settings to activate your trial.
        </p>

        <div style={{ marginTop: 32, display: "flex", justifyContent: "center", gap: 24, fontSize: 13 }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#22c55e" }}>9</div>
            <div style={{ color: "#64748b" }}>Threat sources</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#f8fafc" }}>42+</div>
            <div style={{ color: "#64748b" }}>Signals</div>
          </div>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 20, fontWeight: 800, color: "#f8fafc" }}>0</div>
            <div style={{ color: "#64748b" }}>Data stored</div>
          </div>
        </div>
      </div>
    </div>
  );
}
