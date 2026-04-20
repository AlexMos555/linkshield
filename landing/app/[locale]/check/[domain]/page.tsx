import type { Metadata } from "next";

type Props = { params: Promise<{ domain: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain } = await params;
  return {
    title: `Is ${domain} safe? — LinkShield Safety Check`,
    description: `Check if ${domain} is a phishing or scam website. Free safety analysis with 42+ detection signals and 9 threat intelligence sources.`,
    openGraph: {
      title: `Is ${domain} safe?`,
      description: `LinkShield safety report for ${domain}`,
      url: `https://linkshield.io/check/${domain}`,
    },
  };
}

export default async function CheckPage({ params }: Props) {
  const { domain } = await params;
  const decodedDomain = decodeURIComponent(domain);

  // Fetch from API (server-side)
  let result: any = null;
  try {
    const apiBase = process.env.NEXT_PUBLIC_API_URL || process.env.API_URL || "https://web-production-fe08.up.railway.app";
    const resp = await fetch(`${apiBase}/api/v1/public/check/${decodedDomain}`, {
      next: { revalidate: 3600 }, // Cache for 1 hour
    });
    if (resp.ok) result = await resp.json();
  } catch (e) {
    // API unavailable — show fallback
  }

  const levelColors: Record<string, string> = {
    safe: "#22c55e",
    caution: "#f59e0b",
    dangerous: "#ef4444",
  };

  const levelIcons: Record<string, string> = {
    safe: "\u2705",
    caution: "\u26A0\uFE0F",
    dangerous: "\u274C",
  };

  const levelLabels: Record<string, string> = {
    safe: "Safe",
    caution: "Caution",
    dangerous: "Dangerous",
  };

  const level = result?.level || "caution";
  const score = result?.score ?? "?";
  const color = levelColors[level] || "#64748b";

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 24px" }}>
        <div style={{ maxWidth: 800, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <a href="/" style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>LinkShield</a>
          <a href="https://chrome.google.com/webstore" style={{ background: "#22c55e", color: "#052e16", padding: "8px 18px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>Add to Chrome</a>
        </div>
      </nav>

      <div style={{ maxWidth: 800, margin: "0 auto", padding: "48px 24px" }}>
        {/* Main Result Card */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: "32px", border: `1px solid ${color}40`, marginBottom: 24 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
            <div style={{ width: 64, height: 64, borderRadius: "50%", background: `${color}20`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 32 }}>
              {levelIcons[level]}
            </div>
            <div>
              <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: 0 }}>
                Is {decodedDomain} safe?
              </h1>
              <p style={{ fontSize: 18, color, fontWeight: 600, margin: "4px 0 0" }}>
                {levelLabels[level]} &mdash; Score: {score}/100
              </p>
            </div>
          </div>

          {result?.verdict && (
            <p style={{ fontSize: 16, color: "#94a3b8", lineHeight: 1.6, marginBottom: 20 }}>
              {result.verdict}
            </p>
          )}

          {result?.signals && result.signals.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 14, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>Detection Signals</h3>
              {result.signals.map((s: string, i: number) => (
                <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", fontSize: 14, color: "#94a3b8" }}>
                  <span style={{ color }}>&#x2022;</span>
                  <span>{s}</span>
                </div>
              ))}
            </div>
          )}

          {result?.confidence === "low" && (
            <p style={{ fontSize: 13, color: "#f59e0b", fontStyle: "italic" }}>
              This is a basic analysis. Install LinkShield for real-time protection with 9 threat intelligence sources.
            </p>
          )}
        </div>

        {/* CTA */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 24, textAlign: "center" }}>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 8 }}>
            Get real-time protection
          </h2>
          <p style={{ fontSize: 14, color: "#94a3b8", marginBottom: 16 }}>
            LinkShield checks every link automatically. 9 threat sources, ML-powered, zero data stored.
          </p>
          <a href="https://chrome.google.com/webstore" style={{ display: "inline-block", background: "#22c55e", color: "#052e16", padding: "12px 28px", borderRadius: 10, fontWeight: 700, fontSize: 15, textDecoration: "none" }}>
            Add to Chrome &mdash; Free
          </a>
        </div>

        {/* SEO: Structured Data */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@type": "WebPage",
              name: `Is ${decodedDomain} safe? - LinkShield`,
              description: `Safety check for ${decodedDomain}. Score: ${score}/100.`,
              url: `https://linkshield.io/check/${decodedDomain}`,
            }),
          }}
        />

        {/* Check Another */}
        <div style={{ marginTop: 32, textAlign: "center" }}>
          <p style={{ color: "#64748b", fontSize: 14, marginBottom: 12 }}>Check another domain:</p>
          <form action="/check" method="get" style={{ display: "flex", gap: 8, maxWidth: 400, margin: "0 auto" }}>
            <input name="q" placeholder="Enter domain..." style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: "1px solid #334155", background: "#0f172a", color: "#e2e8f0", fontSize: 14, outline: "none" }} />
            <button type="submit" style={{ background: "#3b82f6", color: "white", border: "none", padding: "10px 20px", borderRadius: 8, fontWeight: 600, cursor: "pointer" }}>Check</button>
          </form>
        </div>

        <p style={{ textAlign: "center", fontSize: 12, color: "#475569", marginTop: 32 }}>
          Data from 9 threat intelligence sources. Updated in real-time. <a href="/privacy-policy" style={{ color: "#60a5fa" }}>Privacy Policy</a>
        </p>
      </div>
    </div>
  );
}
