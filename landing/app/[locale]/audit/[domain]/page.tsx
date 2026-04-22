import type { Metadata } from "next";

type Props = { params: Promise<{ domain: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain } = await params;
  return {
    title: `${domain} Privacy Audit — Cleanway`,
    description: `Privacy report for ${domain}. See trackers, cookies, data collection, and fingerprinting. Grade A-F.`,
    openGraph: {
      title: `${domain} Privacy Audit`,
      description: `How much data does ${domain} collect? Find out with Cleanway.`,
      url: `https://cleanway.ai/audit/${domain}`,
    },
  };
}

export default async function AuditPage({ params }: Props) {
  const { domain } = await params;
  const d = decodeURIComponent(domain);

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh" }}>
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 24px" }}>
        <div style={{ maxWidth: 800, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <a href="/" style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>Cleanway</a>
          <a href="https://chrome.google.com/webstore" style={{ background: "#22c55e", color: "#052e16", padding: "8px 18px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>Add to Chrome</a>
        </div>
      </nav>

      <div style={{ maxWidth: 600, margin: "0 auto", padding: "48px 24px", textAlign: "center" }}>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>
          Privacy Audit: {d}
        </h1>
        <p style={{ color: "#94a3b8", marginBottom: 32 }}>
          Install Cleanway to see the full privacy report for this site.
        </p>

        {/* Teaser Card */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 32, marginBottom: 24, border: "1px solid #334155" }}>
          <div style={{ fontSize: 64, fontWeight: 800, color: "#64748b", marginBottom: 8 }}>?</div>
          <p style={{ fontSize: 18, color: "#f8fafc", fontWeight: 600, marginBottom: 4 }}>Grade: Hidden</p>
          <p style={{ fontSize: 14, color: "#94a3b8" }}>
            Install the extension to see trackers, cookies, data collection forms,
            and fingerprinting for {d}.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 20 }}>
            {[
              { label: "Trackers", value: "?" },
              { label: "Cookies", value: "?" },
              { label: "Data Fields", value: "?" },
              { label: "Fingerprinting", value: "?" },
            ].map((item, i) => (
              <div key={i} style={{ background: "#111827", borderRadius: 10, padding: 12, textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 800, color: "#475569" }}>{item.value}</div>
                <div style={{ fontSize: 11, color: "#64748b" }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>

        <a href="https://chrome.google.com/webstore" style={{
          display: "inline-block", background: "#22c55e", color: "#052e16",
          padding: "14px 32px", borderRadius: 10, fontWeight: 700, fontSize: 16, textDecoration: "none"
        }}>
          Install Cleanway to See Full Report
        </a>

        <p style={{ fontSize: 12, color: "#475569", marginTop: 20 }}>
          Privacy Audit runs 100% on your device. No data sent to our servers.
        </p>
      </div>
    </div>
  );
}
