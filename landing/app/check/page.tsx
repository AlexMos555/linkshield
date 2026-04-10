import { redirect } from "next/navigation";

export default async function CheckSearch({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const { q } = await searchParams;

  if (q) {
    // Normalize: strip protocol, path
    let domain = q.toLowerCase().trim();
    if (domain.startsWith("http")) {
      try {
        domain = new URL(domain).hostname;
      } catch {}
    }
    domain = domain.replace(/\/$/, "");
    redirect(`/check/${encodeURIComponent(domain)}`);
  }

  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center", maxWidth: 500, padding: 24 }}>
        <h1 style={{ fontSize: 32, fontWeight: 800, color: "#f8fafc", marginBottom: 16 }}>
          Is this site safe?
        </h1>
        <p style={{ color: "#94a3b8", marginBottom: 24 }}>
          Enter any domain or URL to check if it{"'"}s a phishing or scam site.
        </p>
        <form action="/check" method="get" style={{ display: "flex", gap: 8 }}>
          <input
            name="q"
            placeholder="e.g. paypal-verify.com"
            autoFocus
            style={{ flex: 1, padding: "14px 18px", borderRadius: 10, border: "1px solid #334155", background: "#1e293b", color: "#e2e8f0", fontSize: 16, outline: "none" }}
          />
          <button type="submit" style={{ background: "#22c55e", color: "#052e16", border: "none", padding: "14px 24px", borderRadius: 10, fontWeight: 700, fontSize: 16, cursor: "pointer" }}>
            Check
          </button>
        </form>
        <p style={{ fontSize: 12, color: "#475569", marginTop: 16 }}>
          Powered by 9 threat intelligence sources and ML detection.
        </p>
      </div>
    </div>
  );
}
