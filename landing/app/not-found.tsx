export default function NotFound() {
  return (
    <div style={{ background: "#0f172a", color: "#e2e8f0", fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{ textAlign: "center", padding: 24 }}>
        <div style={{ fontSize: 64, marginBottom: 16 }}>&#x1F6E1;</div>
        <h1 style={{ fontSize: 48, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>404</h1>
        <p style={{ fontSize: 18, color: "#94a3b8", marginBottom: 32 }}>This page doesn{"'"}t exist. But we can still protect you.</p>
        <div style={{ display: "flex", gap: 16, justifyContent: "center" }}>
          <a href="/" style={{ background: "#22c55e", color: "#052e16", padding: "12px 28px", borderRadius: 10, fontWeight: 700, textDecoration: "none" }}>Go Home</a>
          <a href="/check" style={{ background: "#1e293b", color: "#e2e8f0", padding: "12px 28px", borderRadius: 10, fontWeight: 600, textDecoration: "none", border: "1px solid #334155" }}>Check a Domain</a>
        </div>
      </div>
    </div>
  );
}
