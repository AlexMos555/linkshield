/**
 * Dynamic Open Graph image for /check/{domain} pages.
 *
 * Each domain scan gets its own share preview with the actual security
 * grade, score, and verdict. This is the viral driver — when someone
 * shares the URL, social platforms pull this image automatically.
 *
 * Sized 1200x630 (Twitter / Facebook / LinkedIn standard).
 */
import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cleanway safety check";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

type ScanResult = {
  level?: "safe" | "caution" | "dangerous";
  score?: number;
};

const COLORS = {
  safe: { fg: "#22c55e", glow: "rgba(34,197,94,0.25)", label: "SAFE" },
  caution: { fg: "#f59e0b", glow: "rgba(245,158,11,0.25)", label: "CAUTION" },
  dangerous: { fg: "#ef4444", glow: "rgba(239,68,68,0.25)", label: "DANGEROUS" },
} as const;

async function fetchScanResult(domain: string): Promise<ScanResult> {
  try {
    const apiBase =
      process.env.NEXT_PUBLIC_API_URL ||
      process.env.API_URL ||
      "https://api.cleanway.ai";
    const resp = await fetch(`${apiBase}/api/v1/public/check/${domain}`, {
      next: { revalidate: 3600 },
    });
    if (!resp.ok) return {};
    const json = (await resp.json()) as ScanResult;
    return json;
  } catch {
    return {};
  }
}

export default async function OpenGraphImage({
  params,
}: {
  params: { domain: string };
}) {
  const decoded = decodeURIComponent(params.domain);
  const result = await fetchScanResult(decoded);
  const level = (result.level ?? "caution") as keyof typeof COLORS;
  const score = result.score ?? "?";
  const palette = COLORS[level] ?? COLORS.caution;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background:
            "linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
          color: "#f8fafc",
          fontFamily: "sans-serif",
          padding: "60px 70px",
          position: "relative",
        }}
      >
        {/* Top bar — brand */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 40,
          }}
        >
          <div
            style={{
              fontSize: 38,
              fontWeight: 800,
              color: "#f8fafc",
              letterSpacing: -0.5,
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <span
              style={{
                width: 44,
                height: 44,
                borderRadius: 10,
                background: "#22c55e",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 28,
              }}
            >
              🧹
            </span>
            Cleanway
          </div>
          <div
            style={{
              fontSize: 18,
              color: "#94a3b8",
              fontWeight: 500,
              display: "flex",
            }}
          >
            cleanway.ai/check
          </div>
        </div>

        {/* Main content */}
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            gap: 56,
          }}
        >
          {/* Score circle */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
            }}
          >
            <div
              style={{
                width: 240,
                height: 240,
                borderRadius: 999,
                background: palette.glow,
                border: `8px solid ${palette.fg}`,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 88,
                fontWeight: 800,
                color: palette.fg,
                lineHeight: 1,
              }}
            >
              <div style={{ display: "flex" }}>{score}</div>
              <div
                style={{
                  fontSize: 20,
                  marginTop: 6,
                  color: "#94a3b8",
                  fontWeight: 600,
                  letterSpacing: 1,
                  display: "flex",
                }}
              >
                / 100
              </div>
            </div>
            <div
              style={{
                marginTop: 16,
                fontSize: 22,
                fontWeight: 800,
                color: palette.fg,
                letterSpacing: 2,
                display: "flex",
              }}
            >
              {palette.label}
            </div>
          </div>

          {/* Domain + verdict */}
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              flex: 1,
              gap: 12,
            }}
          >
            <div
              style={{
                fontSize: 28,
                color: "#94a3b8",
                fontWeight: 500,
                display: "flex",
              }}
            >
              Is this site safe?
            </div>
            <div
              style={{
                fontSize: 64,
                fontWeight: 800,
                color: "#f8fafc",
                lineHeight: 1.05,
                wordBreak: "break-all",
                display: "flex",
              }}
            >
              {decoded}
            </div>
            <div
              style={{
                marginTop: 20,
                fontSize: 22,
                color: "#cbd5e1",
                lineHeight: 1.4,
                display: "flex",
              }}
            >
              Cleanway scans every link with 9 threat sources + ML.
              Privacy-first, on-device.
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            paddingTop: 24,
            borderTop: "1px solid #334155",
            color: "#64748b",
            fontSize: 18,
          }}
        >
          <div style={{ display: "flex" }}>
            9 threat databases · CatBoost ML · 0.9988 AUC
          </div>
          <div
            style={{
              display: "flex",
              background: "#22c55e",
              color: "#052e16",
              padding: "10px 20px",
              borderRadius: 8,
              fontWeight: 700,
              fontSize: 18,
            }}
          >
            Add to Chrome — Free
          </div>
        </div>
      </div>
    ),
    { ...size }
  );
}
