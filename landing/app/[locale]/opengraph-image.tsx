/**
 * Static Open Graph image for the root landing page (cleanway.ai).
 *
 * Per-domain scan pages have their own dynamic OG image at
 * app/[locale]/check/[domain]/opengraph-image.tsx. This file is the
 * fallback rendered for the marketing landing, /pricing, /privacy-policy,
 * /terms, /dns, /transparency, /family, etc. — any route that doesn't
 * override opengraph-image at its segment.
 *
 * Sized 1200x630 (Twitter / Facebook / LinkedIn standard).
 */
import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cleanway — privacy-first anti-phishing";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage() {
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
          padding: "72px 80px",
          position: "relative",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: 14,
              background: "#22c55e",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 40,
            }}
          >
            🧹
          </div>
          <div
            style={{
              fontSize: 52,
              fontWeight: 800,
              color: "#f8fafc",
              letterSpacing: -1,
              display: "flex",
            }}
          >
            Cleanway
          </div>
        </div>

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            justifyContent: "center",
            gap: 24,
            marginTop: 12,
          }}
        >
          <div
            style={{
              fontSize: 84,
              fontWeight: 800,
              color: "#f8fafc",
              letterSpacing: -2,
              lineHeight: 1.02,
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div style={{ display: "flex" }}>Privacy-first</div>
            <div style={{ display: "flex", color: "#22c55e" }}>
              anti-phishing.
            </div>
          </div>
          <div
            style={{
              fontSize: 30,
              color: "#cbd5e1",
              lineHeight: 1.35,
              maxWidth: 880,
              display: "flex",
            }}
          >
            9 threat databases + CatBoost ML scan every link. On-device.
            Open source engine.
          </div>
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            paddingTop: 24,
            borderTop: "1px solid #334155",
            color: "#64748b",
            fontSize: 20,
          }}
        >
          <div style={{ display: "flex" }}>cleanway.ai</div>
          <div
            style={{
              display: "flex",
              background: "#22c55e",
              color: "#052e16",
              padding: "12px 22px",
              borderRadius: 10,
              fontWeight: 700,
              fontSize: 20,
            }}
          >
            Add to Chrome — Free
          </div>
        </div>
      </div>
    ),
    { ...size },
  );
}
