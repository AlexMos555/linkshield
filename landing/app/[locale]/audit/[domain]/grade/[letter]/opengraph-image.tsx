/**
 * Dynamic Open Graph image for the share-a-grade card.
 *
 * Each (domain, letter) combo renders a 1200×630 PNG with the grade
 * letter front-and-center, color-coded A→F. This is the viral asset
 * — when a user shares /audit/{domain}/grade/A on X, this image is
 * what their followers see in the timeline.
 */
import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cleanway privacy grade";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

const VALID = ["A", "B", "C", "D", "F"];

const PALETTE: Record<string, { color: string; glow: string; label: string }> = {
  A: { color: "#22c55e", glow: "rgba(34,197,94,0.25)", label: "EXCELLENT PRIVACY" },
  B: { color: "#84cc16", glow: "rgba(132,204,22,0.25)", label: "GOOD PRIVACY" },
  C: { color: "#eab308", glow: "rgba(234,179,8,0.25)", label: "AVERAGE" },
  D: { color: "#f97316", glow: "rgba(249,115,22,0.25)", label: "HEAVY TRACKING" },
  F: { color: "#ef4444", glow: "rgba(239,68,68,0.25)", label: "POOR PRIVACY" },
};

export default function OpenGraphImage({
  params,
}: {
  params: { domain: string; letter: string };
}) {
  const decoded = decodeURIComponent(params.domain);
  const upper = (params.letter || "").toUpperCase();
  const grade = VALID.includes(upper) ? upper : "C";
  const p = PALETTE[grade];

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
        }}
      >
        {/* Brand */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: 36,
          }}
        >
          <div
            style={{
              fontSize: 36,
              fontWeight: 800,
              color: "#f8fafc",
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
          <div style={{ fontSize: 16, color: "#94a3b8", fontWeight: 500, display: "flex" }}>
            Privacy Audit
          </div>
        </div>

        {/* Centerpiece — giant grade circle */}
        <div
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            gap: 48,
          }}
        >
          <div
            style={{
              width: 320,
              height: 320,
              borderRadius: 999,
              background: p.glow,
              border: `12px solid ${p.color}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 220,
              fontWeight: 900,
              color: p.color,
              lineHeight: 1,
              flexShrink: 0,
            }}
          >
            {grade}
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              flex: 1,
              gap: 16,
            }}
          >
            <div
              style={{
                fontSize: 24,
                fontWeight: 800,
                color: p.color,
                letterSpacing: 2,
                display: "flex",
              }}
            >
              {p.label}
            </div>
            <div
              style={{
                fontSize: 56,
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
                marginTop: 8,
                fontSize: 20,
                color: "#cbd5e1",
                lineHeight: 1.4,
                display: "flex",
              }}
            >
              Trackers · cookies · data collection · fingerprinting.
              Computed on-device.
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            paddingTop: 20,
            borderTop: "1px solid #334155",
            color: "#64748b",
            fontSize: 17,
          }}
        >
          <div style={{ display: "flex" }}>
            cleanway.ai/audit · grade your own sites
          </div>
          <div
            style={{
              display: "flex",
              background: "#22c55e",
              color: "#052e16",
              padding: "10px 20px",
              borderRadius: 8,
              fontWeight: 700,
              fontSize: 17,
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
