/**
 * Open Graph image for /audit/{domain} pages.
 *
 * Unlike /check (which shows the actual scan score), the privacy audit
 * is on-device only — the share card is a branded teaser with the
 * domain name + "?" grade and a CTA to install.
 */
import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cleanway privacy audit";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpenGraphImage({
  params,
}: {
  params: { domain: string };
}) {
  const decoded = decodeURIComponent(params.domain);

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
            marginBottom: 40,
          }}
        >
          <div
            style={{
              fontSize: 38,
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
          <div style={{ fontSize: 18, color: "#94a3b8", fontWeight: 500, display: "flex" }}>
            cleanway.ai/audit
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
                background: "rgba(100,116,139,0.18)",
                border: "8px dashed #64748b",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 120,
                fontWeight: 800,
                color: "#94a3b8",
              }}
            >
              ?
            </div>
            <div
              style={{
                marginTop: 16,
                fontSize: 22,
                fontWeight: 800,
                color: "#94a3b8",
                letterSpacing: 2,
                display: "flex",
              }}
            >
              GRADE HIDDEN
            </div>
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              flex: 1,
              gap: 12,
            }}
          >
            <div style={{ fontSize: 28, color: "#94a3b8", fontWeight: 500, display: "flex" }}>
              Privacy Audit
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
              Trackers · Cookies · Data fields · Fingerprinting.
              On-device, never sent to our servers.
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
          <div style={{ display: "flex" }}>Install to see the full A-F report</div>
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
