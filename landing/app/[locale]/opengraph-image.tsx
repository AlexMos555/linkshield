/**
 * Static Open Graph image for the landing and every page that doesn't
 * override opengraph-image at its segment (/android, /pricing, /support,
 * /privacy-policy, /terms, /dns, /transparency, ...). Per-domain scan pages
 * have their own dynamic image at app/[locale]/check/[domain]/opengraph-image.tsx.
 *
 * Deliberately wordless beyond the brand: this one picture is shown for all
 * ten locales, so any sentence on it is wrong for nine of them — the Russian
 * Android page used to preview in Telegram with an English "Add to Chrome —
 * Free" button for a listing that does not exist. The localized title and
 * description in each page's metadata carry the message instead.
 *
 * Sized 1200x630 (Twitter / Facebook / LinkedIn / Telegram standard).
 */
import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "Cleanway";
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
          alignItems: "center",
          justifyContent: "center",
          gap: 40,
          background:
            "linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%)",
          color: "#f8fafc",
          fontFamily: "sans-serif",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 32,
          }}
        >
          <div
            style={{
              width: 140,
              height: 140,
              borderRadius: 32,
              background: "#22c55e",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 88,
            }}
          >
            🧹
          </div>
          <div
            style={{
              fontSize: 128,
              fontWeight: 800,
              color: "#f8fafc",
              letterSpacing: -3,
              display: "flex",
            }}
          >
            Cleanway
          </div>
        </div>
        <div
          style={{
            display: "flex",
            fontSize: 40,
            color: "#22c55e",
            letterSpacing: 1,
          }}
        >
          cleanway.ai
        </div>
      </div>
    ),
    { ...size },
  );
}
