/**
 * The site's share card, served at /og.png (app/og.png/route.ts) and named by
 * every page through DEFAULT_OG_IMAGE (lib/seo.ts) — the locale layout's
 * openGraph carries it, so a page without its own block inherits it too.
 * Per-domain scan and audit pages have their own dynamic image
 * (app/[locale]/check/[domain]/opengraph-image.tsx and the /audit ones).
 *
 * Not a file convention on purpose. As app/[locale]/opengraph-image.tsx it
 * put og:image=/en/opengraph-image?… on every page without its own image
 * (/success, /cancel, /transparency/methodology, the 404…), a URL that
 * answers 307 through the locale middleware — a preview bot does not follow it.
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

export const OG_CARD_SIZE = { width: 1200, height: 630 } as const;

export function renderOgCard(): ImageResponse {
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
    { ...OG_CARD_SIZE },
  );
}
