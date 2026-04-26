"use client";

import { useCallback, useState } from "react";

/**
 * Share button for /check/{domain} pages.
 *
 * Behavior:
 *  - Mobile / supports Web Share API → one-tap native share sheet (X,
 *    Telegram, WhatsApp, Email, etc. all in one)
 *  - Desktop → expand into a row of platform-specific share links plus
 *    a Copy Link button
 *
 * No tracking, no analytics — keeps the page clean and privacy-first.
 */
interface ShareScanButtonProps {
  domain: string;
  level: "safe" | "caution" | "dangerous";
  score: number | string;
  url: string;
}

const LEVEL_PHRASES: Record<ShareScanButtonProps["level"], string> = {
  safe: "Looks safe",
  caution: "Use caution",
  dangerous: "Flagged as dangerous",
};

function buildShareText(domain: string, level: ShareScanButtonProps["level"], score: number | string): string {
  const phrase = LEVEL_PHRASES[level] ?? "Checked";
  return `${phrase}: ${domain} — Cleanway score ${score}/100`;
}

export default function ShareScanButton({ domain, level, score, url }: ShareScanButtonProps) {
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const text = buildShareText(domain, level, score);

  const handleNativeShare = useCallback(async () => {
    // Avoid relying on `navigator.canShare` which is not always present
    if (typeof navigator !== "undefined" && typeof navigator.share === "function") {
      try {
        await navigator.share({ title: `Is ${domain} safe?`, text, url });
        return;
      } catch {
        // User dismissed — fall through to expanded view
      }
    }
    setExpanded((v) => !v);
  }, [domain, text, url]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard blocked — silently no-op
    }
  }, [url]);

  const encodedUrl = encodeURIComponent(url);
  const encodedText = encodeURIComponent(text);

  const links = [
    { name: "X", href: `https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}` },
    { name: "LinkedIn", href: `https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}` },
    { name: "Reddit", href: `https://reddit.com/submit?url=${encodedUrl}&title=${encodedText}` },
    { name: "Telegram", href: `https://t.me/share/url?url=${encodedUrl}&text=${encodedText}` },
    { name: "WhatsApp", href: `https://wa.me/?text=${encodedText}%20${encodedUrl}` },
    { name: "Email", href: `mailto:?subject=${encodedText}&body=${encodedUrl}` },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <button
        type="button"
        onClick={handleNativeShare}
        style={{
          background: "#3b82f6",
          color: "white",
          border: "none",
          padding: "10px 20px",
          borderRadius: 8,
          fontWeight: 600,
          fontSize: 14,
          cursor: "pointer",
          alignSelf: "flex-start",
        }}
      >
        Share this scan
      </button>

      {expanded && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 8,
            background: "#0f172a",
            padding: 12,
            borderRadius: 8,
            border: "1px solid #1e293b",
          }}
        >
          {links.map((l) => (
            <a
              key={l.name}
              href={l.href}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                background: "#1e293b",
                color: "#e2e8f0",
                padding: "6px 14px",
                borderRadius: 6,
                fontSize: 13,
                textDecoration: "none",
              }}
            >
              {l.name}
            </a>
          ))}
          <button
            type="button"
            onClick={handleCopy}
            style={{
              background: copied ? "#22c55e" : "#1e293b",
              color: copied ? "#052e16" : "#e2e8f0",
              border: "none",
              padding: "6px 14px",
              borderRadius: 6,
              fontSize: 13,
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            {copied ? "Copied!" : "Copy link"}
          </button>
        </div>
      )}
    </div>
  );
}
