"use client";

import { useTranslations } from "next-intl";
import { useCallback, useState } from "react";

/**
 * Share button for /check/{domain} and /audit/{domain}/grade/{letter} pages.
 *
 * Behavior:
 *  - Mobile / supports Web Share API → one-tap native share sheet (X,
 *    Telegram, WhatsApp, Email, etc. all in one)
 *  - Desktop → expand into a row of platform-specific share links plus
 *    a Copy Link button
 *
 * The page writes the message: a scorecard shares its verdict and risk score,
 * a privacy-audit grade shares the grade — never the other way round (a
 * privacy "F" is not "Dangerous", and a letter is not a score out of 100).
 *
 * No tracking, no analytics — keeps the page clean and privacy-first.
 */
interface ShareScanButtonProps {
  /** Localized share message, e.g. "Опасно: example.ru — оценка риска 78 из 100". */
  text: string;
  /** Localized share title (native share sheet, email subject). */
  title: string;
  url: string;
}

export default function ShareScanButton({ text, title, url }: ShareScanButtonProps) {
  const t = useTranslations("Check");
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const handleNativeShare = useCallback(async () => {
    // Avoid relying on `navigator.canShare` which is not always present
    if (typeof navigator !== "undefined" && typeof navigator.share === "function") {
      try {
        await navigator.share({ title, text, url });
        return;
      } catch {
        // User dismissed — fall through to expanded view
      }
    }
    setExpanded((v) => !v);
  }, [title, text, url]);

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
    { name: t("share_email"), href: `mailto:?subject=${encodedText}&body=${encodedUrl}` },
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
        {t("share_button")}
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
            {copied ? t("share_copied") : t("share_copy")}
          </button>
        </div>
      )}
    </div>
  );
}
