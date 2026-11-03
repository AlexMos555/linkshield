import ShareScanButton from "@/components/ShareScanButton";
import type { CardProps, Level } from "@/lib/check-card";
import { GOOGLE_ADVISORY_LINKS } from "@/lib/google-advisory";

/**
 * The /check verdict card. Drawn by the page on the server and, for a verdict
 * resting on Google's lists, by the live check in the browser
 * (components/LiveCheckResult.tsx); its strings come from lib/check-card.ts.
 * No hooks and no "use client": it renders wherever it is imported.
 */

const LEVEL_COLORS: Record<Level, string> = {
  safe: "#22c55e",
  caution: "#f59e0b",
  dangerous: "#ef4444",
};

// Text on the dark card needs AA contrast; the red above is 3.9:1 there.
const LEVEL_TEXT_COLORS: Record<Level, string> = {
  safe: "#22c55e",
  caution: "#f59e0b",
  dangerous: "#f87171",
};

const LEVEL_ICONS: Record<Level, string> = {
  safe: "✅",
  caution: "⚠️",
  dangerous: "❌",
};

const LINK = { color: "#60a5fa", textDecoration: "underline" } as const;

function GoogleLink({ href, children }: { href: string; children: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" style={LINK}>
      {children}
    </a>
  );
}

export default function CheckResultCard(card: CardProps) {
  const { level } = card;
  const color = level ? LEVEL_COLORS[level] : "#8796ab";
  return (
    <div
      data-testid="check-result"
      aria-busy={card.busy || undefined}
      style={{
        background: "#1e293b",
        borderRadius: 16,
        padding: "32px",
        border: `1px solid ${color}40`,
        marginBottom: 24,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
        <div
          aria-hidden="true"
          style={{
            width: 64,
            height: 64,
            borderRadius: "50%",
            background: `${color}20`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 32,
            flexShrink: 0,
          }}
        >
          {level ? LEVEL_ICONS[level] : "…"}
        </div>
        <div style={{ minWidth: 0 }}>
          <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: 0, overflowWrap: "anywhere" }}>
            {card.heading}
          </h1>
          {level && card.levelLabel && (
            <p style={{ fontSize: 18, color: LEVEL_TEXT_COLORS[level], fontWeight: 600, margin: "4px 0 0" }}>
              {card.levelLabel}
              {card.riskScore && <> &mdash; {card.riskScore}</>}
            </p>
          )}
          {/* Strategy doc #12: numeric confidence band chip. The
              number is sourced from the API's calculate_confidence_pct
              output, which blends data coverage × signal margin. */}
          {card.confidence && (
            <p style={{ fontSize: 13, color: "#94a3b8", margin: "4px 0 0", fontWeight: 500 }} title={card.confidenceHint}>
              {card.confidence} &middot;{" "}
              <a href={card.methodologyHref} style={LINK}>
                {card.howWeMeasure}
              </a>
            </p>
          )}
        </div>
      </div>

      <p role={card.busy ? "status" : undefined} style={{ fontSize: 16, color: "#94a3b8", lineHeight: 1.6, marginBottom: 20 }}>
        {card.verdict}
      </p>

      {card.signals.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <h2 style={{ fontSize: 14, color: "#8796ab", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>
            {card.signalsHeading}
          </h2>
          {card.signals.map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", fontSize: 14, color: "#94a3b8" }}>
              <span aria-hidden="true" style={{ color }}>&#x2022;</span>
              <span>{s}</span>
            </div>
          ))}
        </div>
      )}

      {/* One of the reasons is Google's (Web Risk): its rules for warnings ask
          for its credit, linked, and a way to learn more about each threat
          type — and for none of it on a verdict built on other sources. */}
      {card.advisory && (
        <p data-testid="google-advisory" style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.6, margin: "0 0 20px" }}>
          <GoogleLink href={GOOGLE_ADVISORY_LINKS.advisory}>{card.advisory.google}</GoogleLink>
          <br />
          {card.advisory.learn_more}{" "}
          <GoogleLink href={GOOGLE_ADVISORY_LINKS.phishing}>{card.advisory.learn_phishing}</GoogleLink>{" "}&middot;{" "}
          <GoogleLink href={GOOGLE_ADVISORY_LINKS.malware}>{card.advisory.learn_malware}</GoogleLink>{" "}&middot;{" "}
          <GoogleLink href={GOOGLE_ADVISORY_LINKS.unwanted}>{card.advisory.learn_unwanted}</GoogleLink>
        </p>
      )}

      {card.lowConfidence && (
        <p style={{ fontSize: 13, color: "#f59e0b", fontStyle: "italic", marginBottom: 20 }}>{card.lowConfidence}</p>
      )}

      {card.share && <ShareScanButton text={card.share.text} title={card.share.title} url={card.share.url} />}
    </div>
  );
}
