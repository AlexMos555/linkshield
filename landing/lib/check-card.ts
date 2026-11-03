/**
 * What the /check verdict card shows, as plain strings.
 *
 * Two places draw the card: the page itself (rendered on the server, cached
 * and regenerated in the background) and, for a verdict resting on Google's
 * lists, the live check in the browser (components/LiveCheckResult.tsx) —
 * Web Risk allows such a warning only while Google's answer is valid, which a
 * cached page cannot promise (lib/google-advisory.ts). Both build the card
 * here, from the API's answer and the page's translations, so the two never
 * drift apart.
 */
import { hasGoogleAdvisory } from "@/lib/google-advisory";
import { reasonLines } from "@/lib/reason-label";

export type Level = "safe" | "caution" | "dangerous";

export const LEVELS: readonly Level[] = ["safe", "caution", "dangerous"];

/** The body of GET /api/v1/public/check/{domain}, the fields the card reads. */
export type ScanResult = {
  level?: Level;
  score?: number;
  verdict?: string;
  signals?: string[];
  // Machine-readable code per signal, positionally aligned with `signals`.
  reason_codes?: string[];
  confidence?: string;
  // Strategy doc #12 — numeric confidence band 50..99.
  confidence_pct?: number;
  // Seconds a verdict resting on Google may still be shown from a cache;
  // null when no reason is Google's (api/routers/public.py).
  advisory_ttl?: number | null;
};

export function isLevel(value: unknown): value is Level {
  return typeof value === "string" && (LEVELS as readonly string[]).includes(value);
}

/**
 * The verdict rests on Google's lists: one of its shown reasons is Google's,
 * or the API gives Google's answer a lifetime (advisory_ttl is a number only
 * then, even when Google's reason is not among the five it shows). Such a
 * verdict is never kept in the cached page.
 */
export function restsOnGoogle(result: ScanResult): boolean {
  return isLevel(result.level) && (hasGoogleAdvisory(result.reason_codes) || typeof result.advisory_ttl === "number");
}

type Translate = (key: string, values?: Record<string, string | number>) => string;

export type AdvisoryStrings = {
  google: string;
  learn_more: string;
  learn_phishing: string;
  learn_malware: string;
  learn_unwanted: string;
};

export type CardProps = {
  level: Level | null;
  heading: string;
  levelLabel: string | null;
  riskScore: string | null;
  confidence: string | null;
  confidenceHint: string;
  howWeMeasure: string;
  methodologyHref: string;
  verdict: string;
  signalsHeading: string;
  signals: string[];
  advisory: AdvisoryStrings | null;
  lowConfidence: string | null;
  share: { text: string; title: string; url: string } | null;
  /** The live check has not answered yet. */
  busy: boolean;
};

export type CardInput = {
  /** null: no answer yet (the live check is on its way) */
  result: ScanResult | null;
  shownDomain: string;
  canonical: string;
  methodologyHref: string;
  /** the Check namespace */
  t: Translate;
  /** the Reasons namespace */
  reason: (key: string) => string;
  advisory: AdvisoryStrings;
};

export function checkCardProps({ result, shownDomain, canonical, methodologyHref, t, reason, advisory }: CardInput): CardProps {
  const level: Level | null = result && isLevel(result.level) ? result.level : null;
  const score = result && typeof result.score === "number" ? result.score : null;
  const domain = { domain: shownDomain };
  const verdict = level
    ? t(`verdict_${level}`, domain)
    : result === null ? t("checking", domain) : t("check_failed", domain);
  return {
    level,
    heading: t("heading", domain),
    levelLabel: level ? t(`level_${level}`) : null,
    riskScore: level && score !== null ? t("risk_score", { score }) : null,
    confidence: level && typeof result?.confidence_pct === "number" ? t("confidence", { pct: result.confidence_pct }) : null,
    confidenceHint: t("confidence_hint"),
    howWeMeasure: t("how_we_measure"),
    methodologyHref,
    verdict,
    signalsHeading: t("signals_heading"),
    signals: level && result ? reasonLines(result.signals ?? [], result.reason_codes, reason) : [],
    // Google's credit, linked, and the learn-more pages — only on a verdict
    // one of whose reasons is Google's (Web Risk's rules for warnings).
    advisory: level && result && hasGoogleAdvisory(result.reason_codes) ? advisory : null,
    lowConfidence: level && result?.confidence === "low" ? t("low_confidence") : null,
    share: level
      ? {
          text: t("share_text", { verdict: t(`level_${level}`), domain: shownDomain, score: String(score ?? "?") }),
          title: t("share_title", domain),
          url: canonical,
        }
      : null,
    busy: result === null,
  };
}
