import type { AnsweredShare, DetectionFigures } from "./benchmark";

/**
 * The ICU arguments of every sentence that quotes our detection figure: the
 * home badge (Hero.badge, Hero.badge_warned) and the transparency report
 * (Transparency.recall_measured). One place, so the two pages cannot round
 * or date the same report differently.
 *
 * Whole percents: at ~120 answered links a share is only good to about ±7
 * points (the interval says so), and a decimal would claim more. The share is
 * rounded from its counts (145 of 200 is 73%, where the float 0.725 * 100
 * would give 72); the interval's ends are the report's own (4 decimals),
 * rounded the same way.
 */
export type DetectionMessageArgs = {
  /** The run's day, in the visitor's language. */
  date: string;
  /** Called dangerous, % of the answered links; low–high is its 95% interval. */
  dangerous: string;
  low: string;
  high: string;
  /** Dangerous or caution, % of the answered links, and its 95% interval. */
  warned: string;
  warned_low: string;
  warned_high: string;
  /** Live links that got an answer: what both shares are of. */
  answered: number;
  /** Links in the sample. */
  n: number;
  /** The window: links submitted to PhishTank in this many days before the run. */
  days: number;
  /** Left out: names that no longer existed, live links without an answer. */
  not_found: number;
  no_answer: number;
};

function shareArgs(share: AnsweredShare, of: number, format: (x: number) => string): [string, string, string] {
  return [
    format(Math.round((share.count * 100) / of)),
    format(Math.round(share.low * 100)),
    format(Math.round(share.high * 100)),
  ];
}

/** The run's day as the pages print it (UTC: the report's timestamp is UTC). */
export function benchmarkDay(iso: string, locale: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : new Intl.DateTimeFormat(locale, { dateStyle: "long", timeZone: "UTC" }).format(date);
}

export function detectionMessageArgs(figures: DetectionFigures, locale: string): DetectionMessageArgs {
  const whole = new Intl.NumberFormat(locale, { maximumFractionDigits: 0 });
  const format = (x: number) => whole.format(x);
  const [dangerous, low, high] = shareArgs(figures.dangerous, figures.answered, format);
  const [warned, warnedLow, warnedHigh] = shareArgs(figures.warned, figures.answered, format);
  return {
    date: benchmarkDay(figures.ts, locale),
    dangerous,
    low,
    high,
    warned,
    warned_low: warnedLow,
    warned_high: warnedHigh,
    answered: figures.answered,
    n: figures.n,
    days: figures.days,
    not_found: figures.notFound,
    no_answer: figures.noAnswer,
  };
}
