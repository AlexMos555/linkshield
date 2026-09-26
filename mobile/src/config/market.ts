/**
 * What this build offers where. One small switch, so a market decision is a
 * one-line change instead of screens edited by hand.
 *
 * Paid plans are hidden for Russian: Stripe cannot take Russian cards, the
 * plan prices on the server are placeholders, and the upgrade screen led to
 * an English page in dollars that no one in Russia could pay (report #15).
 * The upgrade code stays; only its entry points are hidden.
 */
const PAID_PLANS_HIDDEN_LANGUAGES: ReadonlySet<string> = new Set(["ru"]);

/** Show "Upgrade" and prices to someone using the app in [language]? */
export function paidPlansVisible(language: string): boolean {
  const base = (language || "").split("-")[0].toLowerCase();
  return !PAID_PLANS_HIDDEN_LANGUAGES.has(base);
}
