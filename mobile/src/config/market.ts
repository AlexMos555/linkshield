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

/**
 * Show the family steps that exist only under Russian law — the Госуслуги
 * bans, «вторая рука», caller-ID apps named by their Russian names? The app
 * language decides, or a phone whose region is Russia in another language;
 * a Spanish-speaking grandmother in Madrid is not sent to Госуслуги.
 */
export function russianStepsVisible(language: string, region: string | null | undefined): boolean {
  const base = (language || "").split("-")[0].toLowerCase();
  return base === "ru" || (region ?? "").toUpperCase() === "RU";
}
