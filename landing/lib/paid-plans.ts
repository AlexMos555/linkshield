/**
 * Where paid plans are offered at all.
 *
 * For Russia the answer is "nowhere yet": checkout runs on Stripe, which does
 * not take Russian cards, and the launch promise to Tele2 subscribers is that
 * protection is free. Showing dollar plan cards there sells something the
 * visitor cannot buy. So a Russian-language page, or a visitor whose country
 * we know is RU, gets the free-only variant: what is included, no prices.
 */
const FREE_ONLY_LOCALES: ReadonlySet<string> = new Set(["ru"]);
const FREE_ONLY_COUNTRIES: ReadonlySet<string> = new Set(["RU"]);

export interface Visitor {
  /** Page locale, e.g. "ru". */
  readonly locale: string;
  /** ISO 3166-1 alpha-2 country, when known (edge geo header or ?cc=). */
  readonly country?: string | null;
}

export function paidPlansOffered({ locale, country }: Visitor): boolean {
  if (FREE_ONLY_LOCALES.has(locale)) return false;
  const cc = (country ?? "").trim().toUpperCase();
  return !FREE_ONLY_COUNTRIES.has(cc);
}
