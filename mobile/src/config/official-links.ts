/**
 * Official pages that the "Проверка защиты" cards open — the ONE place their
 * addresses live.
 *
 * A wrong "official" link is itself phishing (roadmap №4, "главный риск"),
 * so a card shows its button only after a HUMAN has verified the link:
 *
 *   1. open `url` on a real phone in Russia, signed in to a real Госуслуги
 *      account (not from abroad: gosuslugi.ru does not answer foreign IPs,
 *      and a page seen logged-out is not the page grandma will see);
 *   2. confirm it is the page `expect` describes, on www.gosuslugi.ru, and
 *      that it never asks for a code from an SMS;
 *   3. on the same account, follow the card's written steps
 *      (mobile.checkup.<id>.how) — they ship even without a button, so
 *      they are checked even if a link is dropped;
 *   4. write the date here: verified_on: "YYYY-MM-DD".
 *
 * Re-check every quarter, and clear the date the day a page moves. Until the
 * date is filled, the card keeps its written steps but shows no button —
 * except in a review build (REVIEW_SHOWS_UNVERIFIED_LINKS), so the people
 * verifying can tap through it.
 *
 * Candidates were collected on 2026-09-27 from Госуслуги's own pages and
 * search results; none could be opened from outside Russia. Primary facts
 * behind each card: see `source`.
 */

export interface OfficialLink {
  /** The exact page the button opens. https, www.gosuslugi.ru only. */
  url: string;
  /** What the verifier must see on that page. */
  expect: string;
  /** Where the address was found. */
  source: string;
  /**
   * "YYYY-MM-DD" — the day a person opened `url` on a real account in
   * Russia and saw `expect`. Empty = unverified: the button stays hidden.
   */
  verified_on: string;
}

export type OfficialLinkId = "credit_ban" | "sim_ban";

/**
 * REVIEW SWITCH — on only in an APK built with EXPO_PUBLIC_REVIEW_LINKS=1
 * (inlined at build time), so the founder and the tester in Russia can tap
 * every unverified link from the app. Any other build — every release — shows
 * a link only once `verified_on` is filled. Never hard-code it: a committed
 * `true` would ship unverified official links to everyone, and
 * test-checkup.mjs fails CI if the switch is on without the variable.
 * metro.config.js keys Metro's cache on the value, so a release built after
 * a review build cannot reuse the review bundle's inlined `true`.
 */
export const REVIEW_SHOWS_UNVERIFIED_LINKS: boolean = process.env.EXPO_PUBLIC_REVIEW_LINKS === "1";

export const OFFICIAL_LINKS: Readonly<Record<OfficialLinkId, OfficialLink>> = {
  credit_ban: {
    url: "https://www.gosuslugi.ru/newsearch/samozapret-na-kredity",
    expect:
      "Госуслуги, «Самозапрет на кредиты»: кнопка, ведущая к заявлению об установлении самозапрета " +
      "(можно выбрать все кредиты и займы). Коды спрашивает только обычный вход в Госуслуги.",
    source:
      "gosuslugi.ru/newsearch/samozapret-na-kredity (заголовок «Самозапрет на кредиты»); " +
      "справка gosuslugi.ru/help/faq/credit_lock/262252 — запасной вариант; " +
      "условия — cbr.ru/ckki/self-prohibition_credit/.",
    verified_on: "",
  },
  sim_ban: {
    url: "https://www.gosuslugi.ru/newsearch/samozapret-na-dogovor-svyazi",
    expect:
      "Госуслуги, «Установить самозапрет на оформление сим-карт»: путь «Профиль → SIM-карты → " +
      "Запрет на оформление договоров связи → Установить».",
    source:
      "gosuslugi.ru/newsearch/samozapret-na-dogovor-svyazi (заголовок «Установить самозапрет на " +
      "оформление сим-карт»); справка gosuslugi.ru/help/faq/sim-cards/104028 — запасной вариант.",
    verified_on: "",
  },
};

const VERIFIED_DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Has a person verified this link (a real date in `verified_on`)? */
export function isVerified(link: OfficialLink): boolean {
  return VERIFIED_DATE.test(link.verified_on) && !Number.isNaN(Date.parse(link.verified_on));
}

/** May the card show a button for this link? Verified, or a review build. */
export function linkButtonVisible(link: OfficialLink, reviewBuild: boolean = REVIEW_SHOWS_UNVERIFIED_LINKS): boolean {
  return isVerified(link) || reviewBuild;
}

/** The host the button names under itself, so the person sees where it goes. */
export function linkHost(link: OfficialLink): string {
  return link.url.replace(/^https:\/\//, "").split("/")[0].replace(/^www\./, "");
}
