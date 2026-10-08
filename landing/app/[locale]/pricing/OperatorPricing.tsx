import type { ReactNode } from "react";
import { useTranslations } from "next-intl";

import { billingMessageArgs, formatPhone, sellerIsComplete, type BillingTerms, type Seller } from "@/lib/billing";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";
import PricingNav from "./PricingNav";

/**
 * /pricing for Russian visitors once NEXT_PUBLIC_BILLING_ENABLED is on: the
 * subscription billed to the phone account (docs/BILLING.md), at the prices
 * this deployment is configured with. Until the flag is on they get
 * FreePricing, unchanged.
 *
 * Since 2026-10-07 the subscription counts devices (docs/ACCOUNTS_BILLING_PLAN.md
 * §5): basic protection with nothing to pay, and one plan — 99 ₽ a month for
 * 3 devices of one account, +29 ₽ for each one more (defaults; lib/billing.ts).
 *
 * Every number on the page is an ICU argument (lib/billing.ts); the strings
 * never carry a price, so a settings change is one env edit. The strings
 * themselves are held to a paid product's truth by
 * scripts/check-landing-claims.py (no "free", no Stripe, no dollars).
 */
interface OperatorPricingProps {
  locale: string;
  terms: BillingTerms;
  seller: Seller;
  supportPhone: string | null;
}

const FAQ_KEYS = ["auto", "device", "cancel", "nomoney", "network", "number", "refund"] as const;
const HOW_STEPS = [1, 2, 3, 4] as const;

export default function OperatorPricing({ locale, terms, seller, supportPhone }: OperatorPricingProps) {
  const t = useTranslations("Billing");
  const support = useTranslations("Support");
  const args = billingMessageArgs(terms);
  const lapse = t(`lapse_${terms.lapsePolicy}`);
  const included = t.raw("included_items") as string[];
  const planItems = t.raw("plan_items") as string[];
  const faq = FAQ_KEYS.map((key) => ({ q: t(`faq_${key}_q`), a: t(`faq_${key}_a`, { ...args, lapse }) }));
  const href = (path: string) => localePath(locale, path);

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200">
      <PricingNav locale={locale} />

      <main className="max-w-5xl mx-auto px-6 pt-20 pb-24" data-testid="operator-pricing">
        {/* Hero */}
        <section className="text-center max-w-3xl mx-auto">
          <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-6">
            {t("badge")}
          </span>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">{t("title")}</h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed mb-6">{t("subtitle", args)}</p>
          <p data-testid="operator-trial" className="inline-block bg-slate-800/60 border border-slate-700 px-4 py-2 rounded-full text-sm text-slate-200">
            {t("trial_note", args)}
          </p>
        </section>

        {/* Plans */}
        <section className="mt-16" aria-labelledby="plans-title">
          <h2 id="plans-title" className="text-2xl font-extrabold text-white text-center mb-8">{t("plans_title")}</h2>
          <div className="grid md:grid-cols-2 gap-5 max-w-4xl mx-auto">
            <article data-testid="plan-card-basic" className="rounded-2xl p-6 border flex flex-col bg-slate-800/50 border-slate-700">
              <h3 className="text-xl font-extrabold text-white">{t("basic_name")}</h3>
              <p className="text-sm text-slate-400 mb-4">{t("basic_for")}</p>
              <p className="text-3xl font-extrabold text-white">{t("basic_price")}</p>
              <ul className="mt-5 space-y-2 flex-grow">
                {(["basic_item_block", "basic_item_checks", "basic_item_first_days"] as const).map((key) => (
                  <CheckItem key={key}>{t(key, args)}</CheckItem>
                ))}
              </ul>
            </article>
            <article data-testid="plan-card-devices" className="rounded-2xl p-6 border flex flex-col bg-green-500/10 border-green-500/40">
              <h3 className="text-xl font-extrabold text-white">{t("plan_name")}</h3>
              <p className="text-sm text-slate-400 mb-4">{t("plan_for")}</p>
              <p className="text-3xl font-extrabold text-white">{t("per_month", args)}</p>
              <p className="text-sm text-slate-300 mt-1">{t("plan_devices", args)}</p>
              <p data-testid="operator-extra-device" className="text-sm text-slate-400 mt-1">{t("extra_device", args)}</p>
              <ul className="mt-5 space-y-2 flex-grow">
                {planItems.map((item) => (
                  <CheckItem key={item}>{item}</CheckItem>
                ))}
              </ul>
              <a
                href={href("/android")}
                className="mt-6 inline-block text-center px-5 py-3 rounded-xl font-bold transition bg-green-500 text-green-950 hover:bg-green-400"
              >
                {t("plan_cta")}
              </a>
            </article>
          </div>
          <p className="text-center text-sm text-slate-500 mt-6">{t("plan_cta_hint")}</p>
        </section>

        {/* Included */}
        <section className="mt-16 bg-slate-800/50 rounded-2xl p-8" aria-labelledby="included-title">
          <h2 id="included-title" className="text-2xl font-extrabold text-white mb-6">{t("included_title")}</h2>
          <ul className="space-y-4">
            {included.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <svg aria-hidden="true" focusable="false" className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span className="text-slate-300">{item}</span>
              </li>
            ))}
          </ul>
        </section>

        {/* How it works */}
        <section className="mt-16" aria-labelledby="how-title">
          <h2 id="how-title" className="text-2xl font-extrabold text-white text-center mb-8">{t("how_title")}</h2>
          <ol className="grid md:grid-cols-2 gap-5 list-none p-0 m-0">
            {HOW_STEPS.map((step) => (
              <li key={step} className="bg-slate-800/50 rounded-xl p-6 flex gap-4">
                <span aria-hidden="true" className="w-9 h-9 rounded-full bg-green-500/15 text-green-400 font-extrabold flex items-center justify-center flex-shrink-0">{step}</span>
                <div>
                  <h3 className="font-bold text-white mb-1">{t(`how_${step}_title`)}</h3>
                  <p className="text-slate-400 text-sm leading-relaxed">{t(`how_${step}_body`, args)}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>

        {/* FAQ */}
        <section className="mt-16 max-w-3xl mx-auto" aria-labelledby="faq-title" data-testid="operator-faq">
          <h2 id="faq-title" className="text-2xl font-extrabold text-white text-center mb-8">{t("faq_title")}</h2>
          <div className="space-y-4">
            {faq.map((item) => (
              <details key={item.q} className="bg-slate-800/50 rounded-xl p-5 group">
                <summary className="cursor-pointer font-semibold text-white list-none flex justify-between items-center">
                  <span>{item.q}</span>
                  <span aria-hidden="true" className="text-slate-400 group-open:rotate-180 transition">▾</span>
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed">{item.a}</p>
              </details>
            ))}
          </div>
        </section>

        {/* Seller + support */}
        <section className="mt-16 grid md:grid-cols-2 gap-5">
          <div className="bg-slate-800/50 rounded-2xl p-6" data-testid="requisites">
            <h2 className="text-lg font-bold text-white mb-3">{t("requisites_title")}</h2>
            {sellerIsComplete(seller) ? (
              <div className="text-slate-300 text-sm space-y-1" data-testid="requisites-complete">
                <p className="m-0">{t("requisites_name", { name: seller.name ?? "" })}</p>
                <p className="m-0">{t("requisites_inn", { inn: seller.inn ?? "" })}</p>
                <p className="m-0">{t("requisites_ogrnip", { ogrnip: seller.ogrnip ?? "" })}</p>
              </div>
            ) : (
              <p className="text-amber-300 text-sm m-0" data-testid="requisites-pending">{t("requisites_pending")}</p>
            )}
            <p className="text-slate-500 text-xs leading-relaxed mt-4 mb-0">{t("requisites_note")}</p>
          </div>
          <div className="bg-slate-800/50 rounded-2xl p-6" data-testid="operator-support">
            <h2 className="text-lg font-bold text-white mb-3">{t("support_title")}</h2>
            <p className="text-slate-300 text-sm leading-relaxed">{t("support_body")}</p>
            {SUPPORT_EMAIL_LIVE ? (
              <a href={`mailto:${SUPPORT_EMAIL}`} className="text-green-400 font-semibold">{SUPPORT_EMAIL}</a>
            ) : (
              <p className="text-amber-300 text-sm m-0" data-testid="billing-support-email-not-live">{support("email_not_live_body")}</p>
            )}
            {supportPhone && (
              <p className="text-slate-300 text-sm mt-3 mb-0" data-testid="operator-support-phone">
                {t("support_phone", { phone: formatPhone(supportPhone) })}
              </p>
            )}
          </div>
        </section>

        {/* Legal links */}
        <nav aria-label="Subscription documents" className="mt-10 flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm">
          <a href={href("/cancel")} className="text-green-400 underline hover:text-green-300">{t("link_cancel")}</a>
          <a href={href("/terms")} className="text-slate-400 underline hover:text-white">{t("link_terms")}</a>
          <a href={href("/privacy-policy")} className="text-slate-400 underline hover:text-white">{t("link_privacy")}</a>
        </nav>
      </main>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(buildJsonLd(terms, faq)) }}
      />
    </div>
  );
}

function CheckItem({ children }: { children: ReactNode }) {
  return (
    <li className="flex items-start gap-2 text-sm text-slate-300">
      <svg aria-hidden="true" focusable="false" className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
      </svg>
      <span>{children}</span>
    </li>
  );
}

/** Product offers in rubles plus the FAQ, for search-result rich snippets. */
function buildJsonLd(terms: BillingTerms, faq: ReadonlyArray<{ q: string; a: string }>) {
  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "FAQPage",
        mainEntity: faq.map((item) => ({
          "@type": "Question",
          name: item.q,
          acceptedAnswer: { "@type": "Answer", text: item.a },
        })),
      },
      {
        "@type": "Product",
        name: "Cleanway",
        brand: { "@type": "Brand", name: "Cleanway" },
        offers: [
          {
            "@type": "Offer",
            name: `Cleanway — ${terms.includedDevices}`,
            price: terms.priceRub,
            priceCurrency: "RUB",
            availability: "https://schema.org/InStock",
            priceSpecification: {
              "@type": "UnitPriceSpecification",
              price: terms.priceRub,
              priceCurrency: "RUB",
              billingDuration: "P1M",
              unitCode: "MON",
            },
          },
        ],
      },
    ],
  };
}
