import type { Metadata } from "next";
import { headers } from "next/headers";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { createClient } from "@cleanway/api-client";
import PricingClient from "./PricingClient";
import FreePricing from "./FreePricing";
import OperatorPricing from "./OperatorPricing";
import PricingNav from "./PricingNav";
import { routing, type Locale } from "@/i18n/routing";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { InstallButtons } from "@/components/InstallButtons";
import { billingMessageArgs } from "@/lib/billing";
import { BILLING_TERMS, SELLER, SUPPORT_PHONE, pricingVariantFor } from "@/lib/billing-config";
import { localePath } from "@/lib/locale-path";
import { DEFAULT_PRICING, intervalFrom, normalizePricing, usd, type WorldPricing } from "@/lib/world-pricing";

const SITE_URL = "https://cleanway.ai";

function pricingUrlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/pricing` : `${SITE_URL}/${locale}/pricing`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const canonical = pricingUrlFor(safeLocale);

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = pricingUrlFor(loc as Locale);
  languages["x-default"] = pricingUrlFor(routing.defaultLocale);

  const t = await getTranslations({ locale: safeLocale, namespace: "Pricing" });
  // The hero subtitle does double duty as the meta description — same
  // promise, same cultural register. A free-only locale gets the free copy:
  // its link preview must not talk about paying; with the operator-billed
  // subscription switched on, the preview names the subscription instead.
  const variant = pricingVariantFor({ locale: safeLocale });
  const billing = await getTranslations({ locale: safeLocale, namespace: "Billing" });
  const title = `${variant === "free" ? t("free_title") : variant === "operator" ? billing("meta_title") : t("page_title")} — Cleanway`;
  const description =
    variant === "free" ? t("free_subtitle")
    : variant === "operator" ? billing("meta_description", billingMessageArgs(BILLING_TERMS))
    : t("hero_subtitle", { devices: DEFAULT_PRICING.includedDevices });

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title,
      description,
      url: canonical,
      siteName: "Cleanway",
      type: "website",
      locale: safeLocale,
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      site: "@cleanwayai",
    },
    robots: {
      index: true,
      follow: true,
      googleBot: { index: true, follow: true, "max-image-preview": "large" },
    },
  };
}

const DEFAULT_API_URL = "https://api.cleanway.ai";

// Shared API client — typed, timeout-enforced, never throws.
// One instance per SSR render is fine: it's stateless, just closes over config.
const api = createClient({
  baseUrl: process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL,
  timeoutMs: 5000,
});

const COUNTRY = /^[A-Za-z]{2}$/;

/**
 * The device plan for this visitor's country, or the base tier when the API is
 * down or still serves the plans from before the device plan (the site and the
 * API deploy separately — lib/world-pricing.ts checks the shape at runtime).
 */
async function fetchPricing(country: string | null): Promise<WorldPricing> {
  const { data, error } = await api.pricing.forCountry(country && COUNTRY.test(country) ? country : undefined);
  if (error) {
    // In SSR we don't have a logger wired; console.warn surfaces in Vercel logs
    // and lets us see patterns (which countries 404, which regions time out).
    // eslint-disable-next-line no-console
    console.warn("[pricing] API fetch failed:", error.kind, error.message);
    return DEFAULT_PRICING;
  }
  const pricing = normalizePricing(data);
  if (!pricing) {
    // eslint-disable-next-line no-console
    console.warn("[pricing] API answered without the device plan; showing base-tier prices");
    return DEFAULT_PRICING;
  }
  return pricing;
}

const FAQ_KEYS = ["device", "unlink", "free", "cancel", "refund", "region"] as const;

export default async function PricingPage({
  searchParams,
  params,
}: {
  searchParams: Promise<{ cc?: string; interval?: string }>;
  params: Promise<{ locale: string }>;
}) {
  const { cc, interval } = await searchParams;
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  setRequestLocale(safeLocale);
  // Vercel's edge geo header; ?cc= overrides it for testing a region.
  const country = cc ?? (await headers()).get("x-vercel-ip-country");
  const variant = pricingVariantFor({ locale: safeLocale, country });
  if (variant === "free") {
    return <FreePricing locale={safeLocale} />;
  }
  if (variant === "operator") {
    return <OperatorPricing locale={safeLocale} terms={BILLING_TERMS} seller={SELLER} supportPhone={SUPPORT_PHONE} />;
  }
  const t = await getTranslations({ locale: safeLocale, namespace: "Pricing" });
  const hero = await getTranslations({ locale: safeLocale, namespace: "Hero" });
  // The prices shown are the prices of the visitor's country — and the same
  // country goes to checkout (pricing.country), so the charge matches.
  const pricing = await fetchPricing(country);
  const faqArgs = {
    devices: pricing.includedDevices,
    extra: usd(pricing.extraDevice.monthly.amount),
    checks: pricing.freeChecksPerDay,
    days: pricing.freeUnlimitedDays,
  };
  const faq = FAQ_KEYS.map((key) => ({ q: t(`faq_${key}_q`), a: t(`faq_${key}_a`, faqArgs) }));

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200" data-testid="world-pricing">
      <PricingNav locale={safeLocale} />

      {/* Hero */}
      <section className="pt-20 pb-12 px-6 text-center">
        <div className="max-w-3xl mx-auto">
          <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-6">
            {t("hero_badge")}
          </span>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">{t("hero_title")}</h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto mb-6">
            {t("hero_subtitle", { devices: pricing.includedDevices })}
          </p>
          <div className="inline-flex items-center gap-2 bg-slate-800/60 border border-slate-700 px-4 py-2 rounded-full text-sm text-slate-300">
            <span aria-hidden="true" className="w-2 h-2 bg-green-400 rounded-full"></span>
            {pricing.country ? t("region_badge", { country: pricing.country }) : t("region_badge_default")}
          </div>
        </div>
      </section>

      {/* Plan cards (client for the interval toggle and checkout) */}
      <PricingClient pricing={pricing} initialInterval={intervalFrom(interval)} />

      {/* The invariant: blocking never stops */}
      <section className="py-16 px-6 bg-slate-900/40 border-y border-slate-800">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white mb-6">{t("always_title")}</h2>
          <p className="text-white text-lg leading-relaxed mb-4">{t("always_body")}</p>
          <p className="text-slate-400 text-sm leading-relaxed">{t("always_note")}</p>
        </div>
      </section>

      {/* Regional pricing explainer */}
      <section className="py-16 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-2xl md:text-3xl font-extrabold text-white mb-4">{t("region_title")}</h2>
          <p className="text-slate-400 leading-relaxed">{t("region_body")}</p>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-16 px-6 bg-slate-900/40 border-t border-slate-800" aria-labelledby="pricing-faq-title">
        <div className="max-w-3xl mx-auto">
          <h2 id="pricing-faq-title" className="text-3xl md:text-4xl font-extrabold text-white text-center mb-10">{t("faq_title")}</h2>
          <div className="space-y-4" data-testid="pricing-faq">
            {faq.map((item) => (
              <details key={item.q} className="bg-slate-800/50 rounded-xl p-5 group">
                <summary className="cursor-pointer font-semibold text-white list-none flex justify-between items-center gap-4">
                  <span>{item.q}</span>
                  <span aria-hidden="true" className="text-slate-400 group-open:rotate-180 transition">▾</span>
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed">{item.a}</p>
              </details>
            ))}
          </div>
          <p className="mt-10 text-center text-sm text-slate-500">
            {t("business_note")}{" "}
            <a href={localePath(safeLocale, "/business")} className="text-green-400 underline hover:text-green-300">{t("business_link")}</a>
          </p>
        </div>
      </section>

      {/* Footer CTA */}
      <section className="py-20 px-6 text-center">
        <div className="max-w-2xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white mb-4">{t("footer_cta_title")}</h2>
          <p className="text-slate-400 mb-8">{t("footer_cta_body")}</p>
          <PrimaryInstallLink androidLabel={hero("cta_android")} className="inline-block bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition">
            {hero("cta_primary")}
          </PrimaryInstallLink>
          <div className="mt-8">
            <InstallButtons platforms={["android","ios"]} size="sm" />
          </div>
          <div className="mt-4">
            <InstallButtons platforms={["chrome","firefox","edge","safari"]} size="sm" />
          </div>
        </div>
      </section>

      {/* Rich snippets — Product (with the regional offers) + FAQPage */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify(buildPricingJsonLd(pricing, faq, t("plan_name"))),
        }}
      />
    </div>
  );
}

/**
 * One Product — the device plan — with its monthly and yearly Offers at the
 * prices this visitor was shown, plus the FAQ, so search results can show
 * price chips and answers.
 */
function buildPricingJsonLd(pricing: WorldPricing, faq: ReadonlyArray<{ q: string; a: string }>, planName: string) {
  const name = `Cleanway ${planName}`;
  const offer = (interval: "monthly" | "yearly") => ({
    "@type": "Offer",
    name: `${name} — ${interval === "monthly" ? "Monthly" : "Yearly"}`,
    price: pricing.price[interval].amount,
    priceCurrency: "USD",
    availability: "https://schema.org/InStock",
    priceSpecification: {
      "@type": "UnitPriceSpecification",
      price: pricing.price[interval].amount,
      priceCurrency: "USD",
      billingDuration: interval === "monthly" ? "P1M" : "P1Y",
      unitCode: interval === "monthly" ? "MON" : "ANN",
    },
  });

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
        name,
        description: `Unlimited detailed checks of links and messages on ${pricing.includedDevices} devices of one account.`,
        brand: { "@type": "Brand", name: "Cleanway" },
        offers: {
          "@type": "AggregateOffer",
          priceCurrency: "USD",
          lowPrice: pricing.price.monthly.amount,
          highPrice: pricing.price.yearly.amount,
          offerCount: 2,
          offers: [offer("monthly"), offer("yearly")],
        },
      },
    ],
  };
}
