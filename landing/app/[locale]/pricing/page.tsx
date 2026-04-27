import type { Metadata } from "next";
import { createClient, type PricingFor } from "@cleanway/api-client";
import PricingClient from "./PricingClient";
import { routing, type Locale } from "@/i18n/routing";

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

  const title = "Pricing — Cleanway";
  const description =
    "Fair, regional pricing. Free forever for blocking phishing. Pay only for details, family protection, and accessibility modes.";

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

// FAQ data lifted out of the JSX so we can both render it AND emit it as
// FAQPage structured data for rich snippets in Google SERPs.
const FAQ_ITEMS: ReadonlyArray<{ q: string; a: string }> = [
  {
    q: "Do I really get blocking for free, forever?",
    a: "Yes. Phishing site blocking is a right, not a feature to paywall. You could use Cleanway free for 20 years and it would block every known scam site the whole time.",
  },
  {
    q: "What happens after 50 blocked threats on the free tier?",
    a: "Blocking still works — you're still protected. But the detailed \"why is this site dangerous\" explanation gets locked behind the paywall. Simple message, but the block itself never goes away.",
  },
  {
    q: "Can I install it for my mom or grandma?",
    a: "That's exactly who we built it for. Use Family plan ($9.99/mo at base tier) to manage her device remotely, enable Granny Mode (huge fonts + voice alerts), and get notified when a scam is blocked for her.",
  },
  {
    q: "Why is it cheaper in India / Indonesia?",
    a: "Because $4.99/month is a significant fraction of minimum wage there. We use PPP (purchasing power parity) tiers — same product, fair local price. Tier detected from your Stripe billing country, not your IP, so VPN bypass doesn't work either way.",
  },
  {
    q: "Can I cancel anytime?",
    a: "Yes. Monthly plans cancel instantly at end of period. Yearly plans have a 30-day money-back guarantee. No hidden fees, no renewal tricks.",
  },
];

// Shared API client — typed, timeout-enforced, never throws.
// One instance per SSR render is fine: it's stateless, just closes over config.
const api = createClient({
  baseUrl: process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL,
  timeoutMs: 5000,
});

type PricingData = PricingFor;

async function fetchPricing(cc?: string): Promise<PricingData | null> {
  const { data, error } = await api.pricing.forCountry(cc);
  if (error) {
    // In SSR we don't have a logger wired; console.warn surfaces in Vercel logs
    // and lets us see patterns (which countries 404, which regions time out).
    // eslint-disable-next-line no-console
    console.warn("[pricing] API fetch failed:", error.kind, error.message);
    return null;
  }
  return data;
}

export default async function PricingPage({
  searchParams,
}: {
  searchParams: Promise<{ cc?: string }>;
}) {
  const { cc } = await searchParams;
  const initial = await fetchPricing(cc);

  // Fallback if API is down — base tier 2 defaults.
  // Shape intentionally matches PricingFor so prop-drilling into <PricingClient> stays typed.
  const fallback: PricingData = {
    country: cc ?? null,
    tier: 2,
    currency: "USD",
    plans: {
      personal: {
        monthly: { amount: 4.99, monthly_equivalent: 4.99, interval: "monthly", stripe_price_id: "" },
        yearly: { amount: 49.9, monthly_equivalent: 4.99, interval: "yearly", stripe_price_id: "" },
      },
      family: {
        monthly: { amount: 9.99, monthly_equivalent: 9.99, interval: "monthly", stripe_price_id: "" },
        yearly: { amount: 99.9, monthly_equivalent: 9.99, interval: "yearly", stripe_price_id: "" },
      },
      business: {
        monthly: { amount: 3.99, monthly_equivalent: 3.99, interval: "monthly", stripe_price_id: "" },
        yearly: { amount: 39.9, monthly_equivalent: 3.99, interval: "yearly", stripe_price_id: "" },
      },
    },
    messaging: {
      blocking_is_free_forever: true,
      free_threat_threshold: 50,
      what_paid_unlocks: [
        "Detailed explanations for every scam site",
        "Privacy Audit: full tracker list",
        "Family Hub: protect up to 6 loved ones",
        "Granny Mode / Kids Mode for family members",
      ],
    },
  };
  const data: PricingData = initial ?? fallback;

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200">
      {/* Nav */}
      <nav className="sticky top-0 z-50 bg-[#0f172a]/95 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <a href="/" className="text-xl font-extrabold text-white">Cleanway</a>
          <div className="hidden md:flex items-center gap-6">
            <a href="/#features" className="text-sm text-slate-400 hover:text-white transition">Features</a>
            <a href="/pricing" className="text-sm text-white font-semibold">Pricing</a>
            <a href="/business" className="text-sm text-slate-400 hover:text-white transition">Business</a>
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-5 py-2 rounded-lg text-sm font-bold hover:bg-green-400 transition">
              Add to Chrome
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-20 pb-12 px-6 text-center">
        <div className="max-w-3xl mx-auto">
          <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-6">
            Blocking is free forever
          </span>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">
            Fair pricing for{" "}
            <span className="bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent">every country</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto mb-6">
            We believe safety from online scams is a basic right. Block phishing sites — always free.
            Pay only for details, family protection, and accessibility modes.
          </p>
          <TierBadge tier={data.tier} country={data.country} />
        </div>
      </section>

      {/* Pricing cards (client for toggle) */}
      <PricingClient data={data} />

      {/* Free tier explainer */}
      <section className="py-16 px-6 bg-slate-900/40 border-y border-slate-800">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white text-center mb-10">
            What{"'"}s <span className="text-green-400">always free</span>
          </h2>
          <div className="grid md:grid-cols-2 gap-8">
            <ul className="space-y-4">
              {[
                "Automatic link scanning on every page",
                "Green / yellow / red safety badges",
                "Block page for scam sites (always active)",
                "First 50 detailed threat explanations",
                "30-day history of your checks",
                "Privacy Audit grade (A–F) for any site",
                "1 device, all 10 languages",
              ].map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <svg className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  <span className="text-slate-300">{item}</span>
                </li>
              ))}
            </ul>
            <div className="bg-slate-800/60 rounded-2xl p-8 border border-slate-700">
              <div className="text-sm text-green-400 font-semibold uppercase tracking-wide mb-3">Our ethical invariant</div>
              <p className="text-white text-lg leading-relaxed mb-4">
                Blocking a scam site <strong className="text-green-400">always works</strong>, even for free users, even after the {data.messaging.free_threat_threshold}-threat mark.
              </p>
              <p className="text-slate-400 text-sm leading-relaxed">
                Grandma won{"'"}t ever see &quot;Pay to keep being protected from fraud&quot;. That{"'"}s a dark pattern we refuse to ship.
                You pay for details, family features, and accessibility — not for basic safety.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* What paid unlocks */}
      <section className="py-16 px-6">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white text-center mb-10">
            What you get when you{" "}
            <span className="bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent">go premium</span>
          </h2>
          <div className="grid md:grid-cols-2 gap-4">
            {data.messaging.what_paid_unlocks.map((item) => (
              <div key={item} className="bg-slate-800/50 rounded-xl p-5 flex items-start gap-3">
                <span className="text-2xl flex-shrink-0">✨</span>
                <span className="text-slate-200">{item}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Regional pricing explainer */}
      <section className="py-16 px-6 bg-slate-900/40 border-t border-slate-800">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-2xl md:text-3xl font-extrabold text-white mb-4">
            Why your price may differ
          </h2>
          <p className="text-slate-400 leading-relaxed max-w-2xl mx-auto mb-6">
            We use <strong className="text-slate-200">purchasing power parity</strong> — the same price isn{"'"}t fair when average incomes differ 10×.
            Tier 1 countries pay a premium; Tier 4 countries pay 70% less. Protection quality is identical everywhere.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-8 text-left max-w-3xl mx-auto">
            <TierCard tier={1} active={data.tier === 1} examples="US, UK, DE, JP" personalPrice={5.99} />
            <TierCard tier={2} active={data.tier === 2} examples="RU, BR, MX, PL" personalPrice={4.99} />
            <TierCard tier={3} active={data.tier === 3} examples="TH, UA, ZA, CO" personalPrice={2.49} />
            <TierCard tier={4} active={data.tier === 4} examples="IN, ID, VN, EG" personalPrice={1.49} />
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="py-16 px-6">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white text-center mb-10">Questions people actually ask</h2>
          <div className="space-y-4">
            {FAQ_ITEMS.map((item) => (
              <details key={item.q} className="bg-slate-800/50 rounded-xl p-5 group">
                <summary className="cursor-pointer font-semibold text-white list-none flex justify-between items-center">
                  <span>{item.q}</span>
                  <span className="text-slate-400 group-open:rotate-180 transition">▾</span>
                </summary>
                <p className="mt-3 text-slate-400 leading-relaxed">{item.a}</p>
              </details>
            ))}
          </div>
        </div>
      </section>

      {/* Footer CTA */}
      <section className="py-20 px-6 text-center">
        <div className="max-w-2xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white mb-4">Start free today</h2>
          <p className="text-slate-400 mb-8">No credit card. Add to Chrome in 10 seconds. Upgrade only when it makes sense for you.</p>
          <a href="https://chrome.google.com/webstore" className="inline-block bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition">
            Add to Chrome — Free
          </a>
        </div>
      </section>

      {/* Rich snippets — Product (with regional Offers) + FAQPage */}
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: JSON.stringify(buildPricingJsonLd(data)),
        }}
      />
    </div>
  );
}

/**
 * Build a Product graph with the actual prices from the live API response.
 * Each plan (personal/family/business) becomes a Product with monthly+yearly
 * Offers, so Google can surface price chips in SERPs. Currency comes from
 * the regional pricing response — defaults to USD.
 */
function buildPricingJsonLd(data: PricingData) {
  const currency = data.currency || "USD";
  const planConfig: ReadonlyArray<{
    key: "personal" | "family" | "business";
    name: string;
    description: string;
  }> = [
    {
      key: "personal",
      name: "Cleanway Personal",
      description:
        "Unlimited threat detail, full Privacy Audit, Security Score, Weekly Report, priority support.",
    },
    {
      key: "family",
      name: "Cleanway Family",
      description:
        "Up to 6 devices, Family Hub with E2E alerts, Granny Mode + Kids Mode, parental controls.",
    },
    {
      key: "business",
      name: "Cleanway Business",
      description: "Per-seat phishing protection, B2B simulation campaigns, SSO ready.",
    },
  ];

  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "FAQPage",
        mainEntity: FAQ_ITEMS.map((it) => ({
          "@type": "Question",
          name: it.q,
          acceptedAnswer: { "@type": "Answer", text: it.a },
        })),
      },
      ...planConfig.map((plan) => {
        const tier = data.plans[plan.key];
        return {
          "@type": "Product",
          name: plan.name,
          description: plan.description,
          brand: { "@type": "Brand", name: "Cleanway" },
          offers: {
            "@type": "AggregateOffer",
            priceCurrency: currency,
            lowPrice: tier.monthly.amount,
            highPrice: tier.yearly.amount,
            offerCount: 2,
            offers: [
              {
                "@type": "Offer",
                name: `${plan.name} — Monthly`,
                price: tier.monthly.amount,
                priceCurrency: currency,
                availability: "https://schema.org/InStock",
                priceSpecification: {
                  "@type": "UnitPriceSpecification",
                  price: tier.monthly.amount,
                  priceCurrency: currency,
                  billingDuration: "P1M",
                  unitCode: "MON",
                },
              },
              {
                "@type": "Offer",
                name: `${plan.name} — Yearly`,
                price: tier.yearly.amount,
                priceCurrency: currency,
                availability: "https://schema.org/InStock",
                priceSpecification: {
                  "@type": "UnitPriceSpecification",
                  price: tier.yearly.amount,
                  priceCurrency: currency,
                  billingDuration: "P1Y",
                  unitCode: "ANN",
                },
              },
            ],
          },
        };
      }),
    ],
  };
}

function TierBadge({ tier, country }: { tier: 1 | 2 | 3 | 4; country: string | null }) {
  const names = { 1: "Tier 1 · Premium", 2: "Tier 2 · Base", 3: "Tier 3 · Mid", 4: "Tier 4 · Affordable" };
  return (
    <div className="inline-flex items-center gap-2 bg-slate-800/60 border border-slate-700 px-4 py-2 rounded-full text-sm">
      <span className="w-2 h-2 bg-green-400 rounded-full"></span>
      <span className="text-slate-400">Pricing for</span>
      <span className="text-white font-semibold">{country ?? "your region"}</span>
      <span className="text-slate-600">·</span>
      <span className="text-green-400">{names[tier]}</span>
    </div>
  );
}

function TierCard({ tier, active, examples, personalPrice }: { tier: 1 | 2 | 3 | 4; active: boolean; examples: string; personalPrice: number }) {
  const names = { 1: "Premium", 2: "Base", 3: "Mid-emerging", 4: "Affordable" };
  return (
    <div className={`rounded-xl p-4 border ${active ? "bg-green-500/10 border-green-500/40" : "bg-slate-800/40 border-slate-700"}`}>
      <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Tier {tier}</div>
      <div className={`font-bold mb-1 ${active ? "text-green-400" : "text-white"}`}>{names[tier]}</div>
      <div className="text-xs text-slate-500 mb-2">{examples}</div>
      <div className={`text-lg font-extrabold ${active ? "text-green-400" : "text-white"}`}>
        ${personalPrice}
        <span className="text-xs text-slate-500 font-normal">/mo personal</span>
      </div>
    </div>
  );
}
