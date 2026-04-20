"use client";
import { useState } from "react";
import type { PricingFor } from "@linkshield/api-client";

// All shapes come from the generated contract — no hand-rolled types here.
// If the API changes, `npm run build:api-types` regenerates the types and this
// component fails to compile until it's updated. That's the whole point.
type PricingData = PricingFor;
type Interval = "monthly" | "yearly";

interface PricingClientProps {
  data: PricingData;
}

export default function PricingClient({ data }: PricingClientProps) {
  const [interval, setInterval] = useState<Interval>("monthly");

  return (
    <section className="pb-16 px-6">
      <div className="max-w-6xl mx-auto">
        {/* Interval toggle */}
        <div className="flex justify-center mb-10">
          <div className="inline-flex bg-slate-800/60 border border-slate-700 rounded-full p-1">
            {(["monthly", "yearly"] as const).map((opt) => (
              <button
                key={opt}
                type="button"
                onClick={() => setInterval(opt)}
                className={`px-6 py-2 rounded-full text-sm font-semibold transition ${
                  interval === opt ? "bg-green-500 text-green-950" : "text-slate-400 hover:text-white"
                }`}
              >
                {opt === "monthly" ? "Monthly" : "Yearly · save 17%"}
              </button>
            ))}
          </div>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-5">
          {/* Free */}
          <PlanCard
            name="Free"
            subtitle="Forever, no credit card"
            price={0}
            interval={interval}
            features={[
              "Unlimited link scanning",
              "Green/yellow/red badges",
              "Block page always works",
              "First 50 detailed threats",
              "30-day history",
              "Privacy Audit (grade)",
              "1 device · 10 languages",
            ]}
            cta="Add to Chrome"
            ctaHref="https://chrome.google.com/webstore"
            emphasis={false}
          />

          {/* Personal */}
          <PlanCard
            name="Personal"
            subtitle="Full experience for you"
            price={data.plans.personal[interval].amount}
            monthlyEquivalent={data.plans.personal[interval].monthly_equivalent}
            interval={interval}
            features={[
              "Everything in Free",
              "Unlimited threat details",
              "Full Privacy Audit",
              "Security Score breakdown",
              "Weekly Report + percentile",
              "Priority ML updates",
              "Email support",
            ]}
            cta="Try 14 days free"
            emphasis={false}
          />

          {/* Family — emphasized */}
          <PlanCard
            name="Family"
            subtitle="Protect up to 6 loved ones"
            price={data.plans.family[interval].amount}
            monthlyEquivalent={data.plans.family[interval].monthly_equivalent}
            interval={interval}
            features={[
              "Everything in Personal",
              "Up to 6 family members",
              "Granny Mode remote control",
              "Kids Mode + parental dashboard",
              "Real-time block alerts",
              '"Ask a grandchild" button',
              "5 devices + cloud sync",
            ]}
            cta="Try 14 days free"
            emphasis={true}
            badge="Most popular"
          />

          {/* Business */}
          <PlanCard
            name="Business"
            subtitle="Per user · min 1 seat"
            price={data.plans.business[interval].amount}
            monthlyEquivalent={data.plans.business[interval].monthly_equivalent}
            interval={interval}
            priceSuffix="/user"
            features={[
              "Everything in Family",
              "Email proxy (scan before inbox)",
              "Phishing simulation campaigns",
              "SSO (SAML / OIDC)",
              "SCIM provisioning",
              "Org dashboard + reports",
              "API access · priority SLA",
            ]}
            cta="Contact sales"
            ctaHref="/business"
            emphasis={false}
          />
        </div>

        {data.country === null && (
          <p className="mt-6 text-center text-xs text-slate-500">
            Prices shown at base tier (Tier 2). Final price determined by your Stripe billing country.
          </p>
        )}
      </div>
    </section>
  );
}

interface PlanCardProps {
  name: string;
  subtitle: string;
  price: number;
  monthlyEquivalent?: number;
  interval: Interval;
  priceSuffix?: string;
  features: readonly string[];
  cta: string;
  ctaHref?: string;
  emphasis: boolean;
  badge?: string;
}

function PlanCard({ name, subtitle, price, monthlyEquivalent, interval, priceSuffix, features, cta, ctaHref = "#", emphasis, badge }: PlanCardProps) {
  const displayPrice = price === 0 ? "$0" : `$${price.toFixed(2)}`;
  const intervalLabel = price === 0 ? "" : interval === "monthly" ? "/mo" : "/yr";

  return (
    <div
      className={`relative rounded-2xl p-6 flex flex-col ${
        emphasis
          ? "bg-gradient-to-b from-green-500/10 to-slate-800/60 border-2 border-green-500/40 shadow-xl shadow-green-500/10"
          : "bg-slate-800/50 border border-slate-700"
      }`}
    >
      {badge && (
        <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-green-500 text-green-950 text-xs font-bold px-3 py-1 rounded-full">
          {badge}
        </span>
      )}
      <div>
        <h3 className="text-xl font-bold text-white mb-1">{name}</h3>
        <p className="text-sm text-slate-400 mb-5">{subtitle}</p>
        <div className="mb-1 flex items-baseline gap-1">
          <span className="text-4xl font-extrabold text-white">{displayPrice}</span>
          <span className="text-slate-400 text-sm">{priceSuffix}{intervalLabel}</span>
        </div>
        {monthlyEquivalent !== undefined && interval === "yearly" && price > 0 && (
          <p className="text-xs text-slate-500 mb-5">≈ ${monthlyEquivalent.toFixed(2)}/mo billed annually</p>
        )}
        {(monthlyEquivalent === undefined || interval === "monthly" || price === 0) && <div className="mb-5" />}
      </div>
      <ul className="space-y-2 flex-grow mb-6">
        {features.map((f) => (
          <li key={f} className="flex items-start gap-2 text-sm text-slate-300">
            <svg className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>{f}</span>
          </li>
        ))}
      </ul>
      <a
        href={ctaHref}
        className={`block text-center px-4 py-3 rounded-xl font-semibold transition ${
          emphasis ? "bg-green-500 text-green-950 hover:bg-green-400" : "bg-slate-700 text-white hover:bg-slate-600"
        }`}
      >
        {cta}
      </a>
    </div>
  );
}
