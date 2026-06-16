"use client";
import { useLocale, useTranslations } from "next-intl";
import { useState } from "react";
import type { PricingFor } from "@cleanway/api-client";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";

// All shapes come from the generated contract — no hand-rolled types here.
// If the API changes, `npm run build:api-types` regenerates the types and this
// component fails to compile until it's updated. That's the whole point.
type PricingData = PricingFor;
type Interval = "monthly" | "yearly";
type PaidPlan = "personal" | "family";

interface PricingClientProps {
  data: PricingData;
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

/**
 * Kick off a Stripe Checkout session for the chosen plan + interval.
 *
 * Auth status is unknown from the client's perspective (we don't have a
 * landing-side login UI yet), so we attempt the POST and:
 *   - 200: redirect to the Stripe-hosted checkout URL
 *   - 401: redirect to /signup?plan=X so the user can create an account
 *          and resume the checkout flow
 *   - other: show a friendly error and stay on the page
 */
const DEFAULT_LOCALE = "en";

/** Build a locale-prefixed path matching `localePrefix: "as-needed"`. */
function localePath(locale: string, path: string): string {
  return locale === DEFAULT_LOCALE ? path : `/${locale}${path}`;
}

/**
 * Outcome of a checkout attempt — the click handler swallows the
 * promise and renders inline error UI based on the reason. Replaces
 * the old alert()-based reporting which blocked the UI thread and
 * couldn't be styled. (Audit landing UX MEDIUM "Three checkout error
 * paths use browser alert() — blocks the UI thread and cannot be
 * styled".)
 */
type CheckoutError =
  | "network"
  | "server"
  | "bad_response"
  | "invalid_url"
  | "wrong_host";

type CheckoutOutcome =
  | { ok: true }
  | { ok: false; reason: CheckoutError };

async function startCheckout(
  plan: PaidPlan,
  interval: Interval,
  locale: string,
): Promise<CheckoutOutcome> {
  const planKey = `${plan}_${interval}`; // matches backend CheckoutRequest.plan
  const success_url = "https://cleanway.ai/success?session_id={CHECKOUT_SESSION_ID}";
  const cancel_url = "https://cleanway.ai/pricing";

  // Pull the Supabase session token so the backend's get_current_user
  // dependency accepts the request. If Supabase isn't configured yet
  // (NEXT_PUBLIC_SUPABASE_* missing in this build), token is null and
  // the backend will 401 — handled below by sending the user to /signup.
  let bearer: string | null = null;
  if (isAuthConfigured()) {
    try {
      const { data } = await getSupabaseClient().auth.getSession();
      bearer = data.session?.access_token ?? null;
    } catch {
      bearer = null;
    }
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (bearer) headers["Authorization"] = `Bearer ${bearer}`;

  let resp: Response;
  try {
    resp = await fetch(`${API_BASE}/api/v1/payments/checkout`, {
      method: "POST",
      credentials: "include",
      headers,
      body: JSON.stringify({ plan: planKey, success_url, cancel_url }),
    });
  } catch {
    return { ok: false, reason: "network" };
  }

  if (resp.status === 401) {
    window.location.href = localePath(locale, `/signup?plan=${plan}&interval=${interval}`);
    return { ok: true };
  }

  if (resp.status === 410) {
    // Soft-deleted account in 30-day grace window. Supabase session is
    // alive but the API is refusing every authed call. Route them to the
    // restore page (preserving their locale prefix) instead of letting
    // them bounce through generic error UX.
    window.location.href = localePath(locale, "/account/restore?reason=locked");
    return { ok: true };
  }

  if (!resp.ok) {
    return { ok: false, reason: "server" };
  }

  const data = (await resp.json().catch(() => null)) as { checkout_url?: string } | null;
  if (!data || !data.checkout_url) {
    return { ok: false, reason: "bad_response" };
  }

  // Origin validation. The backend SHOULD only ever return a
  // checkout.stripe.com URL, but verifying client-side closes the
  // open-redirect class: a compromised /payments/checkout endpoint
  // (server-side template-injection, misconfigured Stripe SDK, etc.)
  // could otherwise hand the client back any URL and we'd redirect
  // straight to it. (Audit landing-security MEDIUM "checkout_url
  // from API assigned to window.location.href with no origin
  // validation".)
  let target: URL;
  try {
    target = new URL(data.checkout_url);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  if (target.protocol !== "https:" || target.hostname !== "checkout.stripe.com") {
    return { ok: false, reason: "wrong_host" };
  }
  window.location.href = target.href;
  return { ok: true };
}

const CHECKOUT_ERROR_COPY: Record<CheckoutError, string> = {
  network: "Couldn't reach our servers. Please try again in a moment.",
  server: "Couldn't start checkout. Please try again or contact support.",
  bad_response: "Checkout didn't return a redirect URL — please contact support.",
  invalid_url: "Checkout returned an invalid URL — please contact support.",
  wrong_host: "Checkout returned an unexpected URL — please contact support.",
};

export default function PricingClient({ data }: PricingClientProps) {
  const [interval, setInterval] = useState<Interval>("monthly");
  // Needed for locale-aware redirects on auth failure (401 → /signup)
  // and soft-delete lock (410 → /account/restore). With
  // `localePrefix: "as-needed"`, a non-EN user MUST keep their prefix
  // or they'd be silently moved to English mid-flow.
  const locale = useLocale();
  const t = useTranslations("Pricing");

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
                {opt === "monthly"
                  ? t("interval_monthly")
                  : `${t("interval_yearly")} · ${t("badge_save_2_months")}`}
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
            paidPlan="personal"
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
            paidPlan="family"
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
  // When set, the CTA becomes a button that hits /payments/checkout
  // for that plan + current interval. Free plan and Business stay as
  // anchor links via ctaHref.
  paidPlan?: PaidPlan;
}

function PlanCard({ name, subtitle, price, monthlyEquivalent, interval, priceSuffix, features, cta, ctaHref = "#", emphasis, badge, paidPlan }: PlanCardProps) {
  const locale = useLocale();
  const [checkoutError, setCheckoutError] = useState<CheckoutError | null>(null);
  const [checkoutPending, setCheckoutPending] = useState(false);
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
      {paidPlan ? (
        <>
          <button
            type="button"
            disabled={checkoutPending}
            aria-busy={checkoutPending}
            onClick={async () => {
              setCheckoutError(null);
              setCheckoutPending(true);
              const result = await startCheckout(paidPlan, interval, locale);
              if (!result.ok) {
                setCheckoutError(result.reason);
                setCheckoutPending(false);
              }
              // On success window.location.href has fired — keep the
              // spinner up so the user doesn't double-click while the
              // browser navigates away.
            }}
            className={`block w-full text-center px-4 py-3 rounded-xl font-semibold transition ${
              checkoutPending
                ? "opacity-70 cursor-wait"
                : ""
            } ${
              emphasis
                ? "bg-green-500 text-green-950 hover:bg-green-400"
                : "bg-slate-700 text-white hover:bg-slate-600"
            }`}
          >
            {checkoutPending ? "Loading…" : cta}
          </button>
          {/* aria-live polite so screen readers announce the error
              when it appears without interrupting whatever's being
              read. Replaces the blocking alert() flow. */}
          <div role="status" aria-live="polite" className="mt-3">
            {checkoutError && (
              <div className="text-sm text-red-200 bg-red-500/10 border border-red-500/40 rounded-lg px-3 py-2">
                {CHECKOUT_ERROR_COPY[checkoutError]}
              </div>
            )}
          </div>
        </>
      ) : (
        <a
          href={ctaHref}
          className={`block text-center px-4 py-3 rounded-xl font-semibold transition ${
            emphasis ? "bg-green-500 text-green-950 hover:bg-green-400" : "bg-slate-700 text-white hover:bg-slate-600"
          }`}
        >
          {cta}
        </a>
      )}
    </div>
  );
}
