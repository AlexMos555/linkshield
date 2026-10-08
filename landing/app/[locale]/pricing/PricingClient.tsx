"use client";
import { useLocale, useTranslations } from "next-intl";
import { useState, type ReactNode } from "react";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { localePath } from "@/lib/locale-path";
import { checkoutPlanKey, monthsFree, usd, type Interval, type WorldPricing } from "@/lib/world-pricing";

interface PricingClientProps {
  pricing: WorldPricing;
  /** From `?interval=` after sign-up; yearly otherwise (lib/world-pricing.ts). */
  initialInterval: Interval;
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

/**
 * Outcome of a checkout attempt — rendered as inline error UI, never alert().
 * "invalid_url" / "wrong_host" are folded into one message for the reader.
 */
type CheckoutError =
  | "network"
  | "server"
  | "bad_response"
  | "already_subscribed";

type CheckoutOutcome =
  | { ok: true }
  | { ok: false; reason: CheckoutError };

/**
 * Kick off a Stripe Checkout session for the device plan on the chosen interval.
 *
 *   - 200: redirect to the Stripe-hosted checkout URL (checkout.stripe.com only)
 *   - 401: send the visitor to /signup, which brings them back here with the
 *          same interval selected
 *   - 410: soft-deleted account → /account/restore
 *   - 409: the account already pays (any source)
 */
async function startCheckout(
  interval: Interval,
  locale: string,
  // The country the shown prices were computed for (/pricing/for-country
  // echoes it). Sent along so checkout charges exactly the shown price.
  country: string | null,
): Promise<CheckoutOutcome> {
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
      body: JSON.stringify({
        plan: checkoutPlanKey(interval), // matches backend parse_plan_key
        success_url,
        cancel_url,
        ...(country ? { country } : {}),
      }),
    });
  } catch {
    return { ok: false, reason: "network" };
  }

  if (resp.status === 401) {
    window.location.href = localePath(locale, `/signup?plan=devices&interval=${interval}`);
    return { ok: true };
  }

  if (resp.status === 410) {
    // Soft-deleted account in 30-day grace window. Route them to the
    // restore page (preserving their locale prefix).
    window.location.href = localePath(locale, "/account/restore?reason=locked");
    return { ok: true };
  }

  if (resp.status === 409) {
    // subscription_already_active — one paid subscription per account.
    return { ok: false, reason: "already_subscribed" };
  }

  if (!resp.ok) {
    return { ok: false, reason: "server" };
  }

  const data = (await resp.json().catch(() => null)) as { checkout_url?: string } | null;
  if (!data || !data.checkout_url) {
    return { ok: false, reason: "bad_response" };
  }

  // Origin validation: only ever follow a checkout.stripe.com URL, so a
  // compromised /payments/checkout cannot turn this button into an open
  // redirect.
  let target: URL;
  try {
    target = new URL(data.checkout_url);
  } catch {
    return { ok: false, reason: "bad_response" };
  }
  if (target.protocol !== "https:" || target.hostname !== "checkout.stripe.com") {
    return { ok: false, reason: "bad_response" };
  }
  window.location.href = target.href;
  return { ok: true };
}

export default function PricingClient({ pricing, initialInterval }: PricingClientProps) {
  // Yearly is pre-selected on the web: one payment fee covers the year, so
  // the yearly price is where the visitor's money goes furthest.
  const [interval, setInterval] = useState<Interval>(initialInterval);
  const [checkoutError, setCheckoutError] = useState<CheckoutError | null>(null);
  const [checkoutPending, setCheckoutPending] = useState(false);
  const locale = useLocale();
  const t = useTranslations("Pricing");
  const nav = useTranslations("Nav");

  const months = monthsFree(pricing);
  const price = pricing.price[interval];
  const extra = pricing.extraDevice[interval];

  return (
    <section className="pb-16 px-6">
      <div className="max-w-5xl mx-auto">
        {/* Interval toggle */}
        <div className="flex justify-center mb-10">
          <div role="radiogroup" aria-label={t("interval_label")} className="inline-flex bg-slate-800/60 border border-slate-700 rounded-full p-1">
            {(["monthly", "yearly"] as const).map((opt) => (
              <button
                key={opt}
                type="button"
                role="radio"
                aria-checked={interval === opt}
                data-testid={`interval-${opt}`}
                onClick={() => setInterval(opt)}
                className={`px-5 py-2 min-h-[44px] rounded-full text-sm font-semibold transition ${
                  interval === opt ? "bg-green-500 text-green-950" : "text-slate-300 hover:text-white"
                }`}
              >
                {opt === "monthly" ? t("interval_monthly") : t("interval_yearly")}
                {opt === "yearly" && months > 0 && (
                  <span
                    data-testid="yearly-saving"
                    className={`ms-2 rounded-full px-2 py-0.5 text-xs font-bold ${
                      interval === "yearly" ? "bg-green-950/20" : "bg-green-500/15 text-green-400"
                    }`}
                  >
                    {t("yearly_saving", { months })}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-6 items-stretch">
          {/* Free */}
          <article data-testid="plan-card-free" className="relative rounded-2xl p-6 flex flex-col bg-slate-800/50 border border-slate-700">
            <h3 className="text-xl font-bold text-white mb-1">{t("free_plan_name")}</h3>
            <p className="text-sm text-slate-400 mb-5">{t("free_plan_tagline")}</p>
            <p className="mb-6 text-4xl font-extrabold text-white">$0</p>
            <ul className="space-y-2 flex-grow mb-6">
              <Feature>{t("free_item_block")}</Feature>
              <Feature>{t("free_item_checks", { checks: pricing.freeChecksPerDay })}</Feature>
              <Feature>{t("free_item_first_days", { days: pricing.freeUnlimitedDays })}</Feature>
              <Feature>{t("free_item_account")}</Feature>
            </ul>
            <PrimaryInstallLink
              androidLabel={nav("install_android")}
              className="block text-center px-4 py-3 min-h-[44px] rounded-xl font-semibold transition bg-slate-700 text-white hover:bg-slate-600"
            >
              {nav("install")}
            </PrimaryInstallLink>
          </article>

          {/* Unlimited — the one paid plan */}
          <article
            data-testid="plan-card-unlimited"
            className="relative rounded-2xl p-6 flex flex-col bg-gradient-to-b from-green-500/10 to-slate-800/60 border-2 border-green-500/40 shadow-xl shadow-green-500/10"
          >
            <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-green-500 text-green-950 text-xs font-bold px-3 py-1 rounded-full">
              {t("plan_badge")}
            </span>
            <h3 className="text-xl font-bold text-white mb-1">{t("plan_name")}</h3>
            <p className="text-sm text-slate-400 mb-5">{t("plan_tagline")}</p>
            <p className="flex items-baseline gap-1" data-testid="plan-price">
              <span className="text-4xl font-extrabold text-white">{usd(price.amount)}</span>
              <span className="text-slate-400 text-sm">{interval === "monthly" ? t("per_month") : t("per_year")}</span>
            </p>
            <p className="text-xs text-slate-400 mt-1 mb-5">
              {interval === "yearly"
                ? t("billed_yearly", { price: usd(price.monthlyEquivalent) })
                : t("billed_monthly")}
            </p>
            <ul className="space-y-2 flex-grow mb-6">
              <Feature>{t("plan_item_everything_free")}</Feature>
              <Feature>{t("plan_item_unlimited")}</Feature>
              <Feature>{t("plan_item_devices", { devices: pricing.includedDevices })}</Feature>
              <Feature testId="plan-extra-device">
                {interval === "monthly"
                  ? t("plan_item_extra_monthly", { price: usd(extra.amount) })
                  : t("plan_item_extra_yearly", { price: usd(extra.amount) })}
              </Feature>
              <Feature>{t("plan_item_unlink")}</Feature>
            </ul>
            <button
              type="button"
              disabled={checkoutPending}
              aria-busy={checkoutPending}
              data-testid="plan-checkout"
              onClick={async () => {
                setCheckoutError(null);
                setCheckoutPending(true);
                const result = await startCheckout(interval, locale, pricing.country);
                if (!result.ok) {
                  setCheckoutError(result.reason);
                  setCheckoutPending(false);
                }
                // On success window.location.href has fired — keep the
                // spinner up so the user doesn't double-click while the
                // browser navigates away.
              }}
              className={`block w-full text-center px-4 py-3 min-h-[44px] rounded-xl font-semibold transition bg-green-500 text-green-950 hover:bg-green-400 ${
                checkoutPending ? "opacity-70 cursor-wait" : ""
              }`}
            >
              {checkoutPending ? t("plan_cta_loading") : t("plan_cta")}
            </button>
            {pricing.trialDays > 0 && (
              <p className="mt-3 text-xs text-center text-slate-400">{t("plan_trial_note", { days: pricing.trialDays })}</p>
            )}
            {/* aria-live polite so screen readers announce the error when it appears. */}
            <div role="status" aria-live="polite" className="mt-3">
              {checkoutError && (
                <div className="text-sm text-red-200 bg-red-500/10 border border-red-500/40 rounded-lg px-3 py-2">
                  {t(`checkout_error_${checkoutError}`)}
                </div>
              )}
            </div>
          </article>
        </div>

        {pricing.country === null && (
          <p className="mt-6 text-center text-xs text-slate-500">{t("base_region_note")}</p>
        )}
      </div>
    </section>
  );
}

function Feature({ children, testId }: { children: ReactNode; testId?: string }) {
  return (
    <li className="flex items-start gap-2 text-sm text-slate-300" data-testid={testId}>
      <svg aria-hidden="true" focusable="false" className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
      </svg>
      <span>{children}</span>
    </li>
  );
}
