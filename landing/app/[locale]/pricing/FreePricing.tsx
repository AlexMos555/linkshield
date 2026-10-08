import { useTranslations } from "next-intl";

import { localePath } from "@/lib/locale-path";
import PricingNav from "./PricingNav";

/**
 * /pricing for visitors who cannot be sold a plan (lib/paid-plans.ts): today,
 * Russia. Stripe does not take Russian cards and the launch promise is free
 * protection, so instead of dollar plan cards the page says what is included
 * and that it costs nothing (report #15).
 */
export default function FreePricing({ locale }: { locale: string }) {
  const t = useTranslations("Pricing");
  const items = t.raw("free_items") as string[];

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200">
      <PricingNav locale={locale} />

      <main className="max-w-3xl mx-auto px-6 pt-20 pb-24 text-center" data-testid="free-pricing">
        <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-6">
          {t("free_badge")}
        </span>
        <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">{t("free_title")}</h1>
        <p className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto mb-12">{t("free_subtitle")}</p>

        <section className="bg-slate-800/50 rounded-2xl p-8 text-start mb-10">
          <h2 className="text-2xl font-extrabold text-white mb-6">{t("free_list_title")}</h2>
          <ul className="space-y-4">
            {items.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <svg aria-hidden="true" focusable="false" className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span className="text-slate-300">{item}</span>
              </li>
            ))}
          </ul>
          <p className="text-slate-400 text-sm leading-relaxed mt-6">{t("free_note")}</p>
        </section>

        <a
          href={localePath(locale, "/android")}
          className="inline-block bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition"
        >
          {t("free_cta")}
        </a>
      </main>
    </div>
  );
}
