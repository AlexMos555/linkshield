import { getTranslations, setRequestLocale } from "next-intl/server";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";

interface HomeProps {
  params: Promise<{ locale: string }>;
}

interface FeatureItem {
  icon: string;
  title: string;
  desc: string;
}

interface HowItWorksStep {
  step: string;
  title: string;
  desc: string;
}

interface PricingTier {
  name: string;
  price: string;
  features: string[];
  cta: string;
}

interface TestimonialItem {
  q: string;
  n: string;
  r: string;
}

interface FaqItem {
  q: string;
  a: string;
}

export default async function Home({ params }: HomeProps) {
  const { locale } = await params;
  setRequestLocale(locale);
  const nav = await getTranslations("Nav");
  const hero = await getTranslations("Hero");
  const features = await getTranslations("Features");
  const how = await getTranslations("HowItWorks");
  const pricing = await getTranslations("PricingTeaser");
  const comparison = await getTranslations("Comparison");
  const privacy = await getTranslations("Privacy");
  const testimonials = await getTranslations("Testimonials");
  const faq = await getTranslations("FAQ");
  const cta = await getTranslations("FinalCta");
  const footer = await getTranslations("Footer");

  const featureItems = features.raw("items") as FeatureItem[];
  const howSteps = how.raw("steps") as HowItWorksStep[];
  const pricingFree = pricing.raw("free") as PricingTier;
  const pricingPersonal = pricing.raw("personal") as PricingTier;
  const pricingFamily = pricing.raw("family") as PricingTier;
  const comparisonHeaders = comparison.raw("headers") as string[];
  const comparisonRows = comparison.raw("rows") as string[][];
  const privacyServerItems = privacy.raw("server_items") as string[];
  const privacyDeviceItems = privacy.raw("device_items") as string[];
  const testimonialItems = testimonials.raw("items") as TestimonialItem[];
  const faqItems = faq.raw("items") as FaqItem[];

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200">
      {/* Nav */}
      <nav className="sticky top-0 z-50 bg-[#0f172a]/95 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <span className="text-xl font-extrabold text-white">Cleanway</span>
          <div className="hidden md:flex items-center gap-5">
            <a href="#features" className="text-sm text-slate-400 hover:text-white transition">{nav("features")}</a>
            <a href="/pricing" className="text-sm text-slate-400 hover:text-white transition">{nav("pricing")}</a>
            <a href="#privacy" className="text-sm text-slate-400 hover:text-white transition">{nav("privacy")}</a>
            <a href="/business" className="text-sm text-slate-400 hover:text-white transition">{nav("business")}</a>
            <LanguageSwitcher />
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-5 py-2 rounded-lg text-sm font-bold hover:bg-green-400 transition">
              {nav("install")}
            </a>
          </div>
          {/* Mobile menu button */}
          <div className="md:hidden flex items-center gap-2">
            <LanguageSwitcher />
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-4 py-2 rounded-lg text-sm font-bold">
              {nav("install_short")}
            </a>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-24 pb-16 px-6 text-center">
        <div className="max-w-3xl mx-auto animate-in">
          <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-8">
            {hero("badge")}
          </span>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">
            {hero("title_part1")}<br />
            <span className="gradient-text">{hero("title_part2")}</span>
          </h1>
          <p className="text-lg text-slate-400 mb-8 max-w-2xl mx-auto">{hero("subtitle")}</p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition glow-hover">
              {hero("cta_primary")}
            </a>
            <a href="#how" className="border border-slate-600 text-slate-300 px-8 py-4 rounded-xl text-lg font-semibold hover:border-slate-400 transition">
              {hero("cta_secondary")}
            </a>
          </div>
          <p className="text-xs text-slate-500 mt-6">{hero("cta_footer")}</p>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white text-center mb-14">{features("heading")}</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5 stagger">
            {featureItems.map((item) => (
              <div key={item.title} className="bg-slate-800/50 rounded-2xl p-6 hover:bg-slate-800 transition">
                <span className="text-3xl mb-3 block">{item.icon}</span>
                <h3 className="text-lg font-bold text-white mb-2">{item.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="py-20 px-6 bg-[#0b1120]">
        <h2 className="text-3xl font-extrabold text-white text-center mb-14">{how("heading")}</h2>
        <div className="flex flex-col md:flex-row justify-center gap-12 max-w-3xl mx-auto stagger">
          {howSteps.map((s) => (
            <div key={s.step} className="text-center flex-1">
              <div className="w-14 h-14 rounded-full bg-green-500/10 text-green-400 flex items-center justify-center text-xl font-extrabold mx-auto mb-4">{s.step}</div>
              <h3 className="text-lg font-bold text-white mb-2">{s.title}</h3>
              <p className="text-sm text-slate-400">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">{pricing("heading")}</h2>
          <div className="grid md:grid-cols-3 gap-5 items-start stagger">
            {/* Free */}
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-2">{pricingFree.name}</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">{pricingFree.price}</span><span className="text-sm text-slate-500">{pricing("unit_forever")}</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                {pricingFree.features.map((f) => <li key={f}>{f}</li>)}
              </ul>
              <a href="https://chrome.google.com/webstore" className="block text-center py-3 rounded-xl border border-slate-600 text-slate-300 font-semibold hover:border-slate-400 transition">{pricingFree.cta}</a>
            </div>
            {/* Personal */}
            <div className="bg-slate-800/50 rounded-2xl p-8 pricing-featured relative">
              <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-green-500 text-green-950 px-4 py-1 rounded-full text-xs font-bold">{pricing("most_popular")}</span>
              <h3 className="text-xl font-bold text-white mb-2">{pricingPersonal.name}</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">{pricingPersonal.price}</span><span className="text-sm text-slate-500">{pricing("unit_month")}</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                {pricingPersonal.features.map((f) => <li key={f}>{f}</li>)}
              </ul>
              <a href="/signup" className="block text-center py-3 rounded-xl bg-green-500 text-green-950 font-bold hover:bg-green-400 transition">{pricingPersonal.cta}</a>
            </div>
            {/* Family */}
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-2">{pricingFamily.name}</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">{pricingFamily.price}</span><span className="text-sm text-slate-500">{pricing("unit_month")}</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                {pricingFamily.features.map((f) => <li key={f}>{f}</li>)}
              </ul>
              <a href="/signup?plan=family" className="block text-center py-3 rounded-xl border border-slate-600 text-slate-300 font-semibold hover:border-slate-400 transition">{pricingFamily.cta}</a>
            </div>
          </div>
          <p className="text-sm text-slate-500 text-center mt-6">{pricing("trial_note")}</p>
        </div>
      </section>

      {/* Comparison */}
      <section className="py-20 px-6 bg-[#0b1120]">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">{comparison("heading")}</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b-2 border-slate-700">
                  {comparisonHeaders.map((h, i) => (
                    <th key={i} className={`py-3 px-3 text-left ${i === 1 ? "text-green-400 font-extrabold" : "text-slate-400 font-semibold"}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {comparisonRows.map((row, i) => (
                  <tr key={i} className="border-b border-slate-800 hover:bg-slate-800/30 transition">
                    {row.map((cell, j) => (
                      <td key={j} className={`py-3 px-3 ${j === 0 ? "font-semibold text-slate-300" : j === 1 ? "text-slate-200 bg-green-500/5" : "text-slate-400"}`}>{cell}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Privacy */}
      <section id="privacy" className="py-20 px-6">
        <div className="max-w-4xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">{privacy("heading")}</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-lg font-bold text-white mb-4">{privacy("server_heading")}</h3>
              <ul className="space-y-2 text-sm text-slate-400">
                {privacyServerItems.map((item) => <li key={item}>{item}</li>)}
              </ul>
              <p className="text-sm text-green-400 italic mt-4">{privacy("server_note")}</p>
            </div>
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-lg font-bold text-white mb-4">{privacy("device_heading")}</h3>
              <ul className="space-y-2 text-sm text-slate-400">
                {privacyDeviceItems.map((item) => <li key={item}>{item}</li>)}
              </ul>
              <p className="text-sm text-green-400 italic mt-4">{privacy("device_note")}</p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 px-6 bg-[#0b1120]">
        <h2 className="text-3xl font-extrabold text-white text-center mb-14">{testimonials("heading")}</h2>
        <div className="grid md:grid-cols-3 gap-5 max-w-5xl mx-auto stagger">
          {testimonialItems.map((t, i) => (
            <div key={i} className="bg-slate-800/50 rounded-2xl p-6">
              <p className="text-slate-200 text-[15px] leading-relaxed italic mb-4">{"\u201C"}{t.q}{"\u201D"}</p>
              <p className="text-sm font-semibold text-white">{t.n}</p>
              <p className="text-xs text-slate-500">{t.r}</p>
            </div>
          ))}
        </div>
      </section>

      {/* FAQ */}
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">{faq("heading")}</h2>
          {faqItems.map((item, i) => (
            <details key={i} className="bg-slate-800/50 rounded-xl px-6 py-4 mb-2 group">
              <summary className="text-[15px] font-semibold text-white cursor-pointer">{item.q}</summary>
              <p className="text-sm text-slate-400 leading-relaxed mt-3 pt-3 border-t border-slate-700">{item.a}</p>
            </details>
          ))}
        </div>
      </section>

      {/* Final CTA */}
      <section className="py-20 px-6 text-center">
        <h2 className="text-3xl font-extrabold text-white mb-4">{cta("title")}</h2>
        <p className="text-lg text-slate-400 mb-8">{cta("subtitle")}</p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition glow-hover">
            {cta("cta_primary")}
          </a>
          <a href="/business" className="border border-slate-600 text-slate-300 px-8 py-4 rounded-xl text-lg font-semibold hover:border-slate-400 transition">
            {cta("cta_business")}
          </a>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-10 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <p className="text-lg font-extrabold text-white mb-4">{footer("brand")}</p>
          <div className="flex justify-center gap-6 mb-4">
            <a href="/privacy-policy" className="text-sm text-slate-500 hover:text-slate-300 transition">{footer("privacy")}</a>
            <a href="/terms" className="text-sm text-slate-500 hover:text-slate-300 transition">{footer("terms")}</a>
            <a href="mailto:support@cleanway.ai" className="text-sm text-slate-500 hover:text-slate-300 transition">{footer("contact")}</a>
            <a href="https://github.com/AlexMos555/cleanway" className="text-sm text-slate-500 hover:text-slate-300 transition">{footer("github")}</a>
          </div>
          <p className="text-xs text-slate-600">&copy; 2026 Cleanway. {footer("tagline")}</p>
        </div>
      </footer>
    </div>
  );
}
