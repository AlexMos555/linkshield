export default function Home() {
  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200">
      {/* Nav */}
      <nav className="sticky top-0 z-50 bg-[#0f172a]/95 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <span className="text-xl font-extrabold text-white">LinkShield</span>
          <div className="hidden md:flex items-center gap-6">
            <a href="#features" className="text-sm text-slate-400 hover:text-white transition">Features</a>
            <a href="#pricing" className="text-sm text-slate-400 hover:text-white transition">Pricing</a>
            <a href="#privacy" className="text-sm text-slate-400 hover:text-white transition">Privacy</a>
            <a href="/business" className="text-sm text-slate-400 hover:text-white transition">Business</a>
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-5 py-2 rounded-lg text-sm font-bold hover:bg-green-400 transition">
              Add to Chrome
            </a>
          </div>
          {/* Mobile menu button */}
          <a href="https://chrome.google.com/webstore" className="md:hidden bg-green-500 text-green-950 px-4 py-2 rounded-lg text-sm font-bold">
            Install
          </a>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-24 pb-16 px-6 text-center">
        <div className="max-w-3xl mx-auto animate-in">
          <span className="inline-block bg-green-500/10 text-green-400 border border-green-500/30 px-4 py-1.5 rounded-full text-sm font-semibold mb-8">
            91% phishing detection rate
          </span>
          <h1 className="text-4xl md:text-6xl font-extrabold text-white leading-tight mb-6">
            Phishing protection that<br />
            <span className="gradient-text">respects your privacy</span>
          </h1>
          <p className="text-lg md:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto mb-10">
            Automatic link scanning across every page. 9 threat intelligence sources.
            ML&#8209;powered detection. Your browsing data never leaves your device.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-4">
            <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition glow-hover">
              Add to Chrome — Free
            </a>
            <a href="#how" className="border border-slate-600 text-slate-300 px-8 py-4 rounded-xl text-lg font-semibold hover:border-slate-400 transition">
              How it works
            </a>
          </div>
          <p className="text-sm text-slate-500">Free forever for basic protection. No credit card required.</p>
        </div>
      </section>

      {/* Stats bar */}
      <section className="border-y border-slate-800 py-8 px-6">
        <div className="max-w-4xl mx-auto flex flex-wrap justify-around gap-6 stagger">
          {[
            ["9", "Threat sources"], ["42+", "Detection signals"],
            ["100K", "Safe domains"], ["0", "Data stored"],
          ].map(([num, label]) => (
            <div key={label} className="text-center">
              <div className="text-3xl font-extrabold text-green-400">{num}</div>
              <div className="text-xs text-slate-500">{label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl md:text-4xl font-extrabold text-white text-center mb-14">Everything you need. Nothing you don{"'"}t.</h2>
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5 stagger">
            {[
              ["\uD83D\uDD0D", "Automatic Link Scanning", "Every link on every page checked against 9 threat databases. Red, yellow, green badges show safety at a glance."],
              ["\uD83D\uDD12", "Privacy Audit", "Right-click any page to see trackers, cookies, data collection, and fingerprinting. Grade A through F."],
              ["\uD83E\uDDE0", "ML-Powered Detection", "CatBoost model trained on 18K+ domains. 0.9988 AUC. Catches novel phishing that rule-based systems miss."],
              ["\u26A1", "Instant Protection", "95% of checks happen locally via bloom filter in under 1ms. No slowdown. No waiting."],
              ["\uD83D\uDCF1", "Your Data, Your Device", "Browsing history never touches our servers. We only see domain names. Even if breached, your data is safe."],
              ["\uD83D\uDCE7", "Inbox Scanner", "Finds phishing links in your Gmail and Outlook that your browser missed."],
            ].map(([icon, title, desc]) => (
              <div key={title} className="bg-slate-800/50 rounded-2xl p-6 hover:bg-slate-800 transition">
                <span className="text-3xl mb-3 block">{icon}</span>
                <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="py-20 px-6 bg-[#0b1120]">
        <h2 className="text-3xl font-extrabold text-white text-center mb-14">How LinkShield protects you</h2>
        <div className="flex flex-col md:flex-row justify-center gap-12 max-w-3xl mx-auto stagger">
          {[
            ["1", "Install", "Add the Chrome extension. Takes 10 seconds."],
            ["2", "Browse", "LinkShield checks every link automatically. No action needed."],
            ["3", "Stay Safe", "Dangerous links get red badges. Click for details."],
          ].map(([step, title, desc]) => (
            <div key={step} className="text-center flex-1">
              <div className="w-14 h-14 rounded-full bg-green-500/10 text-green-400 flex items-center justify-center text-xl font-extrabold mx-auto mb-4">{step}</div>
              <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
              <p className="text-sm text-slate-400">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">Simple, transparent pricing</h2>
          <div className="grid md:grid-cols-3 gap-5 items-start stagger">
            {/* Free */}
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-2">Free</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">$0</span><span className="text-sm text-slate-500">/forever</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                <li>10 API checks/day</li>
                <li>Unlimited local checks</li>
                <li>Privacy Audit (grade only)</li>
                <li>Link badges on all pages</li>
              </ul>
              <a href="https://chrome.google.com/webstore" className="block text-center py-3 rounded-xl border border-slate-600 text-slate-300 font-semibold hover:border-slate-400 transition">Get Started</a>
            </div>
            {/* Personal */}
            <div className="bg-slate-800/50 rounded-2xl p-8 pricing-featured relative">
              <span className="absolute -top-3 left-1/2 -translate-x-1/2 bg-green-500 text-green-950 px-4 py-1 rounded-full text-xs font-bold">Most Popular</span>
              <h3 className="text-xl font-bold text-white mb-2">Personal</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">$4.99</span><span className="text-sm text-slate-500">/month</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                <li>Unlimited checks</li>
                <li>Full Privacy Audit breakdown</li>
                <li>Weekly Security Report</li>
                <li>Security Score + tips</li>
                <li>Priority support</li>
              </ul>
              <a href="/signup" className="block text-center py-3 rounded-xl bg-green-500 text-green-950 font-bold hover:bg-green-400 transition">Start Free Trial</a>
            </div>
            {/* Family */}
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-2">Family</h3>
              <div className="mb-6"><span className="text-4xl font-extrabold text-white">$9.99</span><span className="text-sm text-slate-500">/month</span></div>
              <ul className="space-y-2 text-sm text-slate-400 mb-8">
                <li>Everything in Personal</li>
                <li>Up to 6 devices</li>
                <li>Family Hub with E2E alerts</li>
                <li>Parental mode</li>
              </ul>
              <a href="/signup?plan=family" className="block text-center py-3 rounded-xl border border-slate-600 text-slate-300 font-semibold hover:border-slate-400 transition">Start Free Trial</a>
            </div>
          </div>
          <p className="text-sm text-slate-500 text-center mt-6">All plans include 14-day free trial. Cancel anytime.</p>
        </div>
      </section>

      {/* Comparison */}
      <section className="py-20 px-6 bg-[#0b1120]">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">How we compare</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b-2 border-slate-700">
                  {["Feature", "LinkShield", "Guardio", "NordVPN TP", "Norton 360", "Free Extensions"].map((h, i) => (
                    <th key={i} className={`py-3 px-3 text-left ${i === 1 ? "text-green-400 font-extrabold" : "text-slate-400 font-semibold"}`}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  ["Price", "$4.99/mo", "$9.99/mo", "~$5/mo (w/ VPN)", "$40-100/yr", "Free"],
                  ["Platforms", "All 5", "Chrome only", "Win/Mac", "All", "Browser only"],
                  ["Privacy Audit", "\u2705", "\u274C", "\u274C", "\u274C", "\u274C"],
                  ["On-device data", "\u2705", "\u274C", "\u274C", "\u274C", "\u274C"],
                  ["ML detection", "\u2705", "\u2705", "\u2705", "\u2705", "\u274C"],
                  ["Breach monitoring", "\u2705", "\u274C", "\u274C", "\u2705", "\u274C"],
                  ["Family Hub", "\u2705 (E2E)", "\u274C", "\u274C", "\u2705", "\u274C"],
                  ["B2B Phishing sim", "\u2705", "\u274C", "\u274C", "\u274C", "\u274C"],
                ].map((row, i) => (
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
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">Privacy is not a feature. It{"'"}s the architecture.</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-lg font-bold text-white mb-4">What our server knows</h3>
              <ul className="space-y-2 text-sm text-slate-400">
                <li>Your email address</li>
                <li>Subscription status</li>
                <li>Weekly aggregate numbers</li>
              </ul>
              <p className="text-sm text-green-400 italic mt-4">If breached: attacker gets emails + subscription. Boring.</p>
            </div>
            <div className="bg-slate-800/50 rounded-2xl p-8">
              <h3 className="text-lg font-bold text-white mb-4">What stays on your device</h3>
              <ul className="space-y-2 text-sm text-slate-400">
                <li>Full URL check history</li>
                <li>Privacy Audit results</li>
                <li>Security Score breakdown</li>
                <li>Weekly Report details</li>
                <li>Family alert content (E2E encrypted)</li>
              </ul>
              <p className="text-sm text-green-400 italic mt-4">If device is lost: protected by OS encryption.</p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials */}
      <section className="py-20 px-6 bg-[#0b1120]">
        <h2 className="text-3xl font-extrabold text-white text-center mb-14">What users say</h2>
        <div className="grid md:grid-cols-3 gap-5 max-w-5xl mx-auto stagger">
          {[
            { q: "Finally, a security tool that doesn\u2019t spy on me. The Privacy Audit is eye-opening.", n: "Alex K.", r: "Software Engineer" },
            { q: "Caught 3 phishing links in my Gmail that Chrome missed. Worth every penny.", n: "Maria S.", r: "Marketing Manager" },
            { q: "We replaced KnowBe4 with LinkShield Business. Same protection, 1/4 the price.", n: "James T.", r: "IT Director" },
          ].map((t, i) => (
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
          <h2 className="text-3xl font-extrabold text-white text-center mb-14">FAQ</h2>
          {[
            ["How is my data protected?", "Your browsing history never leaves your device. Our servers store only your email and subscription status. Even if we\u2019re breached, attackers learn nothing about your online activity."],
            ["Does it slow down browsing?", "No. 95% of checks happen locally via bloom filter in under 1ms. Only unknown domains are sent to our API (domain name only, never full URLs)."],
            ["Can I use it with a VPN?", "Yes! On mobile, LinkShield auto-detects your VPN and switches to DNS mode, working alongside NordVPN, ExpressVPN, or any other provider."],
            ["What\u2019s different from Google Safe Browsing?", "Google Safe Browsing is reactive \u2014 it catches known threats but misses new phishing. LinkShield adds ML detection, 8 additional threat sources, Privacy Audit, and doesn\u2019t send your browsing data to Google."],
            ["Is there a free plan?", "Yes! The free plan includes 10 API checks/day, unlimited local bloom filter checks, and basic Privacy Audit. Most casual users never need to upgrade."],
            ["How does phishing simulation work?", "Business plan includes simulated phishing emails sent to your team. Pick a template, we send test emails, track who clicks vs. who reports. For training, not punishment."],
          ].map(([q, a], i) => (
            <details key={i} className="bg-slate-800/50 rounded-xl px-6 py-4 mb-2 group">
              <summary className="text-[15px] font-semibold text-white cursor-pointer">{q}</summary>
              <p className="text-sm text-slate-400 leading-relaxed mt-3 pt-3 border-t border-slate-700">{a}</p>
            </details>
          ))}
        </div>
      </section>

      {/* Final CTA */}
      <section className="py-20 px-6 text-center">
        <h2 className="text-3xl font-extrabold text-white mb-4">Ready to browse safely?</h2>
        <p className="text-lg text-slate-400 mb-8">Join thousands of users who browse without worry.</p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <a href="https://chrome.google.com/webstore" className="bg-green-500 text-green-950 px-8 py-4 rounded-xl text-lg font-bold hover:bg-green-400 transition glow-hover">
            Add to Chrome — Free
          </a>
          <a href="/business" className="border border-slate-600 text-slate-300 px-8 py-4 rounded-xl text-lg font-semibold hover:border-slate-400 transition">
            For Business Teams
          </a>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800 py-10 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <p className="text-lg font-extrabold text-white mb-4">LinkShield</p>
          <div className="flex justify-center gap-6 mb-4">
            {[
              ["/privacy-policy", "Privacy"], ["/terms", "Terms"],
              ["mailto:support@linkshield.io", "Contact"], ["https://github.com/AlexMos555/linkshield", "GitHub"],
            ].map(([href, label]) => (
              <a key={label} href={href} className="text-sm text-slate-500 hover:text-slate-300 transition">{label}</a>
            ))}
          </div>
          <p className="text-xs text-slate-600">&copy; 2026 LinkShield. Your data, your device.</p>
        </div>
      </footer>
    </div>
  );
}
