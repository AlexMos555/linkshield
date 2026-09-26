import { useTranslations } from "next-intl";

import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { localePath } from "@/lib/locale-path";

/** Top bar of /pricing — localized, with links that keep the reader's language. */
export default function PricingNav({ locale }: { locale: string }) {
  const nav = useTranslations("Nav");
  return (
    <nav className="sticky top-0 z-50 bg-[#0f172a]/95 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
        <a href={localePath(locale, "/")} className="text-xl font-extrabold text-white">Cleanway</a>
        <div className="hidden md:flex items-center gap-6">
          <a href={`${localePath(locale, "/")}#features`} className="text-sm text-slate-400 hover:text-white transition">{nav("features")}</a>
          <a href={localePath(locale, "/pricing")} className="text-sm text-white font-semibold">{nav("pricing")}</a>
          <a href={localePath(locale, "/support")} className="text-sm text-slate-400 hover:text-white transition">{nav("support")}</a>
          <PrimaryInstallLink androidLabel={nav("install_android")} className="bg-green-500 text-green-950 px-5 py-2 rounded-lg text-sm font-bold hover:bg-green-400 transition">
            {nav("install")}
          </PrimaryInstallLink>
        </div>
      </div>
    </nav>
  );
}
