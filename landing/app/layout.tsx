// Root layout — minimal passthrough.
// The locale-aware <html> / <body> / NextIntlClientProvider wrapper lives in
// app/[locale]/layout.tsx so that `lang` and `dir` are set per-locale.
import "./globals.css";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
