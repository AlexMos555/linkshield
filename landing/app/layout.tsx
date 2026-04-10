import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LinkShield — Phishing Protection for Everyone",
  description:
    "Automatic phishing link detection with privacy audit. 91% detection rate, 9 threat intelligence sources, zero browsing data stored. $4.99/mo.",
  keywords: [
    "phishing protection",
    "link checker",
    "privacy audit",
    "anti-phishing",
    "browser extension",
    "safe browsing",
  ],
  openGraph: {
    title: "LinkShield — Phishing Protection for Everyone",
    description: "Your browsing data lives only on your device.",
    url: "https://linkshield.io",
    siteName: "LinkShield",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "LinkShield — Phishing Protection",
    description: "91% phishing detection. Zero data stored.",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}
