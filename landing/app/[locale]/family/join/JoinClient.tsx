"use client";

// Landing destination for an invitee who scanned a QR / tapped a Cleanway
// invite link from their phone or a browser without the extension.
//
// The invite secret (code + 4-digit PIN) is in the URL hash (#code=…&pin=…).
// Hash params NEVER reach the server, so the secret stays client-side.
// All this page does:
//   1. Read the hash and surface code + PIN to the user.
//   2. Say how to join on the platform they're on, in their language.
//   3. Offer to copy the link, to open it again on another device.
//
// We deliberately do NOT round-trip the invite to our backend from this
// page — the extension/mobile app does that itself once installed. Keeping
// this page dumb means there's no way for it to leak the invite, and there's
// no auth required.
//
// What each platform can do today (lib/install-urls.ts): Android has the app
// (/android — never "Google Play", which is blocked), whose Family Hub joins
// with the code and PIN typed in; the iPhone app and the browser extension
// are coming soon, so those visitors are pointed at an Android phone.

import { useEffect, useState } from "react";
import { useLocale, useTranslations } from "next-intl";

import { localePath } from "@/lib/locale-path";

type ParsedInvite = {
  code: string;
  pin: string;
};

function parseInviteHash(hash: string): ParsedInvite | null {
  const trimmed = hash.replace(/^#/, "");
  if (!trimmed) return null;
  const params = new URLSearchParams(trimmed);
  const code = params.get("code");
  const pin = params.get("pin");
  if (!code || !pin) return null;
  // Light shape validation: PIN is always 4 digits, code is short alnum.
  if (!/^\d{4}$/.test(pin)) return null;
  if (!/^[A-Za-z0-9_-]{4,}$/.test(code)) return null;
  return { code, pin };
}

type Platform = "ios" | "android" | "desktop";

function detectPlatform(): Platform {
  if (typeof navigator === "undefined") return "desktop";
  const ua = navigator.userAgent || "";
  if (/iPhone|iPad|iPod/.test(ua)) return "ios";
  if (/Android/.test(ua)) return "android";
  return "desktop";
}

const link: React.CSSProperties = { color: "#60a5fa", textDecoration: "underline" };
const label: React.CSSProperties = { fontSize: 12, color: "#8796ab", textTransform: "uppercase", marginBottom: 6 };
const mono = "ui-monospace, SFMono-Regular, Menlo, monospace";

export default function JoinClient() {
  const t = useTranslations("FamilyJoin");
  const locale = useLocale();
  const [invite, setInvite] = useState<ParsedInvite | null>(null);
  const [platform, setPlatform] = useState<Platform>("desktop");
  const [readyToRead, setReadyToRead] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setInvite(parseInviteHash(window.location.hash));
    setPlatform(detectPlatform());
    setReadyToRead(true);
  }, []);

  const fullUrl = readyToRead && typeof window !== "undefined" ? window.location.href : "";

  async function copyUrl() {
    if (!fullUrl) return;
    try {
      await navigator.clipboard.writeText(fullUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard blocked
    }
  }

  // No invite in URL → bad/old/manual link. Tell them what to do.
  if (readyToRead && !invite) {
    return (
      <Frame home={localePath(locale, "/")}>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 12 }}>
          {t("incomplete_title")}
        </h1>
        <p style={{ color: "#94a3b8", lineHeight: 1.7, marginBottom: 24 }}>
          {t("incomplete_body")}{" "}
          <code dir="ltr" style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4 }}>
            cleanway.ai/family/join#code=…&pin=…
          </code>
        </p>
        <a
          href={localePath(locale, "/")}
          style={{
            display: "inline-block",
            background: "#22c55e",
            color: "#0f172a",
            padding: "12px 24px",
            borderRadius: 8,
            textDecoration: "none",
            fontWeight: 700,
          }}
        >
          {t("back_home")}
        </a>
      </Frame>
    );
  }

  // Hash hasn't been read yet (initial SSR render). Show a thin skeleton
  // so the page doesn't flash empty.
  if (!readyToRead || !invite) {
    return (
      <Frame home={localePath(locale, "/")}>
        <div style={{ height: 200 }} />
      </Frame>
    );
  }

  const androidPage = localePath(locale, "/android");

  return (
    <Frame home={localePath(locale, "/")}>
      <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 12 }}>
        {t("title")}
      </h1>
      <p style={{ color: "#94a3b8", lineHeight: 1.7, marginBottom: 24 }}>{t("intro")}</p>

      {/* Show the parsed code + PIN — nothing leaves this device. */}
      <div
        style={{
          background: "#0f172a",
          border: "1px solid #22c55e40",
          borderRadius: 12,
          padding: 20,
          marginBottom: 24,
        }}
      >
        <div style={label}>{t("code_label")}</div>
        <div
          dir="ltr"
          data-testid="family-join-code"
          style={{ fontFamily: mono, fontSize: 18, color: "#22c55e", fontWeight: 700, wordBreak: "break-all", marginBottom: 16 }}
        >
          {invite.code}
        </div>
        <div style={label}>{t("pin_label")}</div>
        <div
          dir="ltr"
          style={{ fontFamily: mono, fontSize: 28, color: "#22c55e", fontWeight: 700, letterSpacing: 8, textAlign: "center" }}
        >
          {invite.pin}
        </div>
      </div>

      <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f8fafc", marginBottom: 12 }}>{t("how_title")}</h2>

      <ol
        data-testid={`family-join-steps-${platform}`}
        style={{ color: "#cbd5e1", lineHeight: 1.8, paddingInlineStart: 24, marginBottom: 24 }}
      >
        {platform === "android" && (
          <>
            <li>
              {t("android_step1")} <a href={androidPage} style={link}>{t("android_link")}</a>
            </li>
            <li>{t("app_step2")}</li>
            <li>{t("app_step3")}</li>
          </>
        )}
        {platform === "ios" && <li>{t("ios_soon")}</li>}
        {platform === "desktop" && (
          <>
            <li>{t("desktop_soon")}</li>
            <li>
              {t("desktop_phone")} <a href={androidPage} style={link}>{t("android_link")}</a>
            </li>
          </>
        )}
      </ol>

      <button
        onClick={copyUrl}
        style={{
          background: "#1e293b",
          color: "#f8fafc",
          border: "1px solid #334155",
          padding: "12px 20px",
          borderRadius: 8,
          fontSize: 14,
          fontWeight: 600,
          cursor: "pointer",
        }}
      >
        {copied ? t("copied") : t("copy_link")}
      </button>

      <p style={{ color: "#8796ab", fontSize: 13, marginTop: 24, lineHeight: 1.6 }}>{t("privacy_note")}</p>
    </Frame>
  );
}

function Frame({ children, home }: { children: React.ReactNode; home: string }) {
  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        fontFamily:
          '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        minHeight: "100vh",
      }}
    >
      <nav
        style={{
          background: "#0f172af0",
          borderBottom: "1px solid #1e293b",
          padding: "14px 24px",
        }}
      >
        <div
          style={{
            maxWidth: 800,
            margin: "0 auto",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <a
            href={home}
            style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}
          >
            Cleanway
          </a>
        </div>
      </nav>
      <main style={{ maxWidth: 600, margin: "0 auto", padding: "60px 24px" }}>{children}</main>
    </div>
  );
}
