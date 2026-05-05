"use client";

// Landing destination for an invitee who scanned a QR / tapped a Cleanway
// invite link from their phone or a browser without the extension.
//
// The invite secret (code + 4-digit PIN) is in the URL hash (#code=…&pin=…).
// Hash params NEVER reach the server, so the secret stays client-side.
// All this page does:
//   1. Read the hash and surface code + PIN to the user.
//   2. Show install CTAs for whichever platform they're on.
//   3. Tell them how to paste this same URL back into Cleanway once installed.
//
// We deliberately do NOT round-trip the invite to our backend from this
// page — the extension/mobile app does that itself once installed. Keeping
// this page dumb means there's no way for it to leak the invite, and there's
// no auth required.

import { useEffect, useState } from "react";

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

export default function JoinClient() {
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
      <Frame>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 12 }}>
          Invite link looks incomplete
        </h1>
        <p style={{ color: "#94a3b8", lineHeight: 1.7, marginBottom: 24 }}>
          The link you opened doesn&apos;t carry an invite code. Ask the person who invited you
          to send you a new one — the link should look like{" "}
          <code style={{ background: "#1e293b", padding: "2px 6px", borderRadius: 4 }}>
            cleanway.ai/family/join#code=…&pin=…
          </code>
          .
        </p>
        <a
          href="/"
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
          Back to Cleanway
        </a>
      </Frame>
    );
  }

  // Hash hasn't been read yet (initial SSR render). Show a thin skeleton
  // so the page doesn't flash empty.
  if (!readyToRead || !invite) {
    return (
      <Frame>
        <div style={{ height: 200 }} />
      </Frame>
    );
  }

  return (
    <Frame>
      <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 12 }}>
        You&apos;ve been invited to a Cleanway family
      </h1>
      <p style={{ color: "#94a3b8", lineHeight: 1.7, marginBottom: 24 }}>
        Cleanway protects families from phishing and scam links. The person who invited you wants
        you in their private alert circle so you can warn each other when scams hit.
      </p>

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
        <div style={{ fontSize: 12, color: "#64748b", textTransform: "uppercase", marginBottom: 6 }}>
          Code
        </div>
        <div
          style={{
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            fontSize: 18,
            color: "#22c55e",
            fontWeight: 700,
            wordBreak: "break-all",
            marginBottom: 16,
          }}
        >
          {invite.code}
        </div>
        <div style={{ fontSize: 12, color: "#64748b", textTransform: "uppercase", marginBottom: 6 }}>
          PIN
        </div>
        <div
          style={{
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            fontSize: 28,
            color: "#22c55e",
            fontWeight: 700,
            letterSpacing: 8,
            textAlign: "center",
          }}
        >
          {invite.pin}
        </div>
      </div>

      <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f8fafc", marginBottom: 12 }}>
        How to join
      </h2>

      <ol
        style={{
          color: "#cbd5e1",
          lineHeight: 1.8,
          paddingLeft: 24,
          marginBottom: 24,
        }}
      >
        {platform === "ios" && (
          <>
            <li>
              Install the Cleanway app from the App Store. <em>(Coming soon)</em>
            </li>
            <li>Open Cleanway → Family → &quot;Join with code&quot;.</li>
            <li>Paste this link, or type the code + PIN above.</li>
          </>
        )}
        {platform === "android" && (
          <>
            <li>
              Install the Cleanway app from Google Play. <em>(Coming soon)</em>
            </li>
            <li>Open Cleanway → Family → &quot;Join with code&quot;.</li>
            <li>Paste this link, or type the code + PIN above.</li>
          </>
        )}
        {platform === "desktop" && (
          <>
            <li>
              Install the Cleanway browser extension (
              <a
                href="https://chrome.google.com/webstore/detail/cleanway"
                style={{ color: "#60a5fa" }}
              >
                Chrome
              </a>{" "}
              /{" "}
              <a
                href="https://addons.mozilla.org/firefox/addon/cleanway"
                style={{ color: "#60a5fa" }}
              >
                Firefox
              </a>
              ).
            </li>
            <li>Click the Cleanway icon → Settings → Family Hub.</li>
            <li>Click &quot;Join with code&quot; and paste this link, or type the code + PIN above.</li>
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
          marginRight: 8,
        }}
      >
        {copied ? "Copied ✓" : "Copy invite link"}
      </button>

      <p style={{ color: "#64748b", fontSize: 13, marginTop: 24, lineHeight: 1.6 }}>
        Privacy note: the code + PIN above are kept in the URL fragment (after the{" "}
        <code style={{ background: "#1e293b", padding: "1px 4px", borderRadius: 3 }}>#</code>) and
        never sent to Cleanway servers. Even our analytics see only{" "}
        <code style={{ background: "#1e293b", padding: "1px 4px", borderRadius: 3 }}>
          /family/join
        </code>{" "}
        without the secret. Invites expire 7 days after creation.
      </p>
    </Frame>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
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
            href="/"
            style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}
          >
            Cleanway
          </a>
        </div>
      </nav>
      <div style={{ maxWidth: 600, margin: "0 auto", padding: "60px 24px" }}>{children}</div>
    </div>
  );
}
