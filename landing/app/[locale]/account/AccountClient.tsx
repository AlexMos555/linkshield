"use client";

import { useLocale, useTranslations } from "next-intl";
import { useCallback, useEffect, useMemo, useState, type CSSProperties } from "react";
import { createClient, type AccountDevice, type EntitlementResponse } from "@cleanway/api-client";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";
import { localePath } from "@/lib/locale-path";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

const KNOWN_PLANS = new Set(["free", "personal", "family", "business"]);
const KNOWN_SOURCES = new Set(["stripe", "google_play", "app_store", "rustore", "operator_ru", "promo", "partner"]);
const KNOWN_PLATFORMS = new Set(["android", "ios", "extension", "web"]);

type State =
  | { kind: "loading" }
  | { kind: "no_session" }
  | { kind: "locked" }
  | { kind: "error" }
  | { kind: "deleted" }
  | { kind: "ready"; email: string; ent: EntitlementResponse };

/**
 * Plan + devices for the signed-in account. The website itself is NOT a
 * device: visiting /account takes no seat, it only manages the phones and
 * browsers that signed in through the app or the extension.
 */
export default function AccountClient() {
  const t = useTranslations("Account");
  const locale = useLocale();
  const [state, setState] = useState<State>({ kind: "loading" });
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const api = useMemo(
    () =>
      createClient({
        baseUrl: API_BASE,
        getAuthToken: async () => {
          const { data } = await getSupabaseClient().auth.getSession();
          return data.session?.access_token ?? null;
        },
      }),
    [],
  );

  const fmt = useCallback(
    (iso?: string | null) => {
      if (!iso) return "";
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? "" : new Intl.DateTimeFormat(locale, { dateStyle: "medium" }).format(d);
    },
    [locale],
  );

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    // A build without Supabase keys has no sessions at all (local dev, CI).
    if (!isAuthConfigured()) {
      setState({ kind: "no_session" });
      return;
    }
    let email = "";
    try {
      const { data } = await getSupabaseClient().auth.getSession();
      if (!data.session) {
        setState({ kind: "no_session" });
        return;
      }
      email = data.session.user.email ?? "";
    } catch {
      setState({ kind: "error" });
      return;
    }
    let r = await api.account.entitlement();
    if (r.error?.kind === "unauthorized") {
      // Expired between getSession and the call: refresh once.
      await getSupabaseClient().auth.refreshSession().catch(() => null);
      r = await api.account.entitlement();
    }
    if (r.data) setState({ kind: "ready", email, ent: r.data });
    else if (r.error.kind === "unauthorized") setState({ kind: "no_session" });
    else if (r.error.kind === "account_locked") setState({ kind: "locked" });
    else setState({ kind: "error" });
  }, [api]);

  useEffect(() => {
    void load();
  }, [load]);

  async function unlink(device: AccountDevice, name: string) {
    if (!window.confirm(t("unlink_confirm", { name }))) return;
    setBusy(device.id);
    setNotice(null);
    const { data } = await api.account.unlinkDevice(device.id);
    setBusy(null);
    if (data && state.kind === "ready") setState({ ...state, ent: data });
    else setNotice(t("unlink_failed"));
  }

  async function signOut() {
    await getSupabaseClient().auth.signOut().catch(() => null);
    setState({ kind: "no_session" });
  }

  async function deleteAccount() {
    if (!window.confirm(t("delete_confirm"))) return;
    setBusy("delete");
    setNotice(null);
    const { error } = await api.user.deleteAccount();
    setBusy(null);
    if (error) {
      setNotice(t("delete_failed"));
      return;
    }
    await getSupabaseClient().auth.signOut().catch(() => null);
    setState({ kind: "deleted" });
  }

  if (state.kind === "loading") return <p style={muted} role="status">{t("loading")}</p>;

  if (state.kind === "no_session" || state.kind === "deleted") {
    return (
      <section style={card}>
        {state.kind === "deleted" ? (
          <p style={{ ...body, marginTop: 0 }} role="status">{t("delete_done")}</p>
        ) : (
          <>
            <h2 style={h2}>{t("no_session_title")}</h2>
            <p style={body}>{t("no_session_body")}</p>
          </>
        )}
        <a href={`${localePath(locale, "/signup")}?next=/account`} style={button}>{t("no_session_cta")}</a>
      </section>
    );
  }

  if (state.kind === "locked") {
    return (
      <section style={card}>
        <p style={{ ...body, marginTop: 0 }}>{t("locked_body")}</p>
        <a href={`${localePath(locale, "/account/restore")}?reason=locked`} style={button}>{t("locked_cta")}</a>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section style={card}>
        <p style={{ ...body, marginTop: 0 }} role="alert">{t("error_load")}</p>
        <button type="button" style={button} onClick={() => void load()}>{t("retry")}</button>
      </section>
    );
  }

  const { ent, email } = state;
  const paid = ent.plan !== "free";
  const planLabel = t(KNOWN_PLANS.has(ent.plan) ? `plan_${ent.plan}` : "plan_paid");
  const sourceLabel = ent.source ? t(KNOWN_SOURCES.has(ent.source) ? `source_${ent.source}` : "source_other") : null;
  const statusLabel =
    ent.status === "trialing"
      ? ent.period_end ? t("status_trial_until", { date: fmt(ent.period_end) }) : t("status_trial")
      : ent.status === "past_due"
        ? t("status_past_due")
        : ent.status === "active"
          ? ent.period_end ? t("status_paid_until", { date: fmt(ent.period_end) }) : t("status_active")
          : null;

  return (
    <div style={{ display: "grid", gap: 20 }}>
      <p style={muted}>{t("signed_in_as", { email })}</p>

      {notice && <p role="alert" style={{ ...body, color: "#fca5a5", margin: 0 }}>{notice}</p>}

      <section style={card} aria-labelledby="plan-h">
        <h2 id="plan-h" style={h2}>{t("plan_heading")}</h2>
        <p style={{ ...body, fontSize: 20, fontWeight: 700, color: "#f8fafc", margin: "4px 0" }}>{planLabel}</p>
        <p style={muted}>
          {[sourceLabel, statusLabel, paid ? null : t("free_desc")].filter(Boolean).join(" · ")}
        </p>
        {!paid && <a href={localePath(locale, "/pricing")} style={{ ...button, marginTop: 12 }}>{t("plans_cta")}</a>}
      </section>

      <section style={card} aria-labelledby="devices-h">
        <h2 id="devices-h" style={h2}>
          {t("devices_heading")} · {t("devices_count", { used: ent.devices_used, limit: ent.device_limit })}
        </h2>
        <p style={muted}>{t("devices_note")}</p>
        {ent.devices.length === 0 ? (
          <p style={body}>{t("devices_empty")}</p>
        ) : (
          <ul style={{ listStyle: "none", padding: 0, margin: "12px 0 0" }}>
            {ent.devices.map((d) => {
              const name = d.name || t(KNOWN_PLATFORMS.has(d.platform) ? `platform_${d.platform}` : "platform_web");
              return (
                <li key={d.id} style={row}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ ...body, margin: 0, fontWeight: 600, color: "#f8fafc", overflowWrap: "anywhere" }}>{name}</div>
                    {d.last_seen_at && <div style={muted}>{t("last_seen", { date: fmt(d.last_seen_at) })}</div>}
                  </div>
                  <button
                    type="button"
                    style={dangerButton}
                    disabled={busy !== null}
                    aria-label={`${t("unlink")} ${name}`}
                    onClick={() => void unlink(d, name)}
                  >
                    {busy === d.id ? t("unlinking") : t("unlink")}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section style={card} aria-labelledby="delete-h">
        <h2 id="delete-h" style={h2}>{t("delete_heading")}</h2>
        <p style={muted}>{t("delete_body")}</p>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 12 }}>
          <button type="button" style={dangerButton} disabled={busy !== null} onClick={() => void deleteAccount()}>
            {t("delete_cta")}
          </button>
          <button type="button" style={ghostButton} onClick={() => void signOut()}>{t("sign_out")}</button>
        </div>
      </section>
    </div>
  );
}

const card: CSSProperties = {
  background: "#111c33",
  border: "1px solid #1e293b",
  borderRadius: 16,
  padding: 20,
};
const h2: CSSProperties = { fontSize: 16, fontWeight: 700, color: "#cbd5e1", margin: 0 };
const body: CSSProperties = { fontSize: 16, lineHeight: 1.5, color: "#e2e8f0" };
const muted: CSSProperties = { fontSize: 14, lineHeight: 1.5, color: "#94a3b8", margin: "4px 0 0" };
const row: CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 12,
  padding: "12px 0",
  borderTop: "1px solid #1e293b",
};
const button: CSSProperties = {
  display: "inline-block",
  background: "#4c8dff",
  color: "#fff",
  border: "none",
  borderRadius: 10,
  padding: "12px 18px",
  minHeight: 44,
  fontSize: 15,
  fontWeight: 600,
  textDecoration: "none",
  cursor: "pointer",
};
const dangerButton: CSSProperties = {
  ...button,
  background: "transparent",
  color: "#f87171",
  border: "1px solid #f8717166",
  flexShrink: 0,
};
const ghostButton: CSSProperties = {
  ...button,
  background: "transparent",
  color: "#cbd5e1",
  border: "1px solid #334155",
};
