/**
 * Soft-delete grace-period restore overlay.
 *
 * Listens on accountLockedEvents (api.ts) — fires the moment any API
 * call returns 410 Gone. When that happens we mount a modal that
 * lets the user one-tap restore their account before the 30-day
 * window expires. On success the flag clears and the modal dismisses.
 *
 * If the user dismisses the modal explicitly we don't show it again
 * for the rest of the app session — re-firing on every subsequent
 * call would be a nag. The 410 still propagates as an ApiError to
 * the caller, so screens can still surface a non-modal hint.
 *
 * Backend contract: api/routers/user.py::restore_account.
 * Sibling UI in landing/app/[locale]/account/restore/RestoreClient.tsx.
 */
import { useEffect, useState } from "react";
import { Modal, Pressable, StyleSheet, Text, View } from "react-native";
import { useTranslation } from "react-i18next";

import { accountLockedEvents, restoreAccount } from "../services/api";

type RestoreState = "idle" | "restoring" | "restored" | "error";

export function AccountLockedModal(): JSX.Element | null {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);
  const [state, setState] = useState<RestoreState>("idle");
  const [dismissedThisSession, setDismissedThisSession] = useState(false);

  useEffect(() => {
    function handleLocked() {
      if (dismissedThisSession) return;
      setState("idle");
      setVisible(true);
    }
    function handleRestored() {
      setVisible(false);
      setState("idle");
    }
    accountLockedEvents.on("locked", handleLocked);
    accountLockedEvents.on("restored", handleRestored);
    return () => {
      accountLockedEvents.off("locked", handleLocked);
      accountLockedEvents.off("restored", handleRestored);
    };
  }, [dismissedThisSession]);

  async function handleRestore() {
    setState("restoring");
    const ok = await restoreAccount();
    setState(ok ? "restored" : "error");
    if (ok) {
      // Brief success flash, then close.
      setTimeout(() => setVisible(false), 1200);
    }
  }

  function handleDismiss() {
    setDismissedThisSession(true);
    setVisible(false);
  }

  if (!visible) return null;

  return (
    <Modal
      transparent
      animationType="fade"
      visible={visible}
      onRequestClose={handleDismiss}
    >
      <View style={styles.backdrop}>
        <View style={styles.card}>
          <Text style={styles.icon} accessibilityElementsHidden>
            ⏳
          </Text>
          <Text style={styles.title}>
            {state === "restored"
              ? t("extension.popup.locked_restoring")
              : t("extension.popup.locked_title")}
          </Text>
          <Text style={styles.body}>{t("extension.popup.locked_body")}</Text>

          {state === "error" && (
            <Text style={styles.error}>
              {t("extension.popup.locked_error_generic")}
            </Text>
          )}

          <Pressable
            style={[
              styles.primaryBtn,
              state === "restoring" && styles.primaryBtnDisabled,
            ]}
            onPress={handleRestore}
            disabled={state === "restoring" || state === "restored"}
            accessibilityRole="button"
            accessibilityLabel={t("extension.popup.locked_restore_cta")}
          >
            <Text style={styles.primaryBtnText}>
              {state === "restoring"
                ? t("extension.popup.locked_restoring")
                : t("extension.popup.locked_restore_cta")}
            </Text>
          </Pressable>

          <Pressable
            style={styles.secondaryBtn}
            onPress={handleDismiss}
            accessibilityRole="button"
          >
            <Text style={styles.secondaryBtnText}>
              {/* Dismiss is a session-only opt-out — no localized key
                  needed (intentionally low-friction; the modal will
                  return on next cold boot if still locked). */}
              Dismiss
            </Text>
          </Pressable>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    backgroundColor: "rgba(15,23,42,0.85)",
    justifyContent: "center",
    paddingHorizontal: 20,
  },
  card: {
    backgroundColor: "#1e293b",
    borderRadius: 20,
    padding: 24,
    borderWidth: 1,
    borderColor: "#334155",
  },
  icon: {
    fontSize: 48,
    textAlign: "center",
    marginBottom: 12,
  },
  title: {
    color: "#f8fafc",
    fontSize: 20,
    fontWeight: "800",
    textAlign: "center",
    marginBottom: 8,
  },
  body: {
    color: "#94a3b8",
    fontSize: 14,
    lineHeight: 20,
    textAlign: "left",
    marginBottom: 18,
  },
  error: {
    color: "#fecaca",
    fontSize: 13,
    marginBottom: 12,
    padding: 10,
    backgroundColor: "rgba(239,68,68,0.1)",
    borderRadius: 6,
    borderWidth: 1,
    borderColor: "#ef4444",
  },
  primaryBtn: {
    backgroundColor: "#22c55e",
    paddingVertical: 14,
    borderRadius: 10,
    marginBottom: 10,
  },
  primaryBtnDisabled: {
    backgroundColor: "#16a34a",
    opacity: 0.85,
  },
  primaryBtnText: {
    color: "#052e16",
    fontWeight: "800",
    fontSize: 15,
    textAlign: "center",
  },
  secondaryBtn: {
    paddingVertical: 12,
  },
  secondaryBtnText: {
    color: "#94a3b8",
    fontSize: 13,
    textAlign: "center",
  },
});
