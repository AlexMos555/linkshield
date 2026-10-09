import { ActivityIndicator, Linking, Modal, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import { iosDnsSheet, type IosDnsStepState } from "../../utils/ios-dns";
import type { IosDnsProtection } from "../../hooks/useIosDnsProtection";

/**
 * Setting up the iPhone's DNS protection (src/utils/ios-dns.ts, docs/IOS.md §4).
 *
 * What it sends and where comes FIRST, before any button: on iPhone the
 * matching happens on Cleanway's server, not on the phone as on Android, and
 * a person must know that before adding it. Then the two steps iOS imposes —
 * the app saves the setting, the person picks it in Settings — each with its
 * live state, read from iOS again whenever the person comes back.
 */
export function IosDnsSetupSheet({ visible, dns, onClose }: {
  visible: boolean;
  dns: IosDnsProtection;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const sheet = iosDnsSheet(dns.state);
  const on = dns.phase === "on";

  function onPrimary() {
    if (!sheet.primary || sheet.primary.busy) return;
    if (sheet.primary.action === "install") void dns.install();
    // iOS has no public link to the DNS page; this opens Settings (at
    // Cleanway's own page) and the step says where to go from there.
    else void Linking.openSettings();
  }

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View style={s.scrim}>
        <View style={s.sheet} accessibilityViewIsModal>
          <ScrollView contentContainerStyle={s.content} bounces={false}>
            <View style={s.titleRow}>
              <Text style={s.title} accessibilityRole="header">{t("mobile.ios.dns.title")}</Text>
              <TouchableOpacity
                onPress={onClose}
                style={s.close}
                accessibilityRole="button"
                accessibilityLabel={t("mobile.ios.dns.done")}
                hitSlop={8}
              >
                <Ionicons name="close" size={22} color={colors.textSecondary} />
              </TouchableOpacity>
            </View>

            <View style={s.privacy}>
              <Text style={s.privacyTitle}>{t("mobile.ios.dns.privacy_title")}</Text>
              <Text style={s.privacyBody}>{t("mobile.ios.dns.privacy_body")}</Text>
            </View>

            <Step
              n={1}
              state={sheet.steps.add}
              title={t("mobile.ios.dns.step_add_title")}
              body={t("mobile.ios.dns.step_add_body")}
              doneLabel={t("mobile.ios.dns.step_done")}
            />
            <Step
              n={2}
              state={sheet.steps.turnOn}
              title={t("mobile.ios.dns.step_on_title")}
              body={t("mobile.ios.dns.step_on_body")}
              doneLabel={t("mobile.ios.dns.step_done")}
            />

            <View style={[s.status, on && s.statusOn]} accessibilityLiveRegion="polite">
              <Ionicons
                name={on ? "checkmark-circle" : "information-circle-outline"}
                size={20}
                color={on ? colors.green : colors.textSecondary}
              />
              <Text style={[s.statusText, on && s.statusTextOn]}>{t(sheet.statusKey)}</Text>
            </View>
            {sheet.errorKey && (
              <Text style={s.error} accessibilityRole="alert">{t(sheet.errorKey)}</Text>
            )}

            {sheet.primary ? (
              <TouchableOpacity
                style={[s.primaryBtn, sheet.primary.busy && s.primaryBusy]}
                onPress={onPrimary}
                disabled={sheet.primary.busy}
                activeOpacity={0.85}
                accessibilityRole="button"
                accessibilityState={{ disabled: sheet.primary.busy, busy: sheet.primary.busy }}
              >
                {sheet.primary.busy && <ActivityIndicator color="#FFFFFF" style={s.spinner} />}
                <Text style={s.primaryLabel}>{t(sheet.primary.labelKey)}</Text>
              </TouchableOpacity>
            ) : (
              <TouchableOpacity style={s.primaryBtn} onPress={onClose} activeOpacity={0.85} accessibilityRole="button">
                <Text style={s.primaryLabel}>{t("mobile.ios.dns.done")}</Text>
              </TouchableOpacity>
            )}

            {/* "…or remove Cleanway below" — only once there is something to remove. */}
            {(sheet.removable || sheet.removing) && <Text style={s.note}>{t("mobile.ios.dns.note_off")}</Text>}
            <Text style={s.note}>{t("mobile.ios.dns.note_vpn")}</Text>

            {(sheet.removable || sheet.removing) && (
              <TouchableOpacity
                style={s.textBtn}
                onPress={() => void dns.remove()}
                disabled={sheet.removing}
                activeOpacity={0.7}
                accessibilityRole="button"
              >
                <Text style={s.removeLabel}>
                  {t(sheet.removing ? "mobile.ios.dns.removing" : "mobile.ios.dns.remove")}
                </Text>
              </TouchableOpacity>
            )}
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

function Step({ n, state, title, body, doneLabel }: {
  n: number;
  state: IosDnsStepState;
  title: string;
  body: string;
  doneLabel: string;
}) {
  const done = state === "done";
  return (
    <View style={s.step} accessibilityLabel={done ? `${title}. ${doneLabel}` : undefined}>
      <View style={[s.badge, done && s.badgeDone, state === "current" && s.badgeCurrent]}>
        {done ? (
          <Ionicons name="checkmark" size={16} color={colors.bg} />
        ) : (
          <Text style={[s.badgeLabel, state === "current" && s.badgeLabelCurrent]}>{n}</Text>
        )}
      </View>
      <View style={s.stepText}>
        <Text style={[s.stepTitle, state === "todo" && s.stepTitleTodo]}>{title}</Text>
        <Text style={s.stepBody}>{body}</Text>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    maxHeight: "92%",
  },
  content: { padding: space.xxl, paddingBottom: space.huge },
  titleRow: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  title: { ...typo.title2, color: colors.textPrimary, flex: 1 },
  close: { minWidth: 44, minHeight: 44, alignItems: "flex-end", justifyContent: "center" },
  privacy: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control, padding: space.md, marginTop: space.md,
  },
  privacyTitle: { ...typo.headline, color: colors.textPrimary },
  privacyBody: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  step: { flexDirection: "row", gap: space.md, marginTop: space.xl },
  badge: {
    width: 28, height: 28, borderRadius: 14, borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center",
  },
  badgeCurrent: { borderColor: colors.blue },
  badgeDone: { backgroundColor: colors.green, borderColor: colors.green },
  badgeLabel: { fontSize: 14, fontWeight: "600", color: colors.textMuted },
  badgeLabelCurrent: { color: colors.blue },
  stepText: { flex: 1 },
  stepTitle: { ...typo.headline, color: colors.textPrimary },
  stepTitleTodo: { color: colors.textSecondary },
  stepBody: { ...typo.body, color: colors.textSecondary, marginTop: 2 },
  status: {
    flexDirection: "row", alignItems: "flex-start", gap: space.sm,
    borderRadius: radius.control, padding: space.md, marginTop: space.xl,
    backgroundColor: colors.surface,
  },
  statusOn: { backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke },
  statusText: { ...typo.body, color: colors.textSecondary, flex: 1 },
  statusTextOn: { color: colors.green, fontWeight: "600" },
  error: { ...typo.body, color: colors.danger, marginTop: space.sm },
  primaryBtn: {
    minHeight: 54, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.lg, flexDirection: "row",
  },
  primaryBusy: { opacity: 0.7 },
  spinner: { marginRight: space.sm },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  note: { ...typo.caption, color: colors.textMuted, marginTop: space.md },
  textBtn: { alignSelf: "center", minHeight: 44, justifyContent: "center", paddingHorizontal: space.md, marginTop: space.sm },
  removeLabel: { ...typo.body, color: colors.danger },
});
