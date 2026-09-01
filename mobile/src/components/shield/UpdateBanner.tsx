/**
 * UpdateBanner — the one place a sideloaded user learns a newer build exists.
 *
 * Two honest shapes, driven by useUpdateCheck:
 *  - optional: a calm, dismissible card. "A newer version is available."
 *  - required: a prominent, NON-dismissible card in the danger palette. Shown
 *    when the running build is below the security floor. We do not hard-lock
 *    the app behind it — a lock is a trap if the download itself fails — but we
 *    make it impossible to miss and impossible to wave away.
 *
 * Tapping "Update" opens the download target (the signed APK URL, or the
 * /android page as a fallback) in the browser; we do not, and cannot, install
 * an APK for the user.
 */
import { View, Text, StyleSheet, TouchableOpacity, Linking } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import type { UpdateStatus } from "../../hooks/useUpdateCheck";

export function UpdateBanner({ status }: { status: UpdateStatus }) {
  const { t } = useTranslation();
  if (status.decision === "none") return null;

  const required = status.decision === "required";
  const accent = required ? colors.danger : colors.blue;
  const wash = required ? colors.dangerWash : colors.blueWash;
  const stroke = required ? colors.dangerStroke : colors.stroke;

  const open = () => {
    Linking.openURL(status.downloadUrl).catch(() => {});
  };

  return (
    <View style={[s.card, { backgroundColor: wash, borderColor: stroke }]}>
      <View style={s.row}>
        <Ionicons
          name={required ? "shield-half-outline" : "arrow-up-circle-outline"}
          size={20}
          color={accent}
        />
        <View style={s.textCol}>
          <Text style={s.title}>
            {t(required ? "mobile.update.required_title" : "mobile.update.optional_title")}
          </Text>
          <Text style={s.body}>
            {t(required ? "mobile.update.required_body" : "mobile.update.optional_body")}
          </Text>
          {!!status.releaseNotes && <Text style={s.notes}>{status.releaseNotes}</Text>}
        </View>
      </View>

      <View style={s.actions}>
        {!required && (
          <TouchableOpacity onPress={status.dismiss} activeOpacity={0.7} style={s.later}>
            <Text style={s.laterLabel}>{t("mobile.update.later")}</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity
          onPress={open}
          activeOpacity={0.85}
          style={[s.update, { backgroundColor: accent }]}
          accessibilityRole="button"
        >
          <Text style={s.updateLabel}>{t("mobile.update.action")}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  card: {
    marginTop: space.lg,
    padding: space.lg,
    borderRadius: radius.card,
    borderWidth: 1,
    gap: space.md,
  },
  row: { flexDirection: "row", gap: space.md, alignItems: "flex-start" },
  textCol: { flex: 1, gap: 2 },
  title: { ...typo.headline, color: colors.textPrimary },
  body: { ...typo.caption, color: colors.textSecondary },
  notes: { ...typo.caption, color: colors.textMuted, marginTop: space.xs },
  actions: { flexDirection: "row", justifyContent: "flex-end", gap: space.sm },
  later: { paddingVertical: space.sm, paddingHorizontal: space.md },
  laterLabel: { ...typo.body, color: colors.textSecondary, fontWeight: "600" },
  update: {
    paddingVertical: space.sm,
    paddingHorizontal: space.lg,
    borderRadius: radius.control,
  },
  updateLabel: { ...typo.body, color: colors.white, fontWeight: "700" },
});
