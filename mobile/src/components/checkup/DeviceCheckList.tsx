import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius, sectionHeader } from "../../utils/theme";
import { fixCount, type DeviceCheck, type DeviceCheckStatus, type FixAction } from "../../utils/checkup";

// Status is never colour-only: each row pairs its hue with an icon and a sentence.
const LOOKS: Record<DeviceCheckStatus, { icon: keyof typeof Ionicons.glyphMap; color: string }> = {
  ok: { icon: "checkmark-circle", color: colors.green },
  fix: { icon: "alert-circle", color: colors.amber },
  wait: { icon: "time-outline", color: colors.textMuted },
};

interface Props {
  rows: DeviceCheck[];
  onFix: (action: FixAction) => void;
}

/**
 * Part 1 of "Проверка защиты": one sentence per thing the phone read about
 * itself, and "Исправить" beside each one that is wrong. The summary counts
 * problems; while a row is still being checked it claims nothing.
 */
export function DeviceCheckList({ rows, onFix }: Props) {
  const { t } = useTranslation();
  const toFix = fixCount(rows);
  const settled = rows.every((r) => r.status !== "wait");
  return (
    <View>
      <Text style={s.sectionTitle}>{t("mobile.checkup.device.title")}</Text>
      {(toFix > 0 || settled) && (
        <Text style={[s.summary, toFix > 0 && { color: colors.amber }]}>
          {toFix > 0 ? t("mobile.checkup.device.to_fix", { count: toFix }) : t("mobile.checkup.device.all_ok")}
        </Text>
      )}
      <View style={s.card}>
        {rows.map((row, i) => {
          const look = LOOKS[row.status];
          const fix = row.fix;
          return (
            <View key={row.id} style={[s.row, i > 0 && s.rowBorder]}>
              <Ionicons name={look.icon} size={24} color={look.color} />
              <Text style={s.rowText}>{t(row.key, row.params)}</Text>
              {fix && (
                <TouchableOpacity
                  style={s.fixButton}
                  onPress={() => onFix(fix)}
                  activeOpacity={0.85}
                  accessibilityRole="button"
                  accessibilityLabel={`${t("mobile.checkup.device.fix")}: ${t(row.key, row.params)}`}
                >
                  <Text style={s.fixLabel}>{t("mobile.checkup.device.fix")}</Text>
                </TouchableOpacity>
              )}
            </View>
          );
        })}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  sectionTitle: { ...sectionHeader, marginBottom: space.xs, marginLeft: space.xs },
  summary: { fontSize: 17, lineHeight: 23, fontWeight: "600", color: colors.green, marginBottom: space.sm, marginLeft: space.xs },
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, paddingHorizontal: space.lg, paddingVertical: space.xs,
  },
  row: { flexDirection: "row", alignItems: "center", gap: space.md, minHeight: 56, paddingVertical: space.md },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  rowText: { fontSize: 16, lineHeight: 22, color: colors.textPrimary, flex: 1 },
  fixButton: {
    minHeight: 44, justifyContent: "center",
    backgroundColor: colors.blue, borderRadius: radius.pill, paddingHorizontal: space.md,
  },
  fixLabel: { fontSize: 15, fontWeight: "600", color: "#FFFFFF" },
});
