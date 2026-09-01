import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../../utils/theme";

export interface RolloutItem {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  line: string;
}

/**
 * Unbuilt shields, said out loud — muted rows, no Set-up buttons,
 * no chevrons, not tappable. Visibly quieter than active cards by design.
 */
export function RolloutList({ items }: { items: RolloutItem[] }) {
  const { t } = useTranslation();
  if (items.length === 0) return null;
  return (
    <View>
      <Text style={s.header}>{t("mobile.home.rollout_header")}</Text>
      <View style={s.container}>
        {items.map((item, i) => (
          <View
            key={item.title}
            style={[s.row, i > 0 && s.rowBorder]}
            accessibilityState={{ disabled: true }}
          >
            <Ionicons name={item.icon} size={20} color={colors.textDisabled} />
            <View style={{ flex: 1 }}>
              <Text style={s.title}>{item.title}</Text>
              <Text style={s.line} numberOfLines={3}>{item.line}</Text>
            </View>
            <View style={s.pill}>
              <Text style={s.pillLabel}>{t("mobile.shield.status.rollout_pill")}</Text>
            </View>
          </View>
        ))}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  header: { ...sectionHeader, marginBottom: space.sm },
  container: {
    backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card,
  },
  row: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    paddingVertical: 14, paddingHorizontal: space.lg,
  },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  title: { fontSize: 15, fontWeight: "600", color: colors.textDisabled },
  line: { ...typo.caption, color: colors.textMuted, marginTop: 2 },
  pill: {
    backgroundColor: "#FFFFFF0A",
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.pill,
    paddingHorizontal: 10, paddingVertical: 5,
  },
  pillLabel: { fontSize: 13, fontWeight: "600", color: colors.textMuted },
});
