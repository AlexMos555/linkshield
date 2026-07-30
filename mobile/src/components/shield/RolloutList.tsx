import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { colors, type as t, space, radius, sectionHeader } from "../../utils/theme";

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
  if (items.length === 0) return null;
  return (
    <View>
      <Text style={s.header}>Rolling out</Text>
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
              <Text style={s.pillLabel}>Rolling out</Text>
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
  line: { ...t.caption, color: colors.textMuted, marginTop: 2 },
  pill: {
    backgroundColor: "#FFFFFF0A",
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.pill,
    paddingHorizontal: 10, paddingVertical: 5,
  },
  pillLabel: { fontSize: 13, fontWeight: "600", color: colors.textMuted },
});
