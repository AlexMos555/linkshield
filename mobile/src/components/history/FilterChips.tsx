import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { useTranslation } from "react-i18next";
import { colors, space, radius } from "../../utils/theme";
import type { HistoryFilter } from "../../utils/history-model";
import { FILTER_KEYS } from "../../utils/history-labels";

interface FilterChipsProps {
  filters: readonly HistoryFilter[];
  selected: HistoryFilter;
  onSelect: (filter: HistoryFilter) => void;
}

/**
 * The History filters. They wrap onto a second line rather than scroll
 * sideways: five chips do not fit one line of a phone in Russian, and a chip
 * hidden past the edge of a sideways strip is a chip a grandmother never
 * finds. The selected chip is filled and announced as selected, not told
 * apart by colour alone.
 */
export function FilterChips({ filters, selected, onSelect }: FilterChipsProps) {
  const { t } = useTranslation();
  return (
    <View style={s.row} accessibilityRole="tablist">
      {filters.map((filter) => {
        const on = filter === selected;
        return (
          <TouchableOpacity
            key={filter}
            style={[s.chip, on && s.chipOn]}
            onPress={() => onSelect(filter)}
            activeOpacity={0.85}
            accessibilityRole="tab"
            accessibilityState={{ selected: on }}
          >
            <Text style={[s.label, on && s.labelOn]}>{t(FILTER_KEYS[filter])}</Text>
          </TouchableOpacity>
        );
      })}
    </View>
  );
}

const s = StyleSheet.create({
  row: { flexDirection: "row", flexWrap: "wrap", gap: space.sm, paddingVertical: space.xs },
  chip: {
    minHeight: 48, paddingHorizontal: space.lg, justifyContent: "center",
    borderRadius: radius.full, borderWidth: 1, borderColor: colors.stroke,
    backgroundColor: colors.surface,
  },
  chipOn: { backgroundColor: colors.blue, borderColor: colors.blue },
  label: { fontSize: 15, fontWeight: "600", color: colors.textSecondary },
  labelOn: { color: "#FFFFFF" },
});
