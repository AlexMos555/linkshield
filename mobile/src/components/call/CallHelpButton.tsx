import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, space, radius, type as typo } from "../../utils/theme";

/**
 * "I'm being called" — the home button that opens the stop screen on demand.
 * Big and calm: the person reaches for it with the phone at her ear. It makes
 * no protection claim (the screen says what Cleanway cannot see), so it
 * carries no honesty line of its own.
 */
export function CallHelpButton({ onPress }: { onPress: () => void }) {
  const { t } = useTranslation();
  return (
    <TouchableOpacity
      style={s.card}
      onPress={onPress}
      activeOpacity={0.85}
      accessibilityRole="button"
      accessibilityLabel={`${t("mobile.call_guard.home_button")}. ${t("mobile.call_guard.home_button_sub")}`}
    >
      <View style={s.iconBox}>
        <Ionicons name="call-outline" size={26} color={colors.amber} />
      </View>
      <View style={{ flex: 1 }}>
        <Text style={s.title}>{t("mobile.call_guard.home_button")}</Text>
        <Text style={s.sub}>{t("mobile.call_guard.home_button_sub")}</Text>
      </View>
      <Ionicons name="chevron-forward" size={18} color={colors.textMuted} />
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  card: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    minHeight: 72, backgroundColor: colors.amberWash,
    borderWidth: 1, borderColor: colors.amberStroke,
    borderRadius: radius.card, padding: space.lg,
  },
  iconBox: {
    width: 48, height: 48, borderRadius: radius.icon,
    backgroundColor: "#FFFFFF0A", alignItems: "center", justifyContent: "center",
  },
  title: { fontSize: 19, lineHeight: 24, fontWeight: "700", color: colors.textPrimary },
  sub: { ...typo.body, color: colors.textSecondary, marginTop: 2 },
});
