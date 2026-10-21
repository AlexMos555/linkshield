import { View, Text, StyleSheet, TouchableOpacity, I18nManager } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";

interface CheckupCardProps {
  onOpen: () => void;
  done: number;
  total: number;
}

/**
 * Entry to "Проверка защиты" from the home screen. It shows the family
 * steps' count as the person marked them — "done N of M", never a
 * security score — and the whole card opens the screen.
 */
export function CheckupCard({ onOpen, done, total }: CheckupCardProps) {
  const { t } = useTranslation();
  const complete = total > 0 && done === total;
  return (
    <TouchableOpacity style={s.card} onPress={onOpen} activeOpacity={0.85} accessibilityRole="button">
      <View style={s.iconBox}>
        <Ionicons name="clipboard-outline" size={22} color={colors.textSecondary} />
      </View>
      <View style={s.text}>
        <Text style={s.title}>{t("mobile.checkup.title")}</Text>
        <Text style={s.desc}>{t("mobile.checkup.home_desc")}</Text>
        <Text style={[s.progress, complete && { color: colors.green }]}>
          {t("mobile.checkup.home_progress", { done, total })}
        </Text>
      </View>
      <Ionicons name={I18nManager.isRTL ? "chevron-back" : "chevron-forward"} size={18} color={colors.textMuted} />
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  card: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  iconBox: {
    width: 40, height: 40, borderRadius: radius.icon,
    backgroundColor: "#FFFFFF0A",
    alignItems: "center", justifyContent: "center",
  },
  text: { flex: 1 },
  title: { ...typo.headline, color: colors.textPrimary },
  desc: { ...typo.body, color: colors.textSecondary, marginTop: 2 },
  progress: { fontSize: 15, lineHeight: 20, fontWeight: "600", color: colors.blue, marginTop: space.sm },
});
