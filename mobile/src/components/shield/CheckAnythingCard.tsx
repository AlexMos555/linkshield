import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";

interface CheckAnythingCardProps {
  onOpen: () => void;
  onPaste: () => void;
  onScanQr: () => void;
  onHowToShare: () => void;
}

/**
 * The on-demand layer — always present, always fully working
 * (paste / QR / share-sheet). Makes no protection claim, so it carries
 * no honesty line; the footnote states the iMessage-capable scope.
 */
export function CheckAnythingCard({ onOpen, onPaste, onScanQr, onHowToShare }: CheckAnythingCardProps) {
  const { t } = useTranslation();
  return (
    <TouchableOpacity style={s.card} onPress={onOpen} activeOpacity={0.85} accessibilityRole="button">
      <View style={s.titleRow}>
        <View style={s.iconBox}>
          <Ionicons name="search-outline" size={22} color={colors.textSecondary} />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={s.title}>{t("mobile.home.check.title")}</Text>
<Text style={s.desc}>{t("mobile.home.check.desc")}</Text>
        </View>
        <Ionicons name="chevron-forward" size={18} color={colors.textMuted} />
      </View>

      <View style={s.chipRow}>
        <Chip icon="clipboard-outline" label={t("mobile.home.check.paste")} onPress={onPaste} />
        <Chip icon="qr-code-outline" label={t("mobile.home.check.qr")} onPress={onScanQr} />
        <Chip icon="share-outline" label={t("mobile.home.check.share")} onPress={onHowToShare} />
      </View>

      <Text style={s.note}>{t("mobile.home.check.note")}</Text>
    </TouchableOpacity>
  );
}

interface ChipProps {
  icon: keyof typeof Ionicons.glyphMap;
  label: string;
  onPress: () => void;
}

function Chip({ icon, label, onPress }: ChipProps) {
  return (
    <TouchableOpacity style={s.chip} onPress={onPress} activeOpacity={0.85} accessibilityRole="button">
      <Ionicons name={icon} size={16} color={colors.textPrimary} />
      <Text style={s.chipLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  titleRow: { flexDirection: "row", alignItems: "flex-start", gap: space.md },
  iconBox: {
    width: 40, height: 40, borderRadius: radius.icon,
    backgroundColor: "#FFFFFF0A",
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.headline, color: colors.textPrimary },
  desc: { ...typo.body, color: colors.textSecondary, marginTop: 2 },
  chipRow: { flexDirection: "row", flexWrap: "wrap", gap: space.sm, marginTop: 14 },
  chip: {
    flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 6,
    height: 40, paddingHorizontal: space.md,
    backgroundColor: "#FFFFFF0A",
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.chip,
    flexGrow: 1,
  },
  chipLabel: { fontSize: 13, fontWeight: "600", color: colors.textPrimary },
  note: { ...typo.caption, color: colors.textSecondary, marginTop: space.md },
});
