import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";

interface MessageCheckCardProps {
  onOpen: () => void;
  /** The link guard exists on this phone (Android 10+). Omit the link line otherwise. */
  linkGuardAvailable: boolean;
  /** Cleanway is the default link handler right now (live check). */
  linkGuardOn: boolean;
  /**
   * The link guard has a blocklist to check with. Only the "All apps" shield
   * downloads one; without it every tapped link opens unchecked.
   */
  linkListReady: boolean;
}

/**
 * The SMS check (Android). A TOOL, not a shield: it checks the message the
 * person hands it, and nothing on its own — so it has a button instead of a
 * status pill, and it is never counted in the hero's shield totals.
 *
 * Two honest lines under it: Cleanway does not read incoming SMS by itself,
 * and links inside SMS are checked on tap only while the link guard is on
 * AND has a list to check with. The lines are statements, not buttons: the
 * "Link checking" card above is where that shield is set up.
 */
export function MessageCheckCard({ onOpen, linkGuardAvailable, linkGuardOn, linkListReady }: MessageCheckCardProps) {
  const { t } = useTranslation();
  const linksChecked = linkGuardOn && linkListReady;
  return (
    <View style={s.card}>
      <View style={s.titleRow}>
        <View style={s.iconBox}>
          <Ionicons name="chatbubble-ellipses-outline" size={22} color={colors.textSecondary} />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={s.title}>{t("mobile.home.sms_check.title")}</Text>
          <Text style={s.desc}>{t("mobile.home.sms_check.desc")}</Text>
        </View>
      </View>

      <TouchableOpacity style={s.cta} onPress={onOpen} activeOpacity={0.85} accessibilityRole="button">
        <Text style={s.ctaLabel}>{t("mobile.home.sms_check.cta")}</Text>
      </TouchableOpacity>

      <View style={s.lineRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textSecondary} />
        <Text style={s.line}>{t("mobile.home.sms_check.honesty")}</Text>
      </View>

      {linkGuardAvailable && (
        <View style={s.lineRow}>
          <Ionicons
            name={linksChecked ? "checkmark-circle-outline" : "information-circle-outline"}
            size={13}
            color={linksChecked ? colors.green : colors.textSecondary}
          />
          <Text style={s.line}>
            {t(linksChecked
              ? "mobile.home.sms_check.links_on"
              : linkGuardOn ? "mobile.home.sms_check.links_no_list" : "mobile.home.sms_check.links_off")}
          </Text>
        </View>
      )}
    </View>
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
  cta: {
    minHeight: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: 14,
  },
  ctaLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  lineRow: { flexDirection: "row", alignItems: "flex-start", gap: 6, marginTop: 10 },
  line: { ...typo.caption, color: colors.textSecondary, flex: 1 },
});
