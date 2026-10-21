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
  /**
   * The automatic SMS check (RuStore build only): "listening" while it reads
   * incoming SMS, "off" while it does not. Omitted where the build has no
   * automatic check — then "Cleanway does not read your SMS" is the truth.
   */
  autoSms?: "listening" | "off";
  /**
   * Opens the RuStore listing, for the one line the website APK may say about
   * the automatic check. Omitted until that listing is live (config/stores.ts).
   */
  onOpenStore?: () => void;
}

/** The lock line: what Cleanway reads by itself, which differs by build and by switch. */
const HONESTY_KEYS = {
  none: "mobile.home.sms_check.honesty",
  listening: "mobile.home.sms_check.honesty_auto_on",
  off: "mobile.home.sms_check.honesty_auto_off",
} as const;

/**
 * The SMS check (Android). A TOOL, not a shield: it checks the message the
 * person hands it, and nothing on its own — so it has a button instead of a
 * status pill, and it is never counted in the hero's shield totals.
 *
 * Two honest lines under it: whether Cleanway reads incoming SMS by itself
 * (never in the website APK; in the RuStore build only while its "SMS
 * messages" shield runs), and that links inside SMS are checked on tap only
 * while the link guard is on AND has a list to check with. The lines are
 * statements, not buttons: the cards above are where those shields are set
 * up. The card stays in the RuStore build too — it is how a message from a
 * messenger, which no SMS permission reaches, gets checked.
 */
export function MessageCheckCard(props: MessageCheckCardProps) {
  const { onOpen, linkGuardAvailable, linkGuardOn, linkListReady, autoSms, onOpenStore } = props;
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
        <Text style={s.line}>{t(HONESTY_KEYS[autoSms ?? "none"])}</Text>
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

      {onOpenStore && (
        <TouchableOpacity
          style={s.lineRow}
          onPress={onOpenStore}
          activeOpacity={0.7}
          accessibilityRole="link"
        >
          <Ionicons name="storefront-outline" size={13} color={colors.blue} />
          <Text style={[s.line, { color: colors.blue }]}>{t("mobile.home.sms_check.store_offer")}</Text>
          <Ionicons name="open-outline" size={13} color={colors.blue} />
        </TouchableOpacity>
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
