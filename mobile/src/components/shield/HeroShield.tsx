import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../utils/theme";

export type HeroState = "none" | "partial" | "all";

interface HeroShieldProps {
  state: HeroState;
  verifiedCount: number;
  totalCount: number;
  attention?: boolean;
  /**
   * The user had protection ON and it is not running now (reboot without
   * always-on, battery manager, force-stop). Same neutral visuals as "none",
   * but the title must not say "let's set up" — that tells someone their
   * earlier setup never happened.
   */
  interrupted?: boolean;
}

/**
 * Status display, not a control — deliberately not tappable.
 * Honesty rules (docs/MOBILE_AUTO_PROTECTION.md §2): never green with
 * 0 verified shields; the absolute "You're protected" only when ALL
 * platform shields are verified-on.
 */
export function HeroShield({ state, verifiedCount, totalCount, attention, interrupted }: HeroShieldProps) {
  const { t } = useTranslation();
  const active = state !== "none";
  const title =
    state === "all" ? t("mobile.home.hero.title_all")
    : state === "partial" ? t("mobile.home.hero.title_partial", { count: verifiedCount, total: totalCount })
    : interrupted ? t("mobile.home.hero.title_interrupted")
    : t("mobile.home.hero.title_none");
  const sub =
    state === "all" ? t("mobile.home.hero.sub_all")
    : state === "partial" ? t("mobile.home.hero.sub_partial")
    : t("mobile.home.hero.sub_none", { count: verifiedCount });

  return (
    <View style={s.wrap} accessibilityRole="text" accessibilityLabel={t("mobile.home.hero.a11y", { status: title })}>
      <View style={[s.ring, active ? s.ringActive : s.ringNeutral]}>
        <View style={s.disc}>
          <Ionicons
            name={active ? "shield-checkmark" : "shield-outline"}
            size={56}
            color={active ? colors.green : colors.textSecondary}
          />
        </View>
      </View>
      <Text style={[s.title, active && { color: colors.green }]}>{title}</Text>
      <Text style={s.sub}>{sub}</Text>
      {attention && <Text style={s.attention}>{t("mobile.home.hero.attention")}</Text>}
    </View>
  );
}

const s = StyleSheet.create({
  wrap: { alignItems: "center", marginTop: space.lg, marginBottom: space.sm },
  ring: {
    width: 160, height: 160, borderRadius: 80,
    alignItems: "center", justifyContent: "center",
    borderWidth: 2.5,
  },
  ringNeutral: { borderColor: "#22314A" },
  ringActive: { borderColor: colors.greenStroke },
  disc: {
    width: 148, height: 148, borderRadius: 74,
    backgroundColor: colors.surface,
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.title2, color: colors.textPrimary, marginTop: space.md },
  sub: { ...typo.body, color: colors.textSecondary, marginTop: 4 },
  attention: { ...typo.caption, color: colors.amber, marginTop: space.sm },
});
