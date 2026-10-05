import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../utils/theme";
import { clockTime } from "../../utils/relative-time";

export type HeroState = "none" | "partial" | "all";

/**
 * The main shield cannot protect right now, whatever else is on. Wins over
 * the counts: with the link guard on, "partial" used to paint the hero green
 * while every app on the phone was unfiltered (report #20).
 */
export type HeroHold =
  /** Paused by the person; comes back by itself at [until]. */
  | { kind: "paused"; until: number }
  /** Strict Private DNS: the shield cannot run at all. */
  | { kind: "conflict" }
  /** The subscription lapsed to basic: blocking continues from a weekly list — the "yellow shield" (billing plan A.10). */
  | { kind: "basic" }
  /** The subscription lapsed to off: the tunnel runs, nothing is blocked. */
  | { kind: "lapsed_off" };

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
  hold?: HeroHold | null;
  /**
   * The main shield is up but the phone has no internet, so it cannot be
   * proven. Not a fault and not "let's set up" — which is what 1.0.2 said
   * over a shield that was set up and blocking from its list.
   */
  offline?: boolean;
}

/**
 * Status display, not a control — deliberately not tappable.
 * Honesty rules (docs/MOBILE_AUTO_PROTECTION.md §2): never green with
 * 0 verified shields; the absolute "You're protected" only when ALL
 * platform shields are verified-on; never green while the main shield is
 * paused or cannot run.
 */
export function HeroShield({ state, verifiedCount, totalCount, attention, interrupted, hold, offline }: HeroShieldProps) {
  const { t, i18n } = useTranslation();
  const quiet = offline && !hold;
  const active = state !== "none" && !hold && !quiet;
  const title =
    hold?.kind === "paused" ? t("mobile.home.hero.title_paused", { time: clockTime(hold.until, i18n.language) })
    : hold?.kind === "conflict" ? t("mobile.home.hero.title_conflict")
    : hold?.kind === "basic" ? t("mobile.home.hero.title_basic")
    : hold?.kind === "lapsed_off" ? t("mobile.home.hero.title_lapsed_off")
    : quiet ? t("mobile.home.hero.title_offline")
    : state === "all" ? t("mobile.home.hero.title_all")
    : state === "partial" ? t("mobile.home.hero.title_partial", { count: verifiedCount, total: totalCount })
    : interrupted ? t("mobile.home.hero.title_interrupted")
    : t("mobile.home.hero.title_none");
  const sub =
    hold?.kind === "paused" ? t("mobile.home.hero.sub_paused")
    : hold?.kind === "conflict" ? t("mobile.home.hero.sub_conflict")
    : hold?.kind === "basic" ? t("mobile.home.hero.sub_basic")
    : hold?.kind === "lapsed_off" ? t("mobile.home.hero.sub_lapsed_off")
    : quiet ? t("mobile.home.hero.sub_offline")
    : state === "all" ? t("mobile.home.hero.sub_all")
    : state === "partial" ? t("mobile.home.hero.sub_partial")
    : t("mobile.home.hero.sub_none", { count: verifiedCount });
  const icon: keyof typeof Ionicons.glyphMap =
    hold?.kind === "paused" ? "pause-circle-outline"
    : hold?.kind === "basic" ? "shield-half-outline"
    : hold?.kind === "lapsed_off" ? "shield-outline"
    : hold ? "alert-circle-outline"
    : quiet ? "cloud-offline-outline"
    : active ? "shield-checkmark"
    : "shield-outline";
  const iconColor = hold?.kind === "lapsed_off" ? colors.danger : hold ? colors.amber : active ? colors.green : colors.textSecondary;

  return (
    <View style={s.wrap} accessibilityRole="text" accessibilityLabel={t("mobile.home.hero.a11y", { status: title })}>
      <View style={[s.ring, active ? s.ringActive : hold?.kind === "lapsed_off" ? s.ringDanger : hold ? s.ringHold : s.ringNeutral]}>
        <View style={s.disc}>
          <Ionicons name={icon} size={56} color={iconColor} />
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
  ringHold: { borderColor: colors.amberStroke },
  ringDanger: { borderColor: colors.dangerStroke },
  disc: {
    width: 148, height: 148, borderRadius: 74,
    backgroundColor: colors.surface,
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.title2, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  sub: { ...typo.body, color: colors.textSecondary, marginTop: 4, textAlign: "center" },
  attention: { ...typo.caption, color: colors.amber, marginTop: space.sm },
});
