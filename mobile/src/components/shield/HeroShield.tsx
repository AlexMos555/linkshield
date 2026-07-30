import { View, Text, StyleSheet } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { colors, type as t, space } from "../../utils/theme";

export type HeroState = "none" | "partial" | "all";

interface HeroShieldProps {
  state: HeroState;
  verifiedCount: number;
  totalCount: number;
  attention?: boolean;
}

/**
 * Status display, not a control — deliberately not tappable.
 * Honesty rules (docs/MOBILE_AUTO_PROTECTION.md §2): never green with
 * 0 verified shields; the absolute "You're protected" only when ALL
 * platform shields are verified-on.
 */
export function HeroShield({ state, verifiedCount, totalCount, attention }: HeroShieldProps) {
  const active = state !== "none";
  const title =
    state === "all" ? "You're protected"
    : state === "partial" ? `${verifiedCount} of ${totalCount} shields on`
    : "Let's set up your protection";
  const sub =
    state === "all" ? "All shields on and verified"
    : state === "partial" ? "Tap a card below to finish setup"
    : `${verifiedCount} shields active`;

  return (
    <View style={s.wrap} accessibilityRole="text" accessibilityLabel={`Protection status: ${title}`}>
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
      {attention && <Text style={s.attention}>One shield needs attention</Text>}
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
  title: { ...t.title2, color: colors.textPrimary, marginTop: space.md },
  sub: { ...t.body, color: colors.textSecondary, marginTop: 4 },
  attention: { ...t.caption, color: colors.amber, marginTop: space.sm },
});
