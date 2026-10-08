import { View, Text, StyleSheet, Pressable } from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import type { Access } from "../../utils/freemium";

/**
 * Pieces of the free plan's daily limit (src/utils/freemium.ts) that sit in
 * the check screens. The paywall itself is app/paywall.tsx.
 */

/**
 * Where the detailed analysis would be, once today's free checks are used
 * up: what is missing, that list blocking still works, and the way to the
 * paywall. Never shown in place of a "dangerous" verdict — under it.
 */
export function LockedDetailsCard() {
  const { t } = useTranslation();
  const router = useRouter();
  return (
    <View style={s.card}>
      <View style={s.titleRow}>
        <Ionicons name="lock-closed-outline" size={20} color={colors.textPrimary} />
        <Text style={s.title}>{t("mobile.paywall.locked_title")}</Text>
      </View>
      <Text style={s.body}>{t("mobile.paywall.locked_body")}</Text>
      <Pressable
        style={({ pressed }) => [s.button, pressed && s.buttonPressed]}
        onPress={() => router.push("/paywall")}
        accessibilityRole="button"
        android_ripple={{ color: "#FFFFFF22" }}
      >
        <Text style={s.buttonLabel}>{t("mobile.paywall.locked_cta")}</Text>
      </Pressable>
    </View>
  );
}

/**
 * A site the list does not know, when the detailed check is locked: said
 * plainly, without the green of "safe" — not being listed proves nothing.
 */
export function NotListedCard({ domain }: { domain: string }) {
  const { t } = useTranslation();
  return (
    <View
      style={s.verdict}
      accessible
      accessibilityRole="summary"
      accessibilityLabel={`${t("mobile.paywall.not_listed_title")}. ${domain}. ${t("mobile.paywall.not_listed_body")}`}
    >
      <Ionicons name="help-circle-outline" size={44} color={colors.textPrimary} />
      <Text style={s.verdictTitle}>{t("mobile.paywall.not_listed_title")}</Text>
      <Text style={s.domain}>{domain}</Text>
      <Text style={s.verdictBody}>{t("mobile.paywall.not_listed_body")}</Text>
    </View>
  );
}

/**
 * "N free checks left today" under a check button — free plan only (not
 * during the first days, not on a paid plan, not with the limit off).
 */
export function ChecksLeftHint({ access }: { access: Access | null }) {
  const { t } = useTranslation();
  if (!access || access.kind !== "free") return null;
  const none = access.remaining <= 0;
  return (
    <View style={s.hintRow} accessibilityLiveRegion="polite">
      <Ionicons name={none ? "lock-closed-outline" : "time-outline"} size={14} color={none ? colors.amber : colors.textSecondary} />
      <Text style={[s.hint, none && s.hintNone]}>
        {none ? t("mobile.paywall.none_left") : t("mobile.paywall.left_today", { n: access.remaining })}
      </Text>
    </View>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  titleRow: { flexDirection: "row", alignItems: "center", gap: space.sm },
  title: { ...typo.headline, color: colors.textPrimary, flex: 1 },
  body: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: space.sm },
  button: {
    minHeight: 50, backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.lg,
  },
  buttonPressed: { backgroundColor: colors.bluePressed },
  buttonLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF", textAlign: "center" },

  verdict: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.xxl, alignItems: "center", marginBottom: space.md,
  },
  verdictTitle: { ...typo.title2, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  domain: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  verdictBody: { ...typo.body, color: colors.textPrimary, textAlign: "center", marginTop: space.md },

  hintRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.sm, paddingHorizontal: space.xs,
  },
  hint: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, textAlign: "center", flexShrink: 1 },
  hintNone: { color: colors.amber },
});
