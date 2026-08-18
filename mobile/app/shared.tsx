/**
 * Shared URL screen — opens when user shares a link TO Cleanway
 * from any app (Safari, Chrome, Messages, WhatsApp, etc.)
 *
 * Flow:
 *   User in Safari → Share → Cleanway → instant result
 *   User in WhatsApp → long press link → Share → Cleanway → alert if dangerous
 */

import { useEffect, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, ActivityIndicator, TouchableOpacity,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import {
  colors, type as typo, space, radius, sectionHeader,
  levelColors, levelStrokes,
} from "../src/utils/theme";
import { checkDomain, PublicCheckResult, ApiError } from "../src/services/api";
import { saveCheck } from "../src/services/database";
import { toCheckableHost } from "../src/utils/host";

type ErrorKind = "no_url" | ApiError["kind"];
type Level = keyof typeof levelColors;

// Status is never colour-only (design spec §6): every verdict pairs its hue
// with an icon and a written label.
const VERDICT_ICONS: Record<Level, keyof typeof Ionicons.glyphMap> = {
  safe: "shield-checkmark-outline",
  caution: "alert-circle-outline",
  dangerous: "warning-outline",
};

export default function SharedScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const { url } = useLocalSearchParams<{ url: string }>();
  const [result, setResult] = useState<PublicCheckResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ErrorKind | null>(null);

  // One shared parser — see src/utils/host.ts for why the old split("/")
  // version leaked query strings and never punycoded IDN hosts. It returns
  // null for junk, which is what finally makes the "No link found" screen
  // below reachable.
  const domain = toCheckableHost(url || "");

  useEffect(() => {
    if (!domain) {
      setError("no_url");
      setLoading(false);
      return;
    }
    // Result-based call so the error KIND survives — a rate limit told to
    // "check your connection" retries into the rate limit and digs deeper.
    checkDomain(domain)
      .then(async ({ data: r, error: apiError }) => {
        if (!r) {
          setError(apiError?.kind ?? "network");
          return;
        }
        setResult(r);
        await saveCheck(r);
        if (r.level === "dangerous") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        else if (r.level === "caution") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
        else Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      })
      .catch(() => setError("network"))
      .finally(() => setLoading(false));
  }, [domain]);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.centerTitle}>{t("mobile.result.loading", { domain })}</Text>
        <Text style={s.centerSub}>{t("mobile.result.loading_sub")}</Text>
      </View>
    );
  }

  if (error || !result) {
    const noUrl = error === "no_url";
    return (
      <View style={s.center}>
        <Ionicons
          name={noUrl ? "link-outline" : "cloud-offline-outline"}
          size={44}
          color={colors.amber}
        />
        <Text style={s.centerTitle}>
          {t(noUrl ? "mobile.shared.no_url_title" : "mobile.result.error_title")}
        </Text>
        <Text style={s.centerBody}>
          {t(
            noUrl ? "mobile.shared.no_url_body"
            : error === "rate_limited" ? "mobile.result.error_rate_limited"
            : error === "http_5xx" ? "mobile.result.error_server"
            : "mobile.shared.check_failed_body",
          )}
        </Text>
        <TouchableOpacity
          style={s.primaryBtn}
          onPress={() => router.replace("/(tabs)")}
          activeOpacity={0.85}
          accessibilityRole="button"
        >
          <Text style={s.primaryLabel}>{t("mobile.shared.go_home")}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const level = (result.level in levelColors ? result.level : "caution") as Level;
  const color = levelColors[level];
  const label = t(`mobile.result.verdict_${level}`);
  const reasons = result.reasons ?? [];
  const shown = reasons.slice(0, 3);
  const hidden = reasons.length - shown.length;

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.eyebrow}>{t("mobile.shared.eyebrow")}</Text>

      <View
        style={[s.verdictCard, { borderColor: levelStrokes[level] }]}
        accessibilityRole="summary"
        accessibilityLabel={t("mobile.shared.a11y_verdict", {
          verdict: label, domain: result.domain, score: result.score,
        })}
      >
        <View style={[s.ring, { borderColor: color + "66" }]}>
          <Text style={[s.ringScore, { color }]}>{result.score}</Text>
          <Text style={s.ringMax}>/100</Text>
        </View>
        <Text style={s.scoreCaption}>{t("mobile.shared.score_caption")}</Text>

        <View style={s.verdictRow}>
          <Ionicons name={VERDICT_ICONS[level]} size={22} color={color} />
          <Text style={[s.verdictLabel, { color }]}>{label}</Text>
        </View>
        <Text style={s.domain}>{result.domain}</Text>
        <Text style={s.advice}>{t(`mobile.shared.advice_${level}`)}</Text>
        {result.confidence === "low" && (
          <Text style={s.lowConf}>{t("mobile.result.low_confidence")}</Text>
        )}
      </View>

      {shown.length > 0 && (
        <View style={s.card}>
          <Text style={s.cardTitle}>{t("mobile.result.signals")}</Text>
          {shown.map((r, i) => (
            <View key={i} style={[s.signalRow, i > 0 && s.signalBorder]}>
              <View style={[s.signalDot, { backgroundColor: color }]} />
              <Text style={s.signalText}>{r.detail}</Text>
            </View>
          ))}
          {hidden > 0 && (
            <Text style={s.moreSignals}>{t("mobile.shared.more_signals", { n: hidden })}</Text>
          )}
        </View>
      )}

      <TouchableOpacity
        style={s.primaryBtn}
        onPress={() => router.push({ pathname: "/result", params: { domain } })}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Text style={s.primaryLabel}>{t("mobile.shared.full_details")}</Text>
      </TouchableOpacity>

      <TouchableOpacity
        style={s.secondaryBtn}
        onPress={() => router.replace("/(tabs)")}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Text style={s.secondaryLabel}>{t("mobile.shared.done")}</Text>
      </TouchableOpacity>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.result.privacy")}</Text>
      </View>
    </ScrollView>
  );
}


const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, paddingHorizontal: space.xl, paddingBottom: 100,
  },
  centerTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  centerSub: { ...typo.caption, color: colors.textMuted, marginTop: space.xs },
  centerBody: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },

  eyebrow: { ...sectionHeader, marginBottom: space.sm },

  verdictCard: {
    backgroundColor: colors.surface, borderWidth: 1,
    borderRadius: radius.card, padding: space.lg,
    alignItems: "center", marginBottom: space.md,
  },
  ring: {
    width: 104, height: 104, borderRadius: radius.full, borderWidth: 8,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  ringScore: { ...typo.display },
  ringMax: { ...typo.caption, color: colors.textMuted, marginTop: -2 },
  scoreCaption: { ...typo.caption, color: colors.textMuted, marginTop: space.sm, textAlign: "center" },
  verdictRow: { flexDirection: "row", alignItems: "center", gap: space.sm, marginTop: space.lg },
  verdictLabel: { ...typo.title2 },
  domain: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  advice: { ...typo.body, color: colors.textPrimary, textAlign: "center", marginTop: space.md },
  lowConf: { ...typo.caption, color: colors.amber, textAlign: "center", marginTop: space.sm },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { ...typo.headline, color: colors.textPrimary, marginBottom: space.sm },
  signalRow: { flexDirection: "row", alignItems: "center", gap: space.sm, paddingVertical: 8 },
  signalBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  signalDot: { width: 6, height: 6, borderRadius: 3 },
  signalText: { ...typo.body, color: colors.textSecondary, flex: 1 },
  moreSignals: { ...typo.caption, color: colors.textMuted, marginTop: space.sm },

  primaryBtn: {
    height: 50, backgroundColor: colors.blue, borderRadius: radius.control,
    paddingHorizontal: space.xxl,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondaryBtn: {
    height: 50, backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.sm, marginBottom: space.lg,
  },
  secondaryLabel: { fontSize: 15, fontWeight: "600", color: colors.textPrimary },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
