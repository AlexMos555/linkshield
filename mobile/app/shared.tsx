/**
 * Shared URL screen — opens when user shares a link TO LinkShield
 * from any app (Safari, Chrome, Messages, WhatsApp, etc.)
 *
 * Flow:
 *   User in Safari → Share → LinkShield → instant result
 *   User in WhatsApp → long press link → Share → LinkShield → alert if dangerous
 */

import { useEffect, useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator, TouchableOpacity } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { checkSingleDomain, DomainResult } from "../src/services/api";
import { saveCheck } from "../src/services/database";

export default function SharedScreen() {
  const router = useRouter();
  const { url } = useLocalSearchParams<{ url: string }>();
  const [result, setResult] = useState<DomainResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const domain = extractDomain(url || "");

  useEffect(() => {
    if (!domain) {
      setError("No valid URL shared");
      setLoading(false);
      return;
    }
    checkSingleDomain(domain)
      .then(async (r) => {
        setResult(r);
        await saveCheck(r);
        if (r.level === "dangerous") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        else if (r.level === "caution") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
        else Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      })
      .catch(() => setError("Could not check this link"))
      .finally(() => setLoading(false));
  }, [domain]);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.safe} />
        <Text style={s.loadText}>Checking {domain}...</Text>
      </View>
    );
  }

  if (error || !result) {
    return (
      <View style={s.center}>
        <Text style={s.errorIcon}>{"\u26A0"}</Text>
        <Text style={s.errorText}>{error || "Check failed"}</Text>
        <TouchableOpacity style={s.btn} onPress={() => router.replace("/(tabs)")}>
          <Text style={s.btnText}>Go Home</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const c: Record<string, string> = { safe: colors.safe, caution: colors.caution, dangerous: colors.dangerous };
  const icons: Record<string, string> = { safe: "\u2705", caution: "\u26A0\uFE0F", dangerous: "\u274C" };
  const labels: Record<string, string> = { safe: "Safe to open", caution: "Be careful", dangerous: "DO NOT OPEN" };
  const color = c[result.level] || colors.textMuted;

  return (
    <View style={s.container}>
      <View style={[s.card, { borderColor: color + "40" }]}>
        <Text style={s.icon}>{icons[result.level]}</Text>
        <Text style={[s.label, { color }]}>{labels[result.level]}</Text>
        <Text style={s.domain}>{result.domain}</Text>
        <Text style={[s.score, { color }]}>Score: {result.score}/100</Text>

        {result.reasons && result.reasons.length > 0 && (
          <View style={s.reasons}>
            {result.reasons.slice(0, 3).map((r, i) => (
              <Text key={i} style={s.reason}>• {r.detail}</Text>
            ))}
          </View>
        )}
      </View>

      <TouchableOpacity style={[s.btn, { backgroundColor: color }]} onPress={() => router.push({ pathname: "/result", params: { domain } })}>
        <Text style={s.btnText}>Full Details</Text>
      </TouchableOpacity>

      <TouchableOpacity style={s.btnSecondary} onPress={() => router.replace("/(tabs)")}>
        <Text style={s.btnSecondaryText}>Done</Text>
      </TouchableOpacity>
    </View>
  );
}

function extractDomain(url: string): string {
  try {
    if (url.startsWith("http")) return new URL(url).hostname.toLowerCase();
  } catch {}
  return url.trim().split("/")[0].toLowerCase();
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, justifyContent: "center", padding: spacing.xl },
  center: { flex: 1, backgroundColor: colors.bg, alignItems: "center", justifyContent: "center" },
  loadText: { color: colors.text, fontSize: fontSize.lg, marginTop: spacing.lg },
  errorIcon: { fontSize: 48, marginBottom: spacing.md },
  errorText: { color: colors.dangerous, fontSize: fontSize.lg, textAlign: "center" },
  card: {
    backgroundColor: colors.bgCard, borderRadius: 20, padding: spacing.xl,
    alignItems: "center", borderWidth: 2, marginBottom: spacing.lg,
  },
  icon: { fontSize: 64, marginBottom: spacing.md },
  label: { fontSize: 24, fontWeight: "800", marginBottom: spacing.xs },
  domain: { fontSize: fontSize.md, color: colors.textSecondary, marginBottom: spacing.sm },
  score: { fontSize: fontSize.lg, fontWeight: "700" },
  reasons: { marginTop: spacing.lg, alignSelf: "stretch" },
  reason: { color: colors.textMuted, fontSize: fontSize.sm, marginBottom: 4, lineHeight: 20 },
  btn: {
    backgroundColor: colors.safe, borderRadius: 14, padding: 16,
    alignItems: "center", marginBottom: spacing.sm,
  },
  btnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
  btnSecondary: {
    borderRadius: 14, padding: 14, alignItems: "center",
    borderWidth: 1, borderColor: colors.border,
  },
  btnSecondaryText: { color: colors.textMuted, fontWeight: "600", fontSize: fontSize.md },
});
