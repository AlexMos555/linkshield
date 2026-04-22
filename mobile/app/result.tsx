import { useEffect, useState } from "react";
import { View, Text, StyleSheet, ScrollView, ActivityIndicator, TouchableOpacity, Share } from "react-native";
import { useLocalSearchParams } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize, levelColors, levelLabels } from "../src/utils/theme";
import { checkSingleDomain, DomainResult } from "../src/services/api";
import { saveCheck } from "../src/services/database";

export default function ResultScreen() {
  const { domain } = useLocalSearchParams<{ domain: string }>();
  const [result, setResult] = useState<DomainResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!domain) return;
    checkSingleDomain(domain)
      .then((r) => {
        setResult(r);
        saveCheck(r);
        if (r.level === "dangerous") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        else if (r.level === "caution") Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
        else Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [domain]);

  if (loading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color={colors.primary} />
        <Text style={styles.loadingText}>Analyzing {domain}...</Text>
        <Text style={styles.loadingSub}>Checking 9 threat sources + ML model</Text>
      </View>
    );
  }

  if (error || !result) {
    return (
      <View style={styles.center}>
        <Text style={{ fontSize: 48, marginBottom: spacing.md }}>{"\u26A0"}</Text>
        <Text style={styles.errorText}>{error || "Failed to check domain"}</Text>
      </View>
    );
  }

  const color = levelColors[result.level] || colors.textMuted;
  const label = levelLabels[result.level] || "Unknown";
  const icon = result.level === "safe" ? "\u2705" : result.level === "caution" ? "\u26A0\uFE0F" : "\u274C";

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Result Header */}
      <View style={[styles.header, { borderColor: color + "40" }]}>
        <Text style={styles.icon}>{icon}</Text>
        <Text style={[styles.level, { color }]}>{label}</Text>
        <Text style={styles.domain}>{result.domain}</Text>
        <Text style={[styles.score, { color }]}>Score: {result.score}/100</Text>
        {result.confidence === "low" && (
          <Text style={styles.lowConf}>Limited analysis — some checks unavailable</Text>
        )}
      </View>

      {/* Reasons */}
      {result.reasons && result.reasons.length > 0 && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Detection Signals</Text>
          {result.reasons.map((r, i) => (
            <View key={i} style={styles.reasonRow}>
              <Text style={[styles.reasonDot, { color }]}>{"\u2022"}</Text>
              <Text style={styles.reasonText}>{r.detail}</Text>
              <Text style={[styles.reasonWeight, { color }]}>+{r.weight}</Text>
            </View>
          ))}
        </View>
      )}

      {/* Details */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Details</Text>
        {result.domain_age_days != null && (
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Domain Age</Text>
            <Text style={styles.detailValue}>{result.domain_age_days} days</Text>
          </View>
        )}
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>HTTPS</Text>
          <Text style={styles.detailValue}>{result.has_ssl ? "Yes" : "No"}</Text>
        </View>
        {result.ssl_issuer && (
          <View style={styles.detailRow}>
            <Text style={styles.detailLabel}>Certificate</Text>
            <Text style={styles.detailValue}>{result.ssl_issuer}</Text>
          </View>
        )}
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Confidence</Text>
          <Text style={styles.detailValue}>{result.confidence || "medium"}</Text>
        </View>
      </View>

      {/* Share Result */}
      <TouchableOpacity
        style={styles.shareBtn}
        onPress={() => {
          Share.share({
            message: `${result.domain} is ${label} (score: ${result.score}/100). Checked with Cleanway — https://cleanway.ai/check/${result.domain}`,
          });
        }}
      >
        <Text style={styles.shareBtnText}>Share Result</Text>
      </TouchableOpacity>

      <Text style={styles.note}>{"\u{1F512}"} Analysis ran on our servers. Only domain name was sent.</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  center: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: colors.bg },
  loadingText: { color: colors.text, fontSize: fontSize.lg, fontWeight: "600", marginTop: spacing.lg },
  loadingSub: { color: colors.textMuted, fontSize: fontSize.sm, marginTop: spacing.xs },
  errorText: { color: colors.dangerous, fontSize: fontSize.lg, textAlign: "center", padding: spacing.xl },
  header: {
    backgroundColor: colors.bgCard, borderRadius: 16, padding: spacing.xl,
    alignItems: "center", marginBottom: spacing.lg, borderWidth: 1,
  },
  icon: { fontSize: 48, marginBottom: spacing.sm },
  level: { fontSize: fontSize.xxl, fontWeight: "800" },
  domain: { color: colors.textSecondary, fontSize: fontSize.md, marginTop: 4 },
  score: { fontSize: fontSize.lg, fontWeight: "700", marginTop: spacing.sm },
  lowConf: { color: colors.caution, fontSize: fontSize.sm, marginTop: spacing.sm, fontStyle: "italic" },
  card: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  cardTitle: { color: colors.white, fontSize: fontSize.lg, fontWeight: "700", marginBottom: spacing.md },
  reasonRow: { flexDirection: "row", alignItems: "flex-start", gap: spacing.sm, paddingVertical: 6 },
  reasonDot: { fontSize: 18, lineHeight: 20 },
  reasonText: { flex: 1, color: colors.textSecondary, fontSize: fontSize.md, lineHeight: 20 },
  reasonWeight: { fontSize: fontSize.sm, fontWeight: "700" },
  detailRow: {
    flexDirection: "row", justifyContent: "space-between",
    paddingVertical: spacing.sm, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  detailLabel: { color: colors.textMuted, fontSize: fontSize.md },
  detailValue: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },
  shareBtn: {
    backgroundColor: colors.bgCard, borderRadius: 12, padding: 16,
    alignItems: "center", marginBottom: spacing.lg,
    borderWidth: 1, borderColor: colors.border,
  },
  shareBtnText: { color: colors.primary, fontWeight: "700", fontSize: fontSize.md },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm, marginTop: spacing.md },
});
