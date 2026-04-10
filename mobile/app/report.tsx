import { useState, useEffect } from "react";
import { View, Text, StyleSheet, ScrollView, TouchableOpacity, Share } from "react-native";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { getWeeklyStats, getRecentChecks } from "../src/services/database";

export default function ReportScreen() {
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0 });
  const [topThreats, setTopThreats] = useState<{ domain: string; count: number }[]>([]);
  const [percentile, setPercentile] = useState(75);

  useEffect(() => {
    loadReport();
  }, []);

  async function loadReport() {
    const s = await getWeeklyStats();
    setStats(s);

    const checks = await getRecentChecks(200);
    const weekAgo = Date.now() - 7 * 86400000;
    const weekChecks = checks.filter((c: any) => new Date(c.checked_at).getTime() >= weekAgo);

    // Count domains
    const counts: Record<string, number> = {};
    weekChecks.filter((c: any) => c.level !== "safe").forEach((c: any) => {
      counts[c.domain] = (counts[c.domain] || 0) + 1;
    });

    const sorted = Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([domain, count]) => ({ domain, count }));

    setTopThreats(sorted);

    // Estimate percentile based on blocks (simplified)
    const blocked = s.threats_blocked;
    const p = blocked === 0 ? 90 : blocked <= 2 ? 80 : blocked <= 5 ? 65 : 50;
    setPercentile(p);
  }

  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 86400000);
  const period = `${weekAgo.toLocaleDateString()} — ${now.toLocaleDateString()}`;

  async function shareReport() {
    await Share.share({
      message: `My LinkShield Weekly Report:\n${stats.total_checks} links checked, ${stats.threats_blocked} threats blocked.\nI'm safer than ${percentile}% of users.\n\nhttps://linkshield.io`,
    });
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Weekly Report</Text>
      <Text style={styles.period}>{period}</Text>

      {/* Percentile */}
      <View style={styles.percentileCard}>
        <Text style={styles.percentileNum}>{percentile}%</Text>
        <Text style={styles.percentileLabel}>Safer than {percentile}% of users</Text>
      </View>

      {/* Stats */}
      <View style={styles.statsRow}>
        <View style={styles.statCard}>
          <Text style={styles.statNum}>{stats.total_checks}</Text>
          <Text style={styles.statLabel}>Checked</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={[styles.statNum, { color: colors.dangerous }]}>{stats.threats_blocked}</Text>
          <Text style={styles.statLabel}>Blocked</Text>
        </View>
      </View>

      {/* Top Threats */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Top Threats This Week</Text>
        {topThreats.length === 0 ? (
          <Text style={styles.emptyText}>{"\u2705"} No threats this week!</Text>
        ) : (
          topThreats.map((t, i) => (
            <View key={i} style={styles.threatRow}>
              <Text style={styles.threatDomain}>{t.domain}</Text>
              <Text style={styles.threatCount}>{t.count}x</Text>
            </View>
          ))
        )}
      </View>

      {/* Share */}
      <TouchableOpacity style={styles.shareBtn} onPress={shareReport}>
        <Text style={styles.shareBtnText}>Share Report</Text>
      </TouchableOpacity>

      <Text style={styles.note}>{"\u{1F512}"} Generated 100% on your device</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  title: { fontSize: fontSize.xxl, fontWeight: "800", color: colors.white, textAlign: "center" },
  period: { fontSize: fontSize.sm, color: colors.textMuted, textAlign: "center", marginBottom: spacing.xl },
  percentileCard: {
    backgroundColor: colors.safeBg, borderRadius: 16, padding: spacing.xl,
    alignItems: "center", marginBottom: spacing.lg, borderWidth: 1, borderColor: colors.safe + "40",
  },
  percentileNum: { fontSize: 64, fontWeight: "800", color: colors.safe },
  percentileLabel: { fontSize: fontSize.lg, color: colors.safe, fontWeight: "600", marginTop: spacing.xs },
  statsRow: { flexDirection: "row", gap: spacing.md, marginBottom: spacing.lg },
  statCard: { flex: 1, backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, alignItems: "center" },
  statNum: { fontSize: 32, fontWeight: "800", color: colors.white },
  statLabel: { fontSize: fontSize.sm, color: colors.textMuted, marginTop: spacing.xs },
  card: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  cardTitle: { fontSize: fontSize.lg, fontWeight: "700", color: colors.white, marginBottom: spacing.md },
  emptyText: { color: colors.safe, fontSize: fontSize.md, textAlign: "center", padding: spacing.md },
  threatRow: {
    flexDirection: "row", justifyContent: "space-between",
    paddingVertical: spacing.sm, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  threatDomain: { color: colors.textSecondary, fontSize: fontSize.md },
  threatCount: { color: colors.dangerous, fontWeight: "700", fontSize: fontSize.md },
  shareBtn: {
    backgroundColor: colors.bgCard, borderRadius: 12, padding: 16,
    alignItems: "center", borderWidth: 1, borderColor: colors.border,
    marginBottom: spacing.md,
  },
  shareBtnText: { color: colors.primary, fontWeight: "700", fontSize: fontSize.md },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm },
});
