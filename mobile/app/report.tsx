import { useState, useEffect } from "react";
import { View, Text, StyleSheet, ScrollView, TouchableOpacity, Share } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../src/utils/theme";
import { getWeeklyStats, getRecentChecks } from "../src/services/database";

/**
 * Weekly report.
 *
 * Honesty contract: every number here comes from the check history stored in
 * SQLite on this phone (getWeeklyStats / getRecentChecks). There is no
 * server-side aggregation and no comparison against other users, so the copy
 * says "links you checked in this app" and nothing more. The old
 * "Safer than N% of users" hero was a locally invented number with no
 * population behind it — removed rather than restyled.
 */

type FlaggedDomain = { domain: string; count: number };

export default function ReportScreen() {
  const { t } = useTranslation();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0 });
  const [flagged, setFlagged] = useState<FlaggedDomain[]>([]);

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

    setFlagged(sorted);
  }

  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 86400000);
  const period = t("mobile.report.period", {
    from: weekAgo.toLocaleDateString(),
    to: now.toLocaleDateString(),
  });

  async function shareReport() {
    await Share.share({
      message: t("mobile.report.share_message", {
        checked: stats.total_checks,
        flagged: stats.threats_blocked,
      }),
    });
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.title}>{t("mobile.report.title")}</Text>
      <Text style={s.period}>{period}</Text>

      <Text style={[s.sectionHeader, s.firstSection]}>{t("mobile.report.summary_header")}</Text>
      <View style={s.statsRow}>
        <StatCard
          icon="link-outline"
          tint={colors.blue}
          value={stats.total_checks}
          label={t("mobile.report.checked_label")}
        />
        <StatCard
          icon="alert-circle-outline"
          tint={colors.danger}
          value={stats.threats_blocked}
          label={t("mobile.report.flagged_label")}
        />
      </View>
      <Text style={s.note}>{t("mobile.report.summary_note")}</Text>

      <Text style={s.sectionHeader}>{t("mobile.report.flagged_header")}</Text>
      <View style={s.card}>
        {stats.total_checks === 0 ? (
          <EmptyState
            icon="document-text-outline"
            tint={colors.textMuted}
            title={t("mobile.report.empty_title")}
            body={t("mobile.report.empty_body")}
          />
        ) : flagged.length === 0 ? (
          <EmptyState
            icon="shield-checkmark-outline"
            tint={colors.green}
            title={t("mobile.report.clean_title")}
            body={t("mobile.report.clean_body")}
          />
        ) : (
          flagged.map((f, i) => (
            <View key={f.domain} style={[s.row, i > 0 && s.rowBorder]}>
              <Ionicons name="alert-circle-outline" size={16} color={colors.amber} />
              <Text style={s.rowDomain} numberOfLines={1}>{f.domain}</Text>
              <Text style={s.rowCount}>{t("mobile.report.times", { count: f.count })}</Text>
            </View>
          ))
        )}
      </View>
      {flagged.length > 0 && <Text style={s.note}>{t("mobile.report.flagged_note")}</Text>}

      <TouchableOpacity
        style={s.shareBtn}
        activeOpacity={0.85}
        accessibilityRole="button"
        onPress={() => {
          void shareReport().catch(() => {
            /* User dismissed the share sheet — not an error worth surfacing. */
          });
        }}
      >
        <Ionicons name="share-outline" size={18} color={colors.blue} />
        <Text style={s.shareLabel}>{t("mobile.report.share")}</Text>
      </TouchableOpacity>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.report.privacy")}</Text>
      </View>
    </ScrollView>
  );
}

function StatCard({
  icon, tint, value, label,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  tint: string;
  value: number;
  label: string;
}) {
  return (
    <View style={s.statCard}>
      <Ionicons name={icon} size={18} color={tint} />
      <Text style={s.statValue}>{value}</Text>
      <Text style={s.statLabel}>{label}</Text>
    </View>
  );
}

function EmptyState({
  icon, tint, title, body,
}: {
  icon: keyof typeof Ionicons.glyphMap;
  tint: string;
  title: string;
  body: string;
}) {
  return (
    <View style={s.empty}>
      <Ionicons name={icon} size={22} color={tint} />
      <Text style={s.emptyTitle}>{title}</Text>
      <Text style={s.emptyBody}>{body}</Text>
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },

  title: { ...typo.title1, color: colors.textPrimary },
  period: { ...typo.caption, color: colors.textMuted, marginTop: 2 },

  sectionHeader: { ...sectionHeader, marginTop: space.xxl, marginBottom: space.sm },
  firstSection: { marginTop: space.xl + space.sm },

  statsRow: { flexDirection: "row", gap: space.md },
  statCard: {
    flex: 1, alignItems: "flex-start",
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  statValue: { ...typo.title1, color: colors.textPrimary, marginTop: space.sm },
  statLabel: { ...typo.caption, color: colors.textSecondary, marginTop: 2 },

  note: { ...typo.caption, color: colors.textSecondary, marginTop: space.sm },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  row: { flexDirection: "row", alignItems: "center", gap: space.sm, paddingVertical: 10 },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  rowDomain: { ...typo.body, color: colors.textPrimary, flex: 1 },
  rowCount: { ...typo.caption, color: colors.textMuted },

  empty: { alignItems: "center", paddingVertical: space.sm },
  emptyTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.sm, textAlign: "center" },
  emptyBody: { ...typo.body, color: colors.textSecondary, marginTop: space.xs, textAlign: "center" },

  shareBtn: {
    height: 50, flexDirection: "row", gap: space.sm,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.xxl,
  },
  shareLabel: { fontSize: 15, fontWeight: "600", color: colors.blue },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
