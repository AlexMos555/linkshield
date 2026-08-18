import { useState, useEffect } from "react";
import {
  View, Text, StyleSheet, FlatList, TouchableOpacity, RefreshControl, ActivityIndicator,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  colors, type as typo, space, radius, sectionHeader,
  levelColors, levelWashes, levelStrokes,
} from "../../src/utils/theme";
import { getRecentChecks } from "../../src/services/database";
import { recentShieldBlocks, type ShieldRow } from "../../src/services/shield-log";

type Level = keyof typeof levelColors;

const LEVEL_ICONS: Record<Level, keyof typeof Ionicons.glyphMap> = {
  safe: "checkmark-circle-outline",
  caution: "alert-circle-outline",
  dangerous: "close-circle-outline",
};

/**
 * SQLite stores `datetime('now')` — "YYYY-MM-DD HH:MM:SS", UTC with no timezone
 * marker. Hermes either reads that as local time (hours off) or as Invalid Date,
 * so normalise it to ISO-UTC before formatting. Display only; nothing is written.
 */
function parseCheckedAt(value?: string): number {
  if (!value) return NaN;
  const sqlite = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value);
  return new Date(sqlite ? `${value.replace(" ", "T")}Z` : value).getTime();
}

function relativeTime(value: string | undefined, t: TFunction): string {
  const ms = parseCheckedAt(value);
  if (!Number.isFinite(ms)) return "";
  const minutes = Math.max(0, Math.round((Date.now() - ms) / 60000));
  if (minutes < 1) return t("mobile.history.just_now");
  if (minutes < 60) return t("mobile.history.minutes_ago", { minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t("mobile.history.hours_ago", { hours });
  const days = Math.floor(hours / 24);
  if (days === 1) return t("mobile.history.yesterday");
  if (days < 7) return t("mobile.history.days_ago", { days });
  return new Date(ms).toLocaleDateString();
}

function HistoryRow({ item }: { item: any }) {
  const { t } = useTranslation();
  const level = (item.level in levelColors ? item.level : null) as Level | null;
  const color = level ? levelColors[level] : colors.textMuted;
  const wash = level ? levelWashes[level] : colors.surfaceRaised;
  const stroke = level ? levelStrokes[level] : colors.stroke;
  const icon = level ? LEVEL_ICONS[level] : "help-circle-outline";
  const label = level
    ? t(`mobile.result.verdict_${level}`)
    : t("mobile.history.verdict_unknown");
  const when = relativeTime(item.checked_at, t);

  // One label for the whole row. The score chip used to carry its own
  // accessibilityLabel on a bare View with no `accessible` prop, so VoiceOver
  // ignored it and read the child Text — a naked "85" with no hint that it is
  // a risk score or which direction is bad. The "higher means more risk" note
  // in the list header is visual-only and never reaches a screen reader.
  return (
    <View
      style={s.row}
      accessible
      accessibilityLabel={[
        item.domain,
        label,
        t("mobile.history.score_a11y", { score: item.score }),
        when,
      ].filter(Boolean).join(". ")}
    >
      <View style={[s.rowIcon, { backgroundColor: wash, borderColor: stroke }]}>
        <Ionicons name={icon} size={22} color={color} />
      </View>
      <View style={s.rowText}>
        <Text style={s.domain} numberOfLines={1}>{item.domain}</Text>
        <View style={s.metaRow}>
          <Text style={[s.verdict, { color }]}>{label}</Text>
          {when !== "" && <Text style={s.when}>{when}</Text>}
        </View>
      </View>
      <View style={[s.scoreChip, { backgroundColor: wash, borderColor: stroke }]}>
        <Text style={[s.scoreValue, { color }]}>{item.score}</Text>
      </View>
    </View>
  );
}

/**
 * A row for something the DNS shield did on its own — no paste, no tap.
 * Two honest labels: "stopped" (site never opened) vs "flagged" (verdict came
 * after the first lookup; future ones blocked). No score chip: the shield
 * has a verdict, not a number.
 */
function ShieldHistoryRow({ item }: { item: ShieldRow }) {
  const { t } = useTranslation();
  const blocked = item.kind === "blocked";
  const color = blocked ? levelColors.dangerous : levelColors.caution;
  const wash = blocked ? levelWashes.dangerous : levelWashes.caution;
  const stroke = blocked ? levelStrokes.dangerous : levelStrokes.caution;
  const label = t(blocked ? "mobile.history.shield_blocked" : "mobile.history.shield_warned");
  const when = relativeTime(new Date(item.ts).toISOString(), t);
  return (
    <View style={s.row} accessible accessibilityLabel={[item.domain, label, when].filter(Boolean).join(". ")}>
      <View style={[s.rowIcon, { backgroundColor: wash, borderColor: stroke }]}>
        <Ionicons name={blocked ? "shield-checkmark-outline" : "shield-half-outline"} size={22} color={color} />
      </View>
      <View style={s.rowText}>
        <Text style={s.domain} numberOfLines={1}>{item.domain}</Text>
        <View style={s.metaRow}>
          <Text style={[s.verdict, { color }]}>{label}</Text>
          {when !== "" && <Text style={s.when}>{when}</Text>}
        </View>
      </View>
    </View>
  );
}

function ListHeader() {
  const { t } = useTranslation();
  return (
    <View style={s.header}>
      <Text style={s.headerTitle}>{t("mobile.history.section")}</Text>
      <Text style={s.headerHint}>{t("mobile.history.score_hint")}</Text>
    </View>
  );
}

function EmptyState() {
  const router = useRouter();
  const { t } = useTranslation();
  return (
    <View style={s.empty}>
      <View style={s.emptyIcon}>
        <Ionicons name="time-outline" size={22} color={colors.textSecondary} />
      </View>
      <Text style={s.emptyTitle}>{t("mobile.history.empty_title")}</Text>
      <Text style={s.emptyBody}>{t("mobile.history.empty_body")}</Text>
      <TouchableOpacity
        style={s.emptyBtn}
        onPress={() => router.push("/check")}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Text style={s.emptyBtnLabel}>{t("mobile.history.empty_cta")}</Text>
      </TouchableOpacity>
    </View>
  );
}

export default function HistoryScreen() {
  const { t } = useTranslation();
  const [checks, setChecks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  function load() {
    getRecentChecks(100).then((data) => {
      // Merge the shield's own log (persisted natively, so it covers blocks
      // made while the app was closed) with hand-checked links, newest first.
      const manual = (data as any[]).map((c) => ({ ...c, _kind: "check" as const, _ts: parseCheckedAt(c.checked_at) }));
      const shield = recentShieldBlocks(100).map((b) => ({ ...b, _kind: "shield" as const, _ts: b.ts }));
      const merged = [...manual, ...shield].sort((a, b) => (b._ts || 0) - (a._ts || 0));
      setChecks(merged);
      setLoading(false);
      setRefreshing(false);
    }).catch(() => { setLoading(false); setRefreshing(false); });
  }

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.loadingText}>{t("mobile.history.loading")}</Text>
      </View>
    );
  }

  if (checks.length === 0) {
    return (
      <View style={s.container}>
        <EmptyState />
      </View>
    );
  }

  return (
    <View style={s.container}>
      <FlatList
        data={checks}
        keyExtractor={(item) => item._kind === "shield" ? `shield:${item.domain}:${item.ts}` : `check:${item.id}`}
        renderItem={({ item }) => item._kind === "shield" ? <ShieldHistoryRow item={item} /> : <HistoryRow item={item} />}
        ListHeaderComponent={<ListHeader />}
        ListFooterComponent={
          <View style={s.privacyRow}>
            <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
            <Text style={s.privacy}>{t("mobile.history.privacy")}</Text>
          </View>
        }
        contentContainerStyle={s.content}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => { setRefreshing(true); load(); }}
            tintColor={colors.blue}
          />
        }
      />
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, padding: space.xxxl,
  },
  loadingText: { ...typo.body, color: colors.textSecondary, marginTop: space.lg },

  header: { marginBottom: space.md },
  headerTitle: { ...sectionHeader },
  headerHint: { ...typo.caption, color: colors.textMuted, marginTop: space.xs },

  row: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  rowIcon: {
    width: 40, height: 40, borderRadius: radius.icon, borderWidth: 1,
    alignItems: "center", justifyContent: "center",
  },
  rowText: { flex: 1 },
  domain: { ...typo.headline, color: colors.textPrimary },
  metaRow: { flexDirection: "row", alignItems: "center", gap: space.sm, marginTop: 2 },
  verdict: { ...typo.caption, fontWeight: "600" },
  when: { ...typo.caption, color: colors.textMuted },
  scoreChip: {
    minWidth: 44, height: 28, paddingHorizontal: space.sm, borderWidth: 1,
    borderRadius: radius.chip, alignItems: "center", justifyContent: "center",
  },
  scoreValue: { fontSize: 15, fontWeight: "600" },

  empty: { flex: 1, alignItems: "center", justifyContent: "center", paddingHorizontal: space.xl },
  emptyIcon: {
    width: 56, height: 56, borderRadius: radius.icon,
    backgroundColor: colors.surfaceRaised, borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center",
  },
  emptyTitle: { ...typo.title2, color: colors.textPrimary, marginTop: space.lg },
  emptyBody: {
    ...typo.body, color: colors.textSecondary,
    textAlign: "center", marginTop: space.sm,
  },
  emptyBtn: {
    height: 50, paddingHorizontal: space.xxxl, backgroundColor: colors.blue,
    borderRadius: radius.control, alignItems: "center", justifyContent: "center",
    marginTop: space.xl,
  },
  emptyBtnLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.lg, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
