import { useState, useEffect, useRef, useCallback } from "react";
import {
  View, Text, StyleSheet, ScrollView, Animated, Easing, AccessibilityInfo, TouchableOpacity,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../../src/utils/theme";
import { getStats, getWeeklyStats, getActiveDaysThisWeek } from "../../src/services/database";

/**
 * Habit score (docs/design/shield-checklist-design.md §1 tokens, §5 motion, §6 a11y).
 *
 * Honesty contract: the number is one counted fact restated as a percentage —
 * the days you checked a link, out of the last 7. It is NOT a measure of how
 * safe the person is, and the copy says so on screen.
 *
 * It used to be a weighted formula: +50 base, +10 "app installed", +15 for a
 * week with no dangerous links, -3 per dangerous link. That awarded 75/100 and
 * the label "Good habits" to someone who had never checked anything (an empty
 * week trivially has no dangerous links), and it docked points from users for
 * *finding* a bad site — punishing the exact behaviour the app asks for. Both
 * are gone: nothing here is weighted, and nothing is invented.
 */

interface Fact {
  titleKey: string;
  detailKey: string;
  params?: Record<string, number>;
  icon: keyof typeof Ionicons.glyphMap;
  tone?: "warn";
}

export default function ScoreScreen() {
  const { t } = useTranslation();
  const router = useRouter();
  const [loaded, setLoaded] = useState(false);
  const [totalChecks, setTotalChecks] = useState(0);
  const [activeDays, setActiveDays] = useState(0);
  const [facts, setFacts] = useState<Fact[]>([]);

  useFocusEffect(useCallback(() => {
    void load();
  }, []));

  async function load() {
    const [stats, weekly, days] = await Promise.all([
      getStats(), getWeeklyStats(), getActiveDaysThisWeek(),
    ]);

    const rows: Fact[] = [
      { titleKey: "mobile.score.fact.days_title", detailKey: "mobile.score.fact.days_detail",
        params: { days }, icon: "calendar-outline" },
      { titleKey: "mobile.score.fact.total_title", detailKey: "mobile.score.fact.total_detail",
        params: { total: stats.total_checks }, icon: "link-outline" },
    ];
    // Reported, never scored. Running into a bad site is exposure, not a habit,
    // and checking it was the right move.
    if (weekly.threats_blocked > 0) {
      rows.push({
        titleKey: "mobile.score.fact.dangerous_title",
        detailKey: "mobile.score.fact.dangerous_detail",
        params: { num: weekly.threats_blocked }, icon: "alert-circle-outline", tone: "warn",
      });
    }

    setTotalChecks(stats.total_checks);
    setActiveDays(days);
    setFacts(rows);
    setLoaded(true);
  }

  if (!loaded) return <View style={s.container} />;

  // Nothing checked ever: there is no habit to measure, so show none. The old
  // screen printed a confident 75/100 here.
  if (totalChecks === 0) {
    return (
      <ScrollView style={s.container} contentContainerStyle={s.content}>
        <View style={s.emptyCard}>
          <Ionicons name="calendar-outline" size={26} color={colors.textSecondary} />
          <Text style={s.emptyTitle}>{t("mobile.score.empty_title")}</Text>
          <Text style={s.emptyBody}>{t("mobile.score.empty_body")}</Text>
          <TouchableOpacity
            style={s.emptyCta}
            onPress={() => router.push("/check")}
            activeOpacity={0.85}
            accessibilityRole="button"
          >
            <Text style={s.emptyCtaLabel}>{t("mobile.score.empty_cta")}</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    );
  }

  const band = bandFor(activeDays);

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <ScoreRing days={activeDays} band={band} t={t} />

      <View style={s.honestyRow}>
        <Ionicons name="information-circle-outline" size={13} color={colors.textSecondary} />
        <Text style={s.honesty}>{t("mobile.score.honesty")}</Text>
      </View>

      <Text style={[sectionHeader, s.sectionHeader]}>{t("mobile.score.breakdown")}</Text>

      <View style={s.card}>
        {facts.map((f, i) => (
          <FactRow key={f.titleKey} fact={f} first={i === 0} t={t} />
        ))}
      </View>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.score.privacy")}</Text>
      </View>
    </ScrollView>
  );
}

type Band = {
  labelKey: string;
  color: string;
  stroke: string;
  icon: keyof typeof Ionicons.glyphMap;
};

const GREEN = { color: colors.green, stroke: colors.greenStroke, icon: "checkmark-circle-outline" } as const;

/**
 * Banded on days checked out of 7. Zero days is styled neutral, not red — a
 * quiet week is a habit worth nudging, not a danger state, and red here would
 * read as "you are unprotected", which this screen does not know.
 */
function bandFor(days: number): Band {
  if (days >= 5) return { labelKey: "mobile.score.band_great", ...GREEN };
  if (days >= 3) return { labelKey: "mobile.score.band_good", ...GREEN };
  if (days >= 1) {
    return { labelKey: "mobile.score.band_fair", color: colors.amber, stroke: colors.amberStroke, icon: "alert-circle-outline" };
  }
  return { labelKey: "mobile.score.band_low", color: colors.textSecondary, stroke: colors.stroke, icon: "ellipse-outline" };
}

function ScoreRing({ days, band, t }: { days: number; band: Band; t: TFunction }) {
  // The percentage is days/7 restated, nothing more. Kept because a ring reads
  // faster than a fraction, but the exact fraction sits right underneath it.
  const score = Math.round((days / 7) * 100);
  const [shown, setShown] = useState(0);
  const [reduceMotion, setReduceMotion] = useState(false);
  const progress = useRef(new Animated.Value(0)).current;
  const scale = useRef(new Animated.Value(0.96)).current;

  useEffect(() => {
    AccessibilityInfo.isReduceMotionEnabled().then(setReduceMotion).catch(() => {});
  }, []);

  useEffect(() => {
    // Listener + Math.round: interpolating an Animated.Value straight into a
    // string used to render fractional digits ("43.7") mid-count.
    const id = progress.addListener(({ value }) => setShown(Math.round(value)));
    if (reduceMotion) {
      progress.setValue(score);
      scale.setValue(1);
    } else {
      Animated.parallel([
        Animated.timing(progress, {
          toValue: score, duration: 600, easing: Easing.out(Easing.cubic), useNativeDriver: false,
        }),
        Animated.spring(scale, { toValue: 1, friction: 7, useNativeDriver: true }),
      ]).start();
    }
    return () => progress.removeListener(id);
  }, [score, reduceMotion]);

  const label = t(band.labelKey);

  return (
    <Animated.View
      style={[s.scoreCard, { borderColor: band.stroke, transform: [{ scale }] }]}
      accessibilityRole="image"
      accessibilityLabel={t("mobile.score.ring_a11y", { days, band: label })}
    >
      <View style={[s.ring, { borderColor: band.color + "66" }]}>
        <Text style={[s.ringScore, { color: band.color }]}>{shown}</Text>
        <Text style={s.ringMax}>/100</Text>
      </View>
      <View style={s.bandRow}>
        <Ionicons name={band.icon} size={18} color={band.color} />
        <Text style={[s.bandLabel, { color: band.color }]}>{label}</Text>
      </View>
      <Text style={s.subtitle}>{t("mobile.score.subtitle", { days })}</Text>
    </Animated.View>
  );
}

function FactRow({ fact, first, t }: { fact: Fact; first: boolean; t: TFunction }) {
  const color = fact.tone === "warn" ? colors.amber : colors.textMuted;
  return (
    <View
      style={[s.factorRow, !first && s.factorBorder]}
      accessible
      accessibilityLabel={`${t(fact.titleKey)}. ${t(fact.detailKey, fact.params)}`}
    >
      <Ionicons name={fact.icon} size={16} color={color} />
      <View style={s.factorInfo}>
        <Text style={s.factorLabel}>{t(fact.titleKey)}</Text>
        <Text style={s.factorDetail}>{t(fact.detailKey, fact.params)}</Text>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },

  scoreCard: {
    backgroundColor: colors.surface, borderWidth: 1,
    borderRadius: radius.card, padding: space.xxl,
    alignItems: "center",
  },
  ring: {
    width: 120, height: 120, borderRadius: radius.full, borderWidth: 8,
    alignItems: "center", justifyContent: "center",
  },
  ringScore: { ...typo.display },
  ringMax: { ...typo.caption, color: colors.textMuted, marginTop: -2 },
  bandRow: { flexDirection: "row", alignItems: "center", gap: 6, marginTop: space.lg },
  bandLabel: { ...typo.title2 },
  subtitle: { ...typo.body, color: colors.textSecondary, marginTop: 4, textAlign: "center" },

  honestyRow: {
    flexDirection: "row", alignItems: "flex-start", gap: 6,
    marginTop: space.md, paddingHorizontal: space.xs,
  },
  honesty: { ...typo.caption, color: colors.textSecondary, flex: 1 },

  sectionHeader: { marginTop: space.xxl + space.xs, marginBottom: space.sm },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  factorRow: { flexDirection: "row", alignItems: "center", gap: space.md, paddingVertical: 10 },
  factorBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  factorInfo: { flex: 1 },
  factorLabel: { ...typo.body, fontWeight: "600", color: colors.textPrimary },
  factorDetail: { ...typo.caption, color: colors.textSecondary, marginTop: 2 },

  emptyCard: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.xxl, alignItems: "center",
    marginTop: space.xl,
  },
  emptyTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.md },
  emptyBody: {
    ...typo.body, color: colors.textSecondary,
    textAlign: "center", marginTop: space.xs,
  },
  emptyCta: {
    height: 50, paddingHorizontal: space.xxxl, borderRadius: radius.control,
    backgroundColor: colors.blue, alignItems: "center", justifyContent: "center",
    marginTop: space.xl,
  },
  emptyCtaLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
