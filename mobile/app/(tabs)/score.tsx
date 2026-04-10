import { useState, useEffect, useRef } from "react";
import { View, Text, StyleSheet, ScrollView, Animated, Easing } from "react-native";
import { colors, spacing, fontSize } from "../../src/utils/theme";
import { getStats, getWeeklyStats } from "../../src/services/database";

interface ScoreFactor {
  label: string;
  points: number;
  detail: string;
}

export default function ScoreScreen() {
  const [score, setScore] = useState(50);
  const [factors, setFactors] = useState<ScoreFactor[]>([]);

  useEffect(() => {
    calculateScore();
  }, []);

  async function calculateScore() {
    const stats = await getStats();
    const weekly = await getWeeklyStats();

    let s = 50;
    const f: ScoreFactor[] = [];

    // Active usage
    if (stats.total_checks > 50) {
      s += 10;
      f.push({ label: "Active user", points: 10, detail: `${stats.total_checks} total checks` });
    } else {
      f.push({ label: "Usage", points: 0, detail: `${stats.total_checks} checks (50+ for bonus)` });
    }

    // No recent threats
    if (weekly.threats_blocked === 0) {
      s += 15;
      f.push({ label: "Clean week", points: 15, detail: "No dangerous sites this week" });
    } else {
      s -= weekly.threats_blocked * 3;
      f.push({ label: "Threats", points: -weekly.threats_blocked * 3, detail: `${weekly.threats_blocked} dangerous sites visited` });
    }

    // Consistent protection
    s += 10;
    f.push({ label: "App active", points: 10, detail: "Mobile protection enabled" });

    // Base protection
    f.push({ label: "Base", points: 50, detail: "LinkShield installed" });

    s = Math.max(0, Math.min(100, s));
    setScore(s);
    setFactors(f);
  }

  const scoreColor = score >= 80 ? colors.safe : score >= 50 ? colors.caution : colors.dangerous;
  const label = score >= 80 ? "Excellent" : score >= 60 ? "Good" : score >= 40 ? "Fair" : "Needs Work";

  // Animated score counter
  const animatedScore = useRef(new Animated.Value(0)).current;
  const scaleAnim = useRef(new Animated.Value(0.8)).current;

  useEffect(() => {
    Animated.parallel([
      Animated.timing(animatedScore, {
        toValue: score,
        duration: 1200,
        easing: Easing.out(Easing.cubic),
        useNativeDriver: false,
      }),
      Animated.spring(scaleAnim, {
        toValue: 1,
        friction: 4,
        useNativeDriver: true,
      }),
    ]).start();
  }, [score]);

  const displayScore = animatedScore.interpolate({
    inputRange: [0, 100],
    outputRange: [0, 100],
    extrapolate: "clamp",
  });

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Score Circle — Animated */}
      <Animated.View style={[styles.scoreContainer, { transform: [{ scale: scaleAnim }] }]}>
        <View style={[styles.scoreCircle, { borderColor: scoreColor }]}>
          <Animated.Text style={[styles.scoreNum, { color: scoreColor }]}>
            {displayScore.interpolate({ inputRange: [0, 100], outputRange: ["0", "100"] })}
          </Animated.Text>
        </View>
        <Text style={[styles.scoreLabel, { color: scoreColor }]}>{label}</Text>
        <Text style={styles.scoreSub}>Security Score</Text>
      </Animated.View>

      {/* Breakdown */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Score Breakdown</Text>
        {factors.map((f, i) => (
          <View key={i} style={styles.factorRow}>
            <View style={styles.factorInfo}>
              <Text style={styles.factorLabel}>{f.label}</Text>
              <Text style={styles.factorDetail}>{f.detail}</Text>
            </View>
            <Text style={[
              styles.factorPoints,
              { color: f.points > 0 ? colors.safe : f.points < 0 ? colors.dangerous : colors.textMuted }
            ]}>
              {f.points > 0 ? "+" : ""}{f.points}
            </Text>
          </View>
        ))}
      </View>

      <Text style={styles.note}>{"\u{1F512}"} Score calculated 100% on your device</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  scoreContainer: { alignItems: "center", marginVertical: spacing.xl },
  scoreCircle: {
    width: 140, height: 140, borderRadius: 70, borderWidth: 4,
    alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bgCard, marginBottom: spacing.md,
  },
  scoreNum: { fontSize: 56, fontWeight: "800" },
  scoreLabel: { fontSize: fontSize.xl, fontWeight: "700" },
  scoreSub: { color: colors.textMuted, fontSize: fontSize.sm, marginTop: 4 },
  card: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  cardTitle: { color: colors.white, fontSize: fontSize.lg, fontWeight: "700", marginBottom: spacing.lg },
  factorRow: {
    flexDirection: "row", justifyContent: "space-between", alignItems: "center",
    paddingVertical: spacing.sm, borderBottomWidth: 1, borderBottomColor: colors.border,
  },
  factorInfo: { flex: 1 },
  factorLabel: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },
  factorDetail: { color: colors.textMuted, fontSize: fontSize.sm, marginTop: 2 },
  factorPoints: { fontSize: fontSize.xl, fontWeight: "800", marginLeft: spacing.md },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm, marginTop: spacing.md },
});
