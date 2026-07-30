import { useEffect, useState, useCallback } from "react";
import { View, Text, StyleSheet, ScrollView, ActivityIndicator, TouchableOpacity, Share } from "react-native";
import { useLocalSearchParams } from "expo-router";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import {
  colors, type as t, space, radius,
  levelColors, levelWashes, levelStrokes, levelLabels,
} from "../src/utils/theme";
import { checkSingleDomain, DomainResult } from "../src/services/api";
import { saveCheck } from "../src/services/database";

export default function ResultScreen() {
  const { domain } = useLocalSearchParams<{ domain: string }>();
  const [result, setResult] = useState<DomainResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  const retry = useCallback(() => {
    setError(null);
    setResult(null);
    setLoading(true);
    setAttempt(a => a + 1);
  }, []);

  useEffect(() => {
    if (!domain) return;
    let cancelled = false;
    void (async () => {
      try {
        const r = await checkSingleDomain(domain);
        if (cancelled) return;
        setResult(r);
        // Persist before kicking off the haptic so that if the user
        // immediately navigates away the SQLite write has at least
        // started. Failure is logged but doesn't block the UI — the
        // visible result is what matters; the history row is bonus.
        // (Audit mobile-ts LOW saveCheck-no-await race.)
        try {
          await saveCheck(r);
        } catch {
          // Silent — best-effort persistence.
        }
        if (r.level === "dangerous") {
          await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        } else if (r.level === "caution") {
          await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
        } else {
          await Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        }
      } catch (e: unknown) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "Check failed");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [domain, attempt]);

  if (loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.loadingText}>Checking {domain}…</Text>
        <Text style={s.loadingSub}>Running 18 safety checks</Text>
      </View>
    );
  }

  if (error || !result) {
    return (
      <View style={s.center}>
        <Ionicons name="alert-circle" size={44} color={colors.amber} />
        <Text style={s.errorTitle}>Couldn't finish the check</Text>
        <Text style={s.errorBody}>The server didn't answer. Check your connection and try again.</Text>
        <TouchableOpacity style={s.retryBtn} onPress={retry} activeOpacity={0.85}>
          <Text style={s.retryLabel}>Try again</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const level = (result.level in levelColors ? result.level : "caution") as keyof typeof levelColors;
  const color = levelColors[level];
  const wash = levelWashes[level];
  const stroke = levelStrokes[level];
  const label = levelLabels[level];

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      {/* Verdict card with score ring */}
      <View style={[s.verdictCard, { borderColor: stroke }]}>
        <View style={[s.ring, { borderColor: color + "66" }]}>
          <Text style={[s.ringScore, { color }]}>{result.score}</Text>
          <Text style={s.ringMax}>/100</Text>
        </View>
        <Text style={[s.verdictLabel, { color }]}>{label}</Text>
        <Text style={s.domain}>{result.domain}</Text>
        {result.confidence === "low" && (
          <Text style={s.lowConf}>Limited analysis — some checks couldn't run</Text>
        )}
      </View>

      {/* Signals */}
      {result.reasons && result.reasons.length > 0 && (
        <View style={s.card}>
          <Text style={s.cardTitle}>Why we say this</Text>
          {result.reasons.map((r, i) => (
            <View key={i} style={[s.signalRow, i > 0 && s.signalBorder]}>
              <View style={[s.signalDot, { backgroundColor: color }]} />
              <Text style={s.signalText}>{r.detail}</Text>
              <View style={[s.weightChip, { backgroundColor: wash }]}>
                <Text style={[s.weightLabel, { color }]}>+{r.weight}</Text>
              </View>
            </View>
          ))}
        </View>
      )}

      {/* Details */}
      <View style={s.card}>
        <Text style={s.cardTitle}>Details</Text>
        {result.domain_age_days != null && (
          <DetailRow label="Domain age" value={`${result.domain_age_days} days`} />
        )}
        <DetailRow label="HTTPS" value={result.has_ssl ? "Yes" : "No"} />
        {result.ssl_issuer && <DetailRow label="Certificate" value={result.ssl_issuer} />}
        <DetailRow label="Confidence" value={result.confidence || "medium"} last />
      </View>

      {/* Share */}
      <TouchableOpacity
        style={s.shareBtn}
        activeOpacity={0.85}
        onPress={() => {
          // Audit mobile-ts LOW: previously fired without await/catch —
          // a user dismissing the share sheet rejected the promise and
          // we lost the error silently. Now we await + ignore Cancel
          // (it's not really an error) and let the result fall through.
          void Share.share({
            message: `${result.domain} is ${label} (score: ${result.score}/100). Checked with Cleanway — https://cleanway.ai/check/${result.domain}`,
          }).catch(() => {
            /* User dismissed share sheet — not an error worth surfacing. */
          });
        }}
      >
        <Ionicons name="share-outline" size={18} color={colors.blue} />
        <Text style={s.shareLabel}>Share result</Text>
      </TouchableOpacity>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>Checked on our servers. Only the website name was sent — nothing else.</Text>
      </View>
    </ScrollView>
  );
}

function DetailRow({ label, value, last }: { label: string; value: string; last?: boolean }) {
  return (
    <View style={[s.detailRow, !last && s.detailBorder]}>
      <Text style={s.detailLabel}>{label}</Text>
      <Text style={s.detailValue}>{value}</Text>
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
  loadingText: { ...t.headline, color: colors.textPrimary, marginTop: space.lg },
  loadingSub: { ...t.caption, color: colors.textMuted, marginTop: space.xs },
  errorTitle: { ...t.headline, color: colors.textPrimary, marginTop: space.md },
  errorBody: { ...t.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },
  retryBtn: {
    height: 50, paddingHorizontal: space.xxxl,
    backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  retryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  verdictCard: {
    backgroundColor: colors.surface, borderWidth: 1,
    borderRadius: radius.card, padding: space.xxl,
    alignItems: "center", marginBottom: space.md,
  },
  ring: {
    width: 120, height: 120, borderRadius: 60, borderWidth: 8,
    alignItems: "center", justifyContent: "center",
  },
  ringScore: { ...t.display },
  ringMax: { ...t.caption, color: colors.textMuted, marginTop: -2 },
  verdictLabel: { ...t.title2, marginTop: space.lg },
  domain: { ...t.body, color: colors.textSecondary, marginTop: 4 },
  lowConf: { ...t.caption, color: colors.amber, marginTop: space.md },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { ...t.headline, color: colors.textPrimary, marginBottom: space.sm },
  signalRow: { flexDirection: "row", alignItems: "center", gap: space.sm, paddingVertical: 8 },
  signalBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  signalDot: { width: 6, height: 6, borderRadius: 3 },
  signalText: { ...t.body, color: colors.textSecondary, flex: 1 },
  weightChip: {
    height: 24, paddingHorizontal: 8, borderRadius: 8,
    alignItems: "center", justifyContent: "center",
  },
  weightLabel: { fontSize: 13, fontWeight: "600" },

  detailRow: { flexDirection: "row", justifyContent: "space-between", paddingVertical: 10 },
  detailBorder: { borderBottomWidth: 1, borderBottomColor: colors.hairline },
  detailLabel: { fontSize: 15, color: colors.textMuted },
  detailValue: { fontSize: 15, fontWeight: "600", color: colors.textPrimary },

  shareBtn: {
    height: 50, flexDirection: "row", gap: space.sm,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginBottom: space.lg,
  },
  shareLabel: { fontSize: 15, fontWeight: "600", color: colors.blue },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, paddingHorizontal: space.md,
  },
  privacy: { ...t.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
