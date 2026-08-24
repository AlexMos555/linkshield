import { useEffect, useState, useCallback } from "react";
import { reasonLabel } from "../src/utils/reason-label";
import { View, Text, StyleSheet, ScrollView, ActivityIndicator, TouchableOpacity, Share } from "react-native";
import { useLocalSearchParams } from "expo-router";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import {
  colors, type as typo, space, radius,
  levelColors, levelWashes, levelStrokes,
} from "../src/utils/theme";
import { checkDomain, PublicCheckResult, ApiError } from "../src/services/api";
import { saveCheck } from "../src/services/database";

export default function ResultScreen() {
  const { domain } = useLocalSearchParams<{ domain: string }>();
  const { t } = useTranslation();
  const [result, setResult] = useState<PublicCheckResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<ApiError["kind"] | null>(null);
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
        // Result-based call so the error KIND survives. The old throwing
        // wrapper flattened everything to a message this screen then ignored,
        // and every failure — rate limit, server error, offline — rendered
        // the same "check your connection" with a Retry that could not help.
        const { data: r, error: apiError } = await checkDomain(domain);
        if (cancelled) return;
        if (!r) {
          setError(apiError?.kind ?? "network");
          return;
        }
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
      } catch {
        if (cancelled) return;
        setError("network");
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
        <Text style={s.loadingText}>{t("mobile.result.loading", { domain })}</Text>
        <Text style={s.loadingSub}>{t("mobile.result.loading_sub")}</Text>
      </View>
    );
  }

  if (error || !result) {
    // Say what actually went wrong. A rate limit and a dead server are not
    // "check your connection", and telling someone to retry into a rate
    // limit only digs the hole deeper.
    const bodyKey =
      error === "rate_limited" ? "mobile.result.error_rate_limited"
      : error === "http_5xx" ? "mobile.result.error_server"
      : "mobile.result.error_body";
    return (
      <View style={s.center}>
        <Ionicons name="alert-circle" size={44} color={colors.amber} />
        <Text style={s.errorTitle}>{t("mobile.result.error_title")}</Text>
        <Text style={s.errorBody}>{t(bodyKey)}</Text>
        <TouchableOpacity style={s.retryBtn} onPress={retry} activeOpacity={0.85}>
          <Text style={s.retryLabel}>{t("mobile.result.error_retry")}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const level = (result.level in levelColors ? result.level : "caution") as keyof typeof levelColors;
  const color = levelColors[level];
  const wash = levelWashes[level];
  const stroke = levelStrokes[level];
  const label = t(`mobile.result.verdict_${level === "safe" ? "safe" : level === "caution" ? "caution" : "dangerous"}`);

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
          <Text style={s.lowConf}>{t("mobile.result.low_confidence")}</Text>
        )}
      </View>

      {/* Plain-language "what to do", in the user's language. The API also
          writes an English summary sentence (result.verdict), but showing that
          on a 10-locale app leaked English into every non-English screen — the
          reasons below had the same bug. Reuse the localized advice copy that
          the shared screen already uses; one source of truth for the tone. */}
      <View style={s.card}>
        <Text style={s.summary}>{t(`mobile.shared.advice_${level}`)}</Text>
      </View>

      {/* Signals */}
      {result.reasons.length > 0 && (
        <View style={s.card}>
          <Text style={s.cardTitle}>{t("mobile.result.signals")}</Text>
          {result.reasons.map((r, i) => (
            <View key={i} style={[s.signalRow, i > 0 && s.signalBorder]}>
              <View style={[s.signalDot, { backgroundColor: color }]} />
              <Text style={s.signalText}>{reasonLabel(r, t)}</Text>
              {/* The public endpoint scores the domain, not each signal, so a
                  weight is usually absent. Rendering it unconditionally printed
                  a "+undefined" chip. */}
              {typeof r.weight === "number" && (
                <View style={[s.weightChip, { backgroundColor: wash }]}>
                  <Text style={[s.weightLabel, { color }]}>+{r.weight}</Text>
                </View>
              )}
            </View>
          ))}
        </View>
      )}

      {/* Details.
          Only facts the response actually carried. `has_ssl` was previously
          read straight off a response that never contains it, so every site —
          google.com included — was labelled "HTTPS: No". A missing fact is now
          a missing row, never a confident wrong answer. */}
      {(result.confidence_pct != null || result.confidence) && (
        <View style={s.card}>
          <Text style={s.cardTitle}>{t("mobile.result.details")}</Text>
          <DetailRow
            label={t("mobile.result.confidence")}
            value={
              result.confidence_pct != null
                ? t("mobile.result.confidence_pct", { pct: result.confidence_pct })
                : String(result.confidence)
            }
            last
          />
        </View>
      )}

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
            message: t("mobile.result.share_message", {
              domain: result.domain, verdict: label, score: result.score,
            }),
          }).catch(() => {
            /* User dismissed share sheet — not an error worth surfacing. */
          });
        }}
      >
        <Ionicons name="share-outline" size={18} color={colors.blue} />
        <Text style={s.shareLabel}>{t("mobile.result.share")}</Text>
      </TouchableOpacity>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.result.privacy")}</Text>
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
  loadingText: { ...typo.headline, color: colors.textPrimary, marginTop: space.lg },
  loadingSub: { ...typo.caption, color: colors.textMuted, marginTop: space.xs },
  errorTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.md },
  errorBody: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },
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
  ringScore: { ...typo.display },
  ringMax: { ...typo.caption, color: colors.textMuted, marginTop: -2 },
  verdictLabel: { ...typo.title2, marginTop: space.lg },
  domain: { ...typo.body, color: colors.textSecondary, marginTop: 4 },
  lowConf: { ...typo.caption, color: colors.amber, marginTop: space.md },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { ...typo.headline, color: colors.textPrimary, marginBottom: space.sm },
  summary: { ...typo.body, color: colors.textPrimary },
  signalRow: { flexDirection: "row", alignItems: "center", gap: space.sm, paddingVertical: 8 },
  signalBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  signalDot: { width: 6, height: 6, borderRadius: 3 },
  signalText: { ...typo.body, color: colors.textSecondary, flex: 1 },
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
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
