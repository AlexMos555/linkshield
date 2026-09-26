import { View, Text, StyleSheet, TouchableOpacity, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { MessageAnalysis, MessageVerdict } from "../../../modules/cleanway-vpn";
import { colors, space, radius, sectionHeader, levelColors, levelWashes, levelStrokes } from "../../utils/theme";
import {
  ADVICE_KEYS, LINKS_HEADLINE_KEYS, REASON_KEYS, SHAPE_KEYS, VERDICT_KEYS, VERDICT_SUB_KEYS,
} from "../../utils/message-labels";
import {
  adviceFor,
  linksState,
  linkVerdict,
  MAX_SHOWN_REASONS,
  type LinkCheck,
  type MessageCheckReason,
} from "../../utils/message-verdict";
import { MessageLinksCard } from "./MessageLinksCard";

interface Props {
  /** The checked text — shown back on this screen only, never stored. */
  text: string;
  fromShare: boolean;
  analysis: MessageAnalysis;
  linkChecks: Readonly<Record<string, LinkCheck>>;
  verdict: MessageVerdict;
  reasons: MessageCheckReason[];
  onRetry: () => void;
  onAnother: () => void;
  onDone: () => void;
}

type Look = { icon: keyof typeof Ionicons.glyphMap; color: string; wash: string; stroke: string };

// Status is never colour-only: each verdict pairs its hue with an icon and
// words. "No signals" gets no green — it is not a clean bill of health.
const LOOKS: Record<MessageVerdict, Look> = {
  dangerous: { icon: "warning-outline", color: levelColors.dangerous, wash: levelWashes.dangerous, stroke: levelStrokes.dangerous },
  caution: { icon: "alert-circle-outline", color: levelColors.caution, wash: levelWashes.caution, stroke: levelStrokes.caution },
  no_signals: { icon: "checkmark-circle-outline", color: colors.textPrimary, wash: colors.surface, stroke: colors.stroke },
};

// "No signs" with a link we have not checked (yet) gets no tick at all.
const UNCHECKED_LOOK: Look = { icon: "help-circle-outline", color: colors.textPrimary, wash: colors.surface, stroke: colors.stroke };

const RETRYABLE = new Set(["rate_limited", "offline", "timeout", "failed"]);

export function MessageResult(props: Props) {
  const { text, fromShare, analysis, linkChecks, verdict, reasons, onRetry, onAnother, onDone } = props;
  const { t } = useTranslation();
  const links = linksState(analysis.links, linkChecks);
  // A calm verdict never stands in for a link check: while a link is being
  // checked, or when one could not be, the headline says so instead.
  const pending = verdict === "no_signals" && (links === "checking" || links === "unchecked") ? links : null;
  const look = pending ? UNCHECKED_LOOK : LOOKS[verdict];
  const verdictLabel = t(pending ? LINKS_HEADLINE_KEYS[pending].title : VERDICT_KEYS[verdict]);
  const verdictSub = t(pending ? LINKS_HEADLINE_KEYS[pending].sub : VERDICT_SUB_KEYS[verdict]);
  const shown = reasons.slice(0, MAX_SHOWN_REASONS);
  // Native never pairs a legitimate shape with "dangerous"; a server answer
  // that raised the verdict must not leave "looks like a pickup code" beside it.
  const shape = verdict === "no_signals" ? analysis.legitShape : null;
  const advice = adviceFor({
    verdict, reasons, hasLinks: analysis.links.length > 0, hasPhones: analysis.phones.length > 0,
    linksUnchecked: pending !== null,
  });
  const verdicts = analysis.links.map((l) => linkVerdict(l, linkChecks));
  const canRetry = !verdicts.includes("checking") && verdicts.some((v) => RETRYABLE.has(v));

  return (
    <>
      <Text style={s.eyebrow}>{t(fromShare ? "mobile.message.eyebrow_shared" : "mobile.message.eyebrow")}</Text>

      <View
        style={[s.verdictCard, { backgroundColor: look.wash, borderColor: look.stroke }]}
        accessible
        accessibilityRole="summary"
        accessibilityLabel={`${verdictLabel}. ${verdictSub}`}
      >
        {pending === "checking" ? (
          <ActivityIndicator size="large" color={colors.textSecondary} />
        ) : (
          <Ionicons name={look.icon} size={44} color={look.color} />
        )}
        <Text style={[s.verdictLabel, { color: look.color }]}>{verdictLabel}</Text>
        <Text style={s.verdictSub}>{verdictSub}</Text>
      </View>

      {shown.length > 0 && (
        <View style={s.card}>
          <Text style={s.cardTitle}>{t("mobile.message.reasons_title")}</Text>
          {shown.map((code, i) => (
            <View key={code} style={[s.bulletRow, i > 0 && s.rowBorder]}>
              <View style={[s.dot, { backgroundColor: look.color }]} />
              <Text style={s.bulletText}>{t(REASON_KEYS[code])}</Text>
            </View>
          ))}
        </View>
      )}

      {shape && (
        <View style={s.card}>
          <Text style={s.bodyText}>{t(SHAPE_KEYS[shape])}</Text>
        </View>
      )}

      {analysis.links.length > 0 && (
        <MessageLinksCard
          links={analysis.links}
          linkChecks={linkChecks}
          listAvailable={analysis.listAvailable}
          listStale={analysis.listStale}
        />
      )}

      <View style={s.card}>
        <Text style={s.cardTitle}>
          {t(verdict === "no_signals" ? "mobile.message.advice_title_calm" : "mobile.message.advice_title")}
        </Text>
        {advice.map((key, i) => (
          <View key={key} style={[s.bulletRow, i > 0 && s.rowBorder]}>
            <Ionicons name="arrow-forward-circle-outline" size={20} color={colors.textSecondary} />
            <Text style={s.bulletText}>{t(ADVICE_KEYS[key])}</Text>
          </View>
        ))}
      </View>

      {analysis.truncated && <Text style={s.note}>{t("mobile.message.truncated")}</Text>}

      <View style={s.quote}>
        <Text style={s.quoteLabel}>{t("mobile.message.checked_text")}</Text>
        <Text style={s.quoteText} numberOfLines={4}>{text}</Text>
      </View>

      {canRetry && <Button label={t("mobile.message.retry_links")} onPress={onRetry} primary />}
      <Button label={t("mobile.message.another")} onPress={onAnother} primary={!canRetry} />
      <Button label={t("mobile.message.done")} onPress={onDone} />
    </>
  );
}

function Button({ label, onPress, primary = false }: { label: string; onPress: () => void; primary?: boolean }) {
  return (
    <TouchableOpacity
      style={primary ? s.primaryBtn : s.secondaryBtn}
      onPress={onPress}
      activeOpacity={0.85}
      accessibilityRole="button"
    >
      <Text style={primary ? s.primaryLabel : s.secondaryLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  eyebrow: { ...sectionHeader, marginBottom: space.sm },
  verdictCard: {
    borderWidth: 1, borderRadius: radius.card, padding: space.xl,
    alignItems: "center", marginBottom: space.md,
  },
  verdictLabel: { fontSize: 28, lineHeight: 34, fontWeight: "700", textAlign: "center", marginTop: space.md },
  verdictSub: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, textAlign: "center", marginTop: space.sm },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { fontSize: 18, lineHeight: 24, fontWeight: "600", color: colors.textPrimary, marginBottom: space.xs },
  bulletRow: { flexDirection: "row", alignItems: "flex-start", gap: space.md, paddingVertical: space.md },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  dot: { width: 8, height: 8, borderRadius: 4, marginTop: 8 },
  bulletText: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, flex: 1 },
  bodyText: { fontSize: 17, lineHeight: 24, color: colors.textPrimary },
  note: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, marginBottom: space.md, paddingHorizontal: space.xs },

  quote: {
    borderLeftWidth: 3, borderLeftColor: colors.stroke,
    paddingLeft: space.md, paddingVertical: space.xs, marginVertical: space.md,
  },
  quoteLabel: { fontSize: 13, lineHeight: 18, color: colors.textMuted },
  quoteText: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: 2 },

  primaryBtn: {
    minHeight: 54, backgroundColor: colors.blue, borderRadius: radius.control,
    paddingHorizontal: space.xl, alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  primaryLabel: { fontSize: 18, fontWeight: "600", color: "#FFFFFF", textAlign: "center" },
  secondaryBtn: {
    minHeight: 54, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control, paddingHorizontal: space.xl,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary, textAlign: "center" },
});
