import { memo } from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import {
  colors, type as typo, space, radius, levelColors, levelWashes, levelStrokes,
} from "../../utils/theme";
import type { CheckItem, HistoryItem, ShieldItem, SmsItem } from "../../utils/history-model";
import { CHECK_LEVEL_KEYS, SHIELD_KIND_KEYS, SHIELD_SOURCE_KEYS } from "../../utils/history-labels";
import { VERDICT_KEYS } from "../../utils/message-labels";
import { relativeTime } from "../../utils/relative-time";

export type Tone = "danger" | "caution" | "safe" | "muted";

/** Colour sets per tone; the detail sheet uses the same ones as the rows. */
export const HISTORY_TONES: Record<Tone, { color: string; wash: string; stroke: string }> = {
  danger: { color: levelColors.dangerous, wash: levelWashes.dangerous, stroke: levelStrokes.dangerous },
  caution: { color: levelColors.caution, wash: levelWashes.caution, stroke: levelStrokes.caution },
  safe: { color: levelColors.safe, wash: levelWashes.safe, stroke: levelStrokes.safe },
  muted: { color: colors.textSecondary, wash: colors.surfaceRaised, stroke: colors.stroke },
};

export function shieldTone(item: ShieldItem): Tone {
  return item.kind === "blocked" ? "danger" : item.kind === "warned" ? "caution" : "muted";
}

export function shieldIcon(item: ShieldItem): keyof typeof Ionicons.glyphMap {
  return item.kind === "blocked" ? "shield-checkmark-outline"
    : item.kind === "warned" ? "shield-half-outline"
    : "shield-outline";
}

/** "source · time", dropping whichever part is missing. */
function metaLine(parts: string[]): string {
  return parts.filter(Boolean).join(" · ");
}

interface RowFrameProps {
  tone: Tone;
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  what: string;
  meta: string;
  a11yLabel: string;
  onPress?: () => void;
  a11yHint?: string;
}

/**
 * One shape for every row: what (the site, or "SMS check"), what happened in
 * plain words — the only coloured line, never colour alone — and where it
 * came from with the time. A tappable row has a chevron; the others do not.
 */
function RowFrame({ tone, icon, title, what, meta, a11yLabel, onPress, a11yHint }: RowFrameProps) {
  const { color, wash, stroke } = HISTORY_TONES[tone];
  const body = (
    <>
      <View style={[s.rowIcon, { backgroundColor: wash, borderColor: stroke }]}>
        <Ionicons name={icon} size={22} color={color} />
      </View>
      <View style={s.rowText}>
        <Text style={s.title} numberOfLines={1}>{title}</Text>
        <Text style={[s.what, { color }]}>{what}</Text>
        {meta !== "" && <Text style={s.meta} numberOfLines={2}>{meta}</Text>}
      </View>
    </>
  );
  if (!onPress) {
    return (
      <View style={s.row} accessible accessibilityLabel={a11yLabel}>
        {body}
      </View>
    );
  }
  return (
    <TouchableOpacity
      style={s.row}
      onPress={onPress}
      activeOpacity={0.85}
      accessibilityRole="button"
      accessibilityLabel={a11yLabel}
      accessibilityHint={a11yHint}
    >
      {body}
      <Ionicons name="chevron-forward" size={18} color={colors.textMuted} />
    </TouchableOpacity>
  );
}

/** Something a shield did on its own. Tapping opens why, when, and the rescue. */
const ShieldRow = memo(function ShieldRow({ item, onOpen }: { item: ShieldItem; onOpen: (item: ShieldItem) => void }) {
  const { t } = useTranslation();
  const what = t(SHIELD_KIND_KEYS[item.kind]);
  const source = item.source ? t(SHIELD_SOURCE_KEYS[item.source]) : "";
  const when = relativeTime(item.ts, t);
  return (
    <RowFrame
      tone={shieldTone(item)}
      icon={shieldIcon(item)}
      title={item.domain}
      what={what}
      meta={metaLine([source, when])}
      a11yLabel={[item.domain, what, source, when].filter(Boolean).join(". ")}
      a11yHint={t("mobile.history.row_open_hint")}
      onPress={() => onOpen(item)}
    />
  );
});

/**
 * A link the person checked. The verdict is the "what happened"; the score
 * chip stays, read out with its meaning — a bare "85" tells a screen reader
 * user nothing about which direction is bad.
 */
const CheckRow = memo(function CheckRow({ item }: { item: CheckItem }) {
  const { t } = useTranslation();
  const tone: Tone = item.level === "dangerous" ? "danger"
    : item.level === "caution" ? "caution"
    : item.level === "safe" ? "safe"
    : "muted";
  const icon: keyof typeof Ionicons.glyphMap = item.level === "dangerous" ? "close-circle-outline"
    : item.level === "caution" ? "alert-circle-outline"
    : item.level === "safe" ? "checkmark-circle-outline"
    : "help-circle-outline";
  const what = item.level ? t(CHECK_LEVEL_KEYS[item.level]) : t("mobile.history.verdict_unknown");
  const source = t("mobile.history.source.manual");
  const when = relativeTime(item.ts, t);
  const { color, wash, stroke } = HISTORY_TONES[tone];
  return (
    <View
      style={s.row}
      accessible
      accessibilityLabel={[
        item.domain, what, t("mobile.history.score_a11y", { score: item.score }), source, when,
      ].filter(Boolean).join(". ")}
    >
      <View style={[s.rowIcon, { backgroundColor: wash, borderColor: stroke }]}>
        <Ionicons name={icon} size={22} color={color} />
      </View>
      <View style={s.rowText}>
        <Text style={s.title} numberOfLines={1}>{item.domain}</Text>
        <Text style={[s.what, { color }]}>{what}</Text>
        <Text style={s.meta} numberOfLines={1}>{metaLine([source, when])}</Text>
      </View>
      <View style={[s.scoreChip, { backgroundColor: wash, borderColor: stroke }]}>
        <Text style={[s.scoreValue, { color }]}>{item.score}</Text>
      </View>
    </View>
  );
});

/**
 * A message check. The row never had the text — only the verdict and the link
 * hosts were saved — so it is not tappable: there is nothing to reopen. Never
 * "safe": the calmest verdict is "no signs of fraud found".
 */
const SmsRow = memo(function SmsRow({ item }: { item: SmsItem }) {
  const { t } = useTranslation();
  const tone: Tone = item.verdict === "dangerous" ? "danger" : item.verdict === "caution" ? "caution" : "muted";
  const title = t("mobile.message.history_title");
  const what = item.verdict ? t(VERDICT_KEYS[item.verdict]) : t("mobile.history.verdict_unknown");
  const hosts = item.hosts.join(", ");
  const when = relativeTime(item.ts, t);
  return (
    <RowFrame
      tone={tone}
      icon="chatbubble-ellipses-outline"
      title={title}
      what={what}
      meta={metaLine([hosts, when])}
      a11yLabel={[title, what, hosts, when].filter(Boolean).join(". ")}
    />
  );
});

export function HistoryRow({ item, onOpenShield }: { item: HistoryItem; onOpenShield: (item: ShieldItem) => void }) {
  if (item.type === "shield") return <ShieldRow item={item} onOpen={onOpenShield} />;
  if (item.type === "sms") return <SmsRow item={item} />;
  return <CheckRow item={item} />;
}

const s = StyleSheet.create({
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
  title: { ...typo.headline, color: colors.textPrimary },
  what: { ...typo.caption, fontWeight: "600", marginTop: 2 },
  meta: { ...typo.caption, color: colors.textMuted, marginTop: 1 },
  scoreChip: {
    minWidth: 44, height: 28, paddingHorizontal: space.sm, borderWidth: 1,
    borderRadius: radius.chip, alignItems: "center", justifyContent: "center",
  },
  scoreValue: { fontSize: 15, fontWeight: "600" },
});
