import { useEffect, useState } from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../utils/theme";
import type { SmsAlertItem } from "../../utils/history-model";
import { SMS_ALERT_SOURCE_KEY, smsAlertTitle } from "../../utils/history-labels";
import { ADVICE_KEYS, REASON_KEYS, VERDICT_KEYS, VERDICT_SUB_KEYS } from "../../utils/message-labels";
import { MAX_SHOWN_REASONS, adviceFor } from "../../utils/message-verdict";
import { absoluteTime, relativeTime } from "../../utils/relative-time";
import { HISTORY_TONES, smsAlertTone } from "./HistoryRows";
import { Fact, SheetFrame, sheetStyles } from "./SheetFrame";
import { linkListAvailable, matchBlocklist } from "../../../modules/cleanway-vpn";

/**
 * What the list on the phone says about one link host now. Looked up on the
 * phone only (the same list and rules as the shields); in automatic mode not
 * even a site name leaves it. "Not listed" is never "safe".
 */
type HostStatus = "checking" | "listed" | "not_listed" | "no_list";

const HOST_LOOK: Record<HostStatus, { key: string; icon: keyof typeof Ionicons.glyphMap; color: string }> = {
  checking: { key: "mobile.message.link.checking", icon: "time-outline", color: colors.textMuted },
  listed: { key: "mobile.message.link.blocked", icon: "close-circle", color: colors.danger },
  not_listed: { key: "mobile.history.sms_alert.host_not_listed", icon: "help-circle-outline", color: colors.textSecondary },
  no_list: { key: "mobile.history.sms_alert.host_no_list", icon: "help-circle-outline", color: colors.textMuted },
};

/** Each host's status, looked up when the sheet opens for an SMS. */
function useHostStatuses(hosts: readonly string[]): readonly HostStatus[] {
  const key = hosts.join(" ");
  const [statuses, setStatuses] = useState<readonly HostStatus[]>([]);
  useEffect(() => {
    const list = key === "" ? [] : key.split(" ");
    setStatuses(list.map(() => "checking"));
    if (list.length === 0) return;
    let alive = true;
    void (async () => {
      const hasList = await linkListAvailable();
      const hits = hasList ? await Promise.all(list.map((h) => matchBlocklist(h))) : list.map(() => null);
      if (!alive) return;
      setStatuses(hits.map((hit) => (!hasList ? "no_list" : hit ? "listed" : "not_listed")));
    })();
    return () => {
      alive = false;
    };
  }, [key]);
  return statuses;
}

interface SmsAlertSheetProps {
  /** The flagged SMS to explain; null keeps the sheet closed. */
  item: SmsAlertItem | null;
  onClose: () => void;
}

/**
 * An SMS the automatic check warned about, opened from History or from the
 * warning itself: who sent it, when, why it looks like a scam, and what to do.
 *
 * The same words as a message checked by hand (reasons, advice), so a person
 * who has seen one understands the other. The text is not here — it was never
 * stored — and the sheet says so, and where the message still is. No action
 * sends anything: in automatic mode not even a site name leaves the phone.
 */
export function SmsAlertSheet({ item, onClose }: SmsAlertSheetProps) {
  const { t, i18n } = useTranslation();
  const hostStatuses = useHostStatuses(item?.hosts ?? []);
  if (!item) return null;

  const tone = HISTORY_TONES[smsAlertTone(item)];
  const when = [relativeTime(item.ts, t), absoluteTime(item.ts, i18n.language)].filter(Boolean).join(" · ");
  const reasons = item.reasons.slice(0, MAX_SHOWN_REASONS);
  // The warning already said "don't call the number": the numbers themselves
  // were never stored, so the advice assumes there was one.
  const advice = adviceFor({ verdict: item.verdict, reasons: item.reasons, hasLinks: item.hosts.length > 0, hasPhones: true });

  return (
    <SheetFrame onClose={onClose}>
      <View style={sheetStyles.headRow}>
        <View style={[sheetStyles.icon, { backgroundColor: tone.wash, borderColor: tone.stroke }]}>
          <Ionicons name="chatbubble-ellipses-outline" size={24} color={tone.color} />
        </View>
        <Text style={[sheetStyles.what, { color: tone.color }]} accessibilityRole="header">
          {t(VERDICT_KEYS[item.verdict])}
        </Text>
      </View>

      <Text style={sheetStyles.title}>{smsAlertTitle(item, t)}</Text>
      <Text style={sheetStyles.body}>{t(VERDICT_SUB_KEYS[item.verdict])}</Text>

      <View style={sheetStyles.facts}>
        {when !== "" && <Fact label={t("mobile.history.detail.when")} value={when} />}
        <Fact label={t("mobile.history.detail.by_warned")} value={t(SMS_ALERT_SOURCE_KEY)} />
      </View>

      {reasons.length > 0 && (
        <Section title={t("mobile.message.reasons_title")} lines={reasons.map((r) => t(REASON_KEYS[r]))} />
      )}
      {item.hosts.length > 0 && (
        <View style={s.section}>
          <Text style={s.sectionTitle} accessibilityRole="header">{t("mobile.message.links_title")}</Text>
          {item.hosts.map((host, i) => (
            <HostLine key={host} host={host} status={hostStatuses[i] ?? "checking"} />
          ))}
        </View>
      )}
      <Section title={t("mobile.message.advice_title")} lines={advice.map((a) => t(ADVICE_KEYS[a]))} />

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={14} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.history.sms_alert.checked_on_phone")}</Text>
      </View>

      <TouchableOpacity style={sheetStyles.primaryBtn} onPress={onClose} activeOpacity={0.85} accessibilityRole="button">
        <Text style={sheetStyles.primaryLabel}>{t("mobile.history.detail.close")}</Text>
      </TouchableOpacity>
    </SheetFrame>
  );
}

/** A link host and what the list says about it. Not selectable: a copied scam address is one paste away from a browser. */
function HostLine({ host, status }: { host: string; status: HostStatus }) {
  const { t } = useTranslation();
  const look = HOST_LOOK[status];
  const label = t(look.key);
  return (
    <View style={s.hostRow} accessible accessibilityLabel={`${host}. ${label}`}>
      <Text style={s.host}>{host}</Text>
      <View style={s.hostStatusRow}>
        <Ionicons name={look.icon} size={16} color={look.color} />
        <Text style={[s.hostStatus, { color: look.color }]}>{label}</Text>
      </View>
    </View>
  );
}

/** A heading and its lines, read out as a list. */
function Section({ title, lines }: { title: string; lines: string[] }) {
  return (
    <View style={s.section}>
      <Text style={s.sectionTitle} accessibilityRole="header">{title}</Text>
      {lines.map((line, i) => (
        <View key={`${i}:${line}`} style={s.lineRow}>
          <Text style={s.bullet} importantForAccessibility="no">•</Text>
          <Text style={s.line}>{line}</Text>
        </View>
      ))}
    </View>
  );
}

const s = StyleSheet.create({
  section: { marginTop: space.lg, gap: space.xs },
  sectionTitle: { ...typo.headline, color: colors.textPrimary },
  lineRow: { flexDirection: "row", gap: space.sm },
  bullet: { ...typo.body, color: colors.textMuted },
  line: { ...typo.body, color: colors.textPrimary, flexShrink: 1 },
  hostRow: { marginTop: space.xs },
  host: { ...typo.body, color: colors.textPrimary },
  hostStatusRow: { flexDirection: "row", alignItems: "center", gap: 6, marginTop: 2 },
  hostStatus: { ...typo.caption, fontWeight: "600", flexShrink: 1 },
  privacyRow: { flexDirection: "row", alignItems: "flex-start", gap: 6, marginTop: space.lg },
  privacy: { ...typo.caption, color: colors.textMuted, flexShrink: 1 },
});
