import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../utils/theme";
import { ShieldCard, type ShieldState } from "./ShieldCard";
import type { SmsShield } from "../../hooks/useSmsShield";
import { offersTurnOn, smsListNote, smsShieldAction, type SmsShieldView } from "../../utils/sms-shield-view";
import { SMS_ACTION_KEYS, smsFixRow, smsFixStepsKey, smsStateCopy } from "../../utils/sms-shield-labels";

/**
 * The "SMS messages" shield (RuStore build only): every incoming SMS is
 * checked on the phone, and a scam gets a warning as it arrives.
 *
 * Same contract as the other shield cards: green only when verified (see
 * sms-shield-view.ts), every other state in words with the one thing that
 * fixes it — as a plain button row under the card, not only behind the amber
 * "Attention" pill, because a 70-year-old should not have to guess that a
 * pill is tappable. Steps to follow in system Settings go full width under
 * the card, never into its narrow text column. The honesty line says what it
 * cannot do: see chats in messengers, or hide or delete an SMS (only the
 * default SMS app can).
 */

function cardState(view: SmsShieldView): ShieldState {
  return view.kind === "on" ? "on" : offersTurnOn(view) ? "setup" : "conflict";
}

export function SmsShieldCard({ sms }: { sms: SmsShield }) {
  const { t } = useTranslation();
  const { view } = sms;
  if (view.kind === "unsupported") return null;
  const fixRow = smsFixRow(smsShieldAction(view));
  const stepsKey = smsFixStepsKey(view);
  const listNote = smsListNote(view, sms.status.listAgeMs);

  return (
    <>
      <ShieldCard
        icon="chatbubbles-outline"
        title={t("mobile.shield.sms_auto.title")}
        description={t("mobile.shield.sms_auto.desc")}
        honesty={t("mobile.shield.sms_auto.honesty")}
        state={cardState(view)}
        stateCopy={smsStateCopy(view, t)}
        actionLabel={t("mobile.shield.sms_auto.action_enable")}
        // "Turn on" asks again (also after the restricted-settings steps);
        // the amber pill does the state's one fix.
        onAction={offersTurnOn(view) ? sms.turnOn : sms.fix}
        onPause={sms.confirmPause}
      />
      {stepsKey !== null && (
        <View style={s.stepsRow}>
          <Ionicons name="information-circle-outline" size={13} color={colors.amber} />
          <Text style={[s.hintText, { color: colors.amber }]}>{t(stepsKey)}</Text>
        </View>
      )}
      {fixRow !== null && (
        <TouchableOpacity
          style={s.hintRow}
          onPress={sms.fix}
          disabled={sms.busy}
          activeOpacity={0.85}
          accessibilityRole="button"
        >
          <Ionicons name="settings-outline" size={13} color={colors.amber} />
          <Text style={[s.hintText, { color: colors.amber }]}>{t(SMS_ACTION_KEYS[fixRow])}</Text>
          <Ionicons name="chevron-forward" size={14} color={colors.amber} />
        </TouchableOpacity>
      )}
      {listNote !== null && (
        // The text rules work without the list; links to known scam sites
        // are caught only with it. Its own line, never folded into "On".
        <View style={s.stepsRow}>
          <Ionicons name="list-outline" size={13} color={colors.textSecondary} />
          <Text style={s.hintText}>
            {t(listNote === "missing" ? "mobile.shield.sms_auto.list_missing" : "mobile.shield.sms_auto.list_stale")}
          </Text>
        </View>
      )}
    </>
  );
}

const s = StyleSheet.create({
  hintRow: {
    flexDirection: "row", alignItems: "center", gap: 6,
    marginTop: space.sm, paddingHorizontal: space.xs, minHeight: 32,
  },
  hintText: { ...typo.caption, color: colors.textSecondary, flex: 1 },
  stepsRow: {
    flexDirection: "row", alignItems: "flex-start", gap: 6,
    marginTop: space.sm, paddingHorizontal: space.xs,
  },
});
