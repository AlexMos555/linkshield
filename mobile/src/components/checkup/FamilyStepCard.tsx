import { useState } from "react";
import { View, Text, StyleSheet, TouchableOpacity, Alert } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius } from "../../utils/theme";
import { OFFICIAL_LINKS, isVerified, linkButtonVisible, linkHost } from "../../config/official-links";
import { openOfficialPage } from "../../services/checkup-actions";
import { openUnknownAppSources } from "../../../modules/cleanway-vpn";
import type { FamilyStep, FamilyStepId } from "../../utils/checkup";

type MarkableStep = Exclude<FamilyStepId, "call_close_one">;

interface Copy {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  why: string;
  /** What to do or what to ask for — where the step itself happens. */
  how: string;
}

// Static keys, so scripts/check-mobile-i18n.py can see every one of them.
const COPY: Record<MarkableStep, Copy> = {
  credit_ban: {
    icon: "card-outline",
    title: "mobile.checkup.credit_ban.title",
    why: "mobile.checkup.credit_ban.why",
    how: "mobile.checkup.credit_ban.how",
  },
  sim_ban: {
    icon: "phone-portrait-outline",
    title: "mobile.checkup.sim_ban.title",
    why: "mobile.checkup.sim_ban.why",
    how: "mobile.checkup.sim_ban.how",
  },
  second_hand: {
    icon: "people-outline",
    title: "mobile.checkup.second_hand.title",
    why: "mobile.checkup.second_hand.why",
    how: "mobile.checkup.second_hand.ask",
  },
  caller_id: {
    icon: "call-outline",
    title: "mobile.checkup.caller_id.title",
    why: "mobile.checkup.caller_id.why",
    how: "mobile.checkup.caller_id.ask",
  },
  install_block: {
    icon: "lock-closed-outline",
    title: "mobile.checkup.install_block.title",
    why: "mobile.checkup.install_block.why",
    how: "mobile.checkup.install_block.how",
  },
  code_word: {
    icon: "chatbubbles-outline",
    title: "mobile.checkup.code_word.title",
    why: "mobile.checkup.code_word.why",
    how: "mobile.checkup.code_word.how",
  },
};

interface Props {
  step: FamilyStep & { id: MarkableStep };
  done: boolean;
  onToggle: () => Promise<boolean>;
}

/**
 * One thing the family does once, outside Cleanway: why (one sentence, a
 * real number where one exists), where to do it, and a "done" mark that is
 * the person's word — the app says so under it.
 *
 * The button opens only an official page, and only once a person has
 * verified the link (config/official-links.ts); the bank and caller-ID
 * steps name no single bank or vendor and have no button at all.
 */
export function FamilyStepCard({ step, done, onToggle }: Props) {
  const { t } = useTranslation();
  const copy = COPY[step.id];
  const [openFailed, setOpenFailed] = useState(false);

  async function toggle() {
    if (!(await onToggle())) Alert.alert(t("mobile.checkup.family.save_failed"));
  }

  return (
    <View style={s.card}>
      <View style={s.titleRow}>
        <View style={s.iconBox}>
          <Ionicons name={copy.icon} size={24} color={colors.textSecondary} />
        </View>
        <Text style={s.title}>{t(copy.title)}</Text>
      </View>
      <Text style={s.why}>{t(copy.why)}</Text>
      <Text style={s.how}>{t(copy.how)}</Text>

      <StepAction step={step} onFailed={() => setOpenFailed(true)} />
      {openFailed && <Text style={s.failed}>{t("mobile.checkup.family.open_failed")}</Text>}

      <TouchableOpacity
        style={s.doneRow}
        onPress={() => void toggle()}
        activeOpacity={0.85}
        accessibilityRole="checkbox"
        accessibilityState={{ checked: done }}
        accessibilityLabel={`${t("mobile.checkup.family.done")}. ${t("mobile.checkup.family.done_note")}`}
      >
        <Ionicons name={done ? "checkbox" : "square-outline"} size={28} color={done ? colors.green : colors.textSecondary} />
        <View style={s.doneText}>
          <Text style={s.doneLabel}>{t("mobile.checkup.family.done")}</Text>
          <Text style={s.doneNote}>{t("mobile.checkup.family.done_note")}</Text>
        </View>
      </TouchableOpacity>
    </View>
  );
}

/** The step's one button, if it has one: an official page, or a system screen. */
function StepAction({ step, onFailed }: { step: FamilyStep; onFailed: () => void }) {
  const { t } = useTranslation();
  if (step.link) {
    const link = OFFICIAL_LINKS[step.link];
    if (!linkButtonVisible(link)) return null;
    return (
      <View style={s.actionWrap}>
        <ActionButton
          label={t("mobile.checkup.family.open_gosuslugi")}
          onPress={() => void openOfficialPage(link.url).then((ok) => { if (!ok) onFailed(); })}
        />
        <Text style={s.host}>{linkHost(link)}</Text>
        {!isVerified(link) && (
          // Only a review build gets here: say plainly that nobody has
          // checked this address yet, so no one mistakes it for a release.
          <Text style={s.unverified}>{t("mobile.checkup.family.unverified_badge")}</Text>
        )}
      </View>
    );
  }
  if (step.id === "install_block") {
    return (
      <View style={s.actionWrap}>
        <ActionButton
          label={t("mobile.checkup.family.open_settings")}
          onPress={() => { if (!openUnknownAppSources()) onFailed(); }}
        />
      </View>
    );
  }
  return null;
}

function ActionButton({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <TouchableOpacity style={s.action} onPress={onPress} activeOpacity={0.85} accessibilityRole="button">
      <Text style={s.actionLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  titleRow: { flexDirection: "row", alignItems: "center", gap: space.md },
  iconBox: {
    width: 44, height: 44, borderRadius: radius.icon, backgroundColor: colors.surface,
    alignItems: "center", justifyContent: "center",
  },
  title: { fontSize: 19, lineHeight: 25, fontWeight: "600", color: colors.textPrimary, flex: 1 },
  why: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, marginTop: space.md },
  how: { fontSize: 16, lineHeight: 23, color: colors.textSecondary, marginTop: space.sm },

  actionWrap: { marginTop: space.md },
  action: {
    minHeight: 52, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg,
  },
  actionLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF", textAlign: "center" },
  host: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, textAlign: "center", marginTop: space.xs },
  unverified: { fontSize: 13, lineHeight: 18, color: colors.amber, textAlign: "center", marginTop: space.xs },
  failed: { fontSize: 14, lineHeight: 20, color: colors.amber, marginTop: space.sm },

  doneRow: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    minHeight: 56, marginTop: space.md, paddingTop: space.md,
    borderTopWidth: 1, borderTopColor: colors.hairline,
  },
  doneText: { flex: 1 },
  doneLabel: { fontSize: 17, lineHeight: 22, fontWeight: "600", color: colors.textPrimary },
  doneNote: { fontSize: 13, lineHeight: 18, color: colors.textMuted, marginTop: 2 },
});
