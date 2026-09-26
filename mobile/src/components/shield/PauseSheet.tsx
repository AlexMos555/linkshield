import { Modal, View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";
import { clockTime } from "../../utils/relative-time";

interface PauseSheetProps {
  visible: boolean;
  /** Minutes of the default, timed pause. */
  minutes: number;
  onPauseTimed: () => void;
  onPauseUntilOn: () => void;
  onKeep: () => void;
}

/**
 * Pausing protection — the step a phone scammer asks for.
 *
 * "Your antivirus is blocking the bank's page, switch it off" is the script,
 * and the old pause obliged with one confirm and lasted until the person
 * remembered to undo it. So the first thing this sheet says is that a request
 * to switch protection off IS the scam; the default pause is short and ends
 * by itself; "until I turn it back on" is still there, but second; and the
 * most prominent button keeps protection on.
 */
export function PauseSheet({ visible, minutes, onPauseTimed, onPauseUntilOn, onKeep }: PauseSheetProps) {
  const { t, i18n } = useTranslation();
  const resumesAt = clockTime(Date.now() + minutes * 60_000, i18n.language);
  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onKeep}>
      <View style={s.scrim}>
        <View style={s.sheet} accessibilityViewIsModal>
          <Text style={s.title}>{t("mobile.shield.pause_confirm_title")}</Text>
          <View style={s.warning}>
            <Ionicons name="call-outline" size={20} color={colors.amber} />
            <Text style={s.warningText}>{t("mobile.shield.pause_scam_warning")}</Text>
          </View>
          <Text style={s.body}>{t("mobile.shield.pause_confirm_body")}</Text>

          <TouchableOpacity style={s.keepBtn} onPress={onKeep} activeOpacity={0.85} accessibilityRole="button">
            <Text style={s.keepLabel}>{t("mobile.shield.pause_keep")}</Text>
          </TouchableOpacity>

          <TouchableOpacity style={s.pauseBtn} onPress={onPauseTimed} activeOpacity={0.85} accessibilityRole="button">
            <Text style={s.pauseLabel}>{t("mobile.shield.pause_timed", { minutes })}</Text>
          </TouchableOpacity>
          <Text style={s.note}>{t("mobile.shield.pause_timed_note", { time: resumesAt })}</Text>

          <TouchableOpacity style={s.textBtn} onPress={onPauseUntilOn} activeOpacity={0.7} accessibilityRole="button">
            <Text style={s.textLabel}>{t("mobile.shield.pause_until_on")}</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

const s = StyleSheet.create({
  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    padding: space.xxl, paddingBottom: space.huge,
  },
  title: { ...typo.title2, color: colors.textPrimary },
  warning: {
    flexDirection: "row", alignItems: "flex-start", gap: space.sm,
    backgroundColor: colors.amberWash, borderWidth: 1, borderColor: colors.amberStroke,
    borderRadius: radius.control, padding: space.md, marginTop: space.lg,
  },
  warningText: { fontSize: 17, lineHeight: 24, fontWeight: "600", color: colors.amber, flex: 1 },
  body: { ...typo.body, color: colors.textSecondary, marginTop: space.md },
  keepBtn: {
    minHeight: 54, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  keepLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  pauseBtn: {
    minHeight: 50, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke,
    backgroundColor: colors.surface, alignItems: "center", justifyContent: "center", marginTop: space.md,
  },
  pauseLabel: { fontSize: 16, fontWeight: "600", color: colors.textPrimary },
  note: { ...typo.caption, color: colors.textMuted, textAlign: "center", marginTop: space.xs },
  textBtn: { alignSelf: "center", minHeight: 44, justifyContent: "center", paddingHorizontal: space.md, marginTop: space.sm },
  textLabel: { ...typo.body, color: colors.textSecondary },
});
