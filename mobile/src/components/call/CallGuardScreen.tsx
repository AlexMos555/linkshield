import { useEffect, useState } from "react";
import { ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, space, radius, type as typo } from "../../utils/theme";
import { closeContactPhone, dialCloseContact, showInCallScreen } from "../../../modules/cleanway-vpn";
import { COUNTDOWN_SECONDS, countdownLeft, type GuardReason } from "../../utils/call-guard";

interface CallGuardScreenProps {
  /**
   * "intercept": the person tapped pause / allow / "open anyway" during or
   * right after a call; the original action waits behind the slow path.
   * "on_demand": the home button "I'm being called" or the after-call notice.
   */
  mode: "intercept" | "on_demand";
  /** In a call, after one, or (on demand only) neither. */
  reason: GuardReason | null;
  /** The big button: keep protection; during a call also bring the phone app up to hang up. */
  onKeep: () => void;
  /** Intercept only: the original action, after the countdown. */
  onProceed?: () => void;
}

/**
 * The stop screen. Big, calm, one message: you are on the phone — if you are
 * asked to switch protection off, open a site or install an app, it's a
 * scam; hang up. The primary button keeps protection. The original action is
 * still reachable ("I understand, this is my call"), but only after a
 * [COUNTDOWN_SECONDS] wait, so the hand cannot outrun the thought.
 *
 * Honesty line at the bottom: Cleanway does not see who is calling, does not
 * block calls and does not listen — the operator shows who is calling.
 */
export function CallGuardScreen({ mode, reason, onKeep, onProceed }: CallGuardScreenProps) {
  const { t } = useTranslation();
  const [openedAt] = useState(() => Date.now());
  const [left, setLeft] = useState(() => countdownLeft(openedAt, Date.now()));
  const [closeOne] = useState(() => closeContactPhone() !== null);
  const intercept = mode === "intercept" && !!onProceed;

  useEffect(() => {
    if (!intercept || left <= 0) return;
    const timer = setInterval(() => setLeft(countdownLeft(openedAt, Date.now())), 250);
    return () => clearInterval(timer);
  }, [intercept, left, openedAt]);

  const inCall = reason === "in_call";
  const title = inCall ? t("mobile.call_guard.title_in_call")
    : reason === "after_call" ? t("mobile.call_guard.title_after_call")
    : t("mobile.call_guard.demand_title");
  const body = inCall ? t("mobile.call_guard.body_in_call")
    : reason === "after_call" ? t("mobile.call_guard.body_after_call")
    : t("mobile.call_guard.demand_body");
  const keepLabel = inCall ? t("mobile.call_guard.keep_in_call")
    : intercept ? t("mobile.call_guard.keep_after_call")
    : t("mobile.call_guard.demand_close");

  function keep() {
    // "Hang up" cannot end the call for her (that needs a permission this
    // app does not ask for); the phone app's own screen is where it lives.
    if (inCall) showInCallScreen();
    onKeep();
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content} bounces={false}>
      <View style={s.iconRing} accessible={false}>
        <Ionicons name="call-outline" size={44} color={colors.amber} />
      </View>
      <Text style={s.title} accessibilityRole="header">{title}</Text>
      <Text style={s.body}>{body}</Text>

      <TouchableOpacity style={s.keepBtn} onPress={keep} activeOpacity={0.85} accessibilityRole="button">
        <Text style={s.keepLabel}>{keepLabel}</Text>
      </TouchableOpacity>

      {closeOne && (
        <TouchableOpacity
          style={s.closeOneBtn}
          onPress={() => dialCloseContact()}
          activeOpacity={0.85}
          accessibilityRole="button"
        >
          <Ionicons name="people-outline" size={20} color={colors.textPrimary} />
          <Text style={s.closeOneLabel}>{t("mobile.call_guard.call_close_one")}</Text>
        </TouchableOpacity>
      )}

      {intercept && (
        <>
          <TouchableOpacity
            style={[s.proceedBtn, left > 0 && s.proceedBtnWaiting]}
            onPress={left > 0 ? undefined : onProceed}
            disabled={left > 0}
            activeOpacity={0.7}
            accessibilityRole="button"
            accessibilityState={{ disabled: left > 0 }}
          >
            <Text style={[s.proceedLabel, left > 0 && s.proceedLabelWaiting]}>
              {left > 0
                ? t("mobile.call_guard.proceed_wait", { seconds: left })
                : t("mobile.call_guard.proceed")}
            </Text>
          </TouchableOpacity>
          {left > 0 && <Text style={s.hint}>{t("mobile.call_guard.proceed_hint")}</Text>}
        </>
      )}

      <View style={s.honestyRow}>
        <Ionicons name="information-circle-outline" size={14} color={colors.textMuted} />
        <Text style={s.honesty}>{t("mobile.call_guard.honesty")}</Text>
      </View>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: {
    flexGrow: 1, justifyContent: "center",
    paddingHorizontal: space.xxl, paddingTop: space.xxxl, paddingBottom: space.huge,
  },
  iconRing: {
    width: 88, height: 88, borderRadius: 44, alignSelf: "center",
    backgroundColor: colors.amberWash, borderWidth: 2, borderColor: colors.amberStroke,
    alignItems: "center", justifyContent: "center",
  },
  // Deliberately larger than the app's title2: read at arm's length, mid-call.
  title: { fontSize: 26, lineHeight: 33, fontWeight: "700", color: colors.textPrimary, textAlign: "center", marginTop: space.xl },
  body: { fontSize: 19, lineHeight: 27, color: colors.textPrimary, textAlign: "center", marginTop: space.lg },
  keepBtn: {
    minHeight: 60, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xxxl, paddingHorizontal: space.lg,
  },
  keepLabel: { fontSize: 19, fontWeight: "700", color: "#FFFFFF", textAlign: "center" },
  closeOneBtn: {
    minHeight: 56, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke,
    backgroundColor: colors.surface, flexDirection: "row", gap: space.sm,
    alignItems: "center", justifyContent: "center", marginTop: space.md, paddingHorizontal: space.lg,
  },
  closeOneLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary },
  proceedBtn: { minHeight: 48, alignItems: "center", justifyContent: "center", marginTop: space.xl },
  proceedBtnWaiting: { opacity: 0.6 },
  proceedLabel: { ...typo.body, fontSize: 16, color: colors.textSecondary, textAlign: "center" },
  proceedLabelWaiting: { color: colors.textMuted },
  hint: { ...typo.caption, color: colors.textMuted, textAlign: "center", marginTop: space.xs },
  honestyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxxl, paddingHorizontal: space.sm,
  },
  honesty: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
