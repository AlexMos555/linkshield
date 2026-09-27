/**
 * "Проверка защиты" (roadmap №4) — reachable from the home card and from
 * Settings.
 *
 * Part 1: what the phone checked about itself, each problem with its fix.
 * Part 2: the steps a family does once, outside Cleanway — the free state
 * bans, «вторая рука», a caller ID, closing the door apps come in through,
 * a code word, a number to call. Cleanway cannot see those, so their "done"
 * is the person's own mark and the screen says so; the summary is "done N
 * of M", never a made-up safety score.
 *
 * Nothing about the person leaves the phone: the marks and the saved number
 * live in secure storage here (services/checkup-store.ts), and an official
 * page opens in a real browser without passing through our link check. The
 * shield row re-runs the home screen's own self-test (a canary lookup, and
 * api.cleanway.ai/health when it fails) — see docs/PRIVACY.md.
 */
import { View, Text, StyleSheet, ScrollView } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius, sectionHeader } from "../src/utils/theme";
import { useDeviceChecks } from "../src/hooks/useDeviceChecks";
import { useFamilySetup } from "../src/hooks/useFamilySetup";
import { DeviceCheckList } from "../src/components/checkup/DeviceCheckList";
import { FamilyStepCard } from "../src/components/checkup/FamilyStepCard";
import { CloseOneCard } from "../src/components/checkup/CloseOneCard";
import type { FamilyStep, FamilyStepId } from "../src/utils/checkup";

type MarkableStep = FamilyStep & { id: Exclude<FamilyStepId, "call_close_one"> };

function isMarkable(step: FamilyStep): step is MarkableStep {
  return step.id !== "call_close_one";
}

export default function CheckupScreen() {
  const { t } = useTranslation();
  const device = useDeviceChecks();
  const family = useFamilySetup();

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled">
      <Text style={s.intro}>{t("mobile.checkup.intro")}</Text>

      {/* Scam calls open with "this is support". Say it before anything else. */}
      <View style={s.neverRow}>
        <Ionicons name="shield-checkmark-outline" size={20} color={colors.green} />
        <Text style={s.never}>{t("mobile.checkup.never_calls")}</Text>
      </View>

      {device.rows.length > 0 && (
        <View style={s.section}>
          <DeviceCheckList rows={device.rows} onFix={device.fix} />
        </View>
      )}

      <View style={s.section}>
        <Text style={s.sectionTitle}>{t("mobile.checkup.family.title")}</Text>
        <Text style={s.progress}>{t("mobile.checkup.family.progress", family.progress)}</Text>
        <Text style={s.familyNote}>{t("mobile.checkup.family.note")}</Text>
        {family.steps.map((step) =>
          isMarkable(step) ? (
            <FamilyStepCard
              key={step.id}
              step={step}
              done={family.marks.has(step.id)}
              onToggle={() => family.toggle(step.id)}
            />
          ) : (
            <CloseOneCard key={step.id} state={family.closeOne} />
          ),
        )}
      </View>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.checkup.privacy")}</Text>
      </View>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.lg, paddingBottom: 100 },
  intro: { fontSize: 17, lineHeight: 24, color: colors.textPrimary },
  neverRow: {
    flexDirection: "row", alignItems: "flex-start", gap: space.sm,
    backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke,
    borderRadius: radius.control, padding: space.md, marginTop: space.lg,
  },
  never: { fontSize: 16, lineHeight: 22, fontWeight: "600", color: colors.textPrimary, flex: 1 },
  section: { marginTop: space.xxl },
  sectionTitle: { ...sectionHeader, marginBottom: space.xs, marginLeft: space.xs },
  progress: { fontSize: 17, lineHeight: 23, fontWeight: "600", color: colors.textPrimary, marginLeft: space.xs },
  familyNote: {
    fontSize: 15, lineHeight: 21, color: colors.textSecondary,
    marginTop: space.xs, marginBottom: space.md, marginLeft: space.xs,
  },
  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xl, paddingHorizontal: space.md,
  },
  privacy: { fontSize: 13, lineHeight: 18, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
