import { useEffect, useState, type ReactNode } from "react";
import {
  View, Text, StyleSheet, ScrollView, Switch, TouchableOpacity, Alert, Linking,
} from "react-native";
import { useRouter } from "expo-router";
import * as SecureStore from "expo-secure-store";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../../src/utils/theme";
import { pruneOldChecks } from "../../src/services/database";

type SkillLevel = "kids" | "regular" | "granny" | "pro";
type IconName = keyof typeof Ionicons.glyphMap;

const SKILL_DEFAULTS: Record<SkillLevel, { fontScale: number; voiceAlerts: boolean }> = {
  kids:    { fontScale: 1.0, voiceAlerts: false },
  regular: { fontScale: 1.0, voiceAlerts: false },
  granny:  { fontScale: 1.3, voiceAlerts: true  },
  pro:     { fontScale: 1.0, voiceAlerts: false },
};

const SKILL_OPTIONS: Array<{ value: SkillLevel; icon: IconName }> = [
  { value: "kids",    icon: "happy-outline" },
  { value: "regular", icon: "person-outline" },
  { value: "granny",  icon: "volume-high-outline" },
  { value: "pro",     icon: "code-slash-outline" },
];

async function pushSkillToApi(
  patch: Record<string, unknown>,
): Promise<void> {
  try {
    const token = await SecureStore.getItemAsync("auth_token");
    if (!token) return;
    // Audit mobile MEDIUM "settings.tsx reads API base URL from
    // SecureStore at runtime — creates a URL-injection vector":
    // previously we honoured `api_url` in SecureStore as an override.
    // A jailbroken phone / shared device / debugger access to
    // SecureStore could write an attacker URL and silently
    // exfiltrate every settings PATCH (including parental PIN hash).
    // EXPO_PUBLIC_API_URL is inlined at build time and cannot be
    // changed by a runtime attacker; the rest of the app already
    // uses this canonical source via services/api.ts.
    const apiBase =
      process.env.EXPO_PUBLIC_API_URL || "https://api.cleanway.ai";
    await fetch(`${apiBase}/api/v1/user/settings`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(patch),
    });
  } catch {
    // Offline or unauthenticated — SecureStore stays authoritative locally
  }
}

export default function SettingsScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const [skillLevel, setSkillLevel] = useState<SkillLevel>("regular");

  // Load persisted skill on mount
  useEffect(() => {
    (async () => {
      try {
        const stored = (await SecureStore.getItemAsync("skill_level")) as SkillLevel | null;
        if (stored && ["kids", "regular", "granny", "pro"].includes(stored)) {
          setSkillLevel(stored);
        }
      } catch {
        // SecureStore unavailable — stay on default
      }
    })();
  }, []);

  async function handleSkillChange(next: SkillLevel): Promise<void> {
    setSkillLevel(next);
    try {
      await SecureStore.setItemAsync("skill_level", next);
      const defaults = SKILL_DEFAULTS[next];
      await SecureStore.setItemAsync("font_scale", String(defaults.fontScale));
      await SecureStore.setItemAsync("voice_alerts", String(defaults.voiceAlerts));
    } catch {
      // Best-effort: UI state is still updated so the user sees the change
    }
    await pushSkillToApi({
      skill_level: next,
      font_scale: SKILL_DEFAULTS[next].fontScale,
      voice_alerts_enabled: SKILL_DEFAULTS[next].voiceAlerts,
    });
  }

  function confirmClearHistory(): void {
    Alert.alert(t("mobile.settings.clear_confirm_title"), t("mobile.settings.clear_confirm_body"), [
      { text: t("mobile.settings.clear_cancel"), style: "cancel" },
      { text: t("mobile.settings.clear_confirm"), style: "destructive", onPress: () => pruneOldChecks(0) },
    ]);
  }

  const chevron = <Ionicons name="chevron-forward" size={18} color={colors.textMuted} />;
  /**
   * The Alerts switches are for features that do not exist yet — the section
   * footnote says so in words. They used to default to `true` and paint green,
   * so the screen showed three active-looking protections backed by nothing but
   * local React state. Rendered off and disabled: the control now looks the way
   * the feature actually is, and the reason travels with it for screen readers
   * instead of living in a caption they may never reach.
   */
  const comingSoonToggle = (label: string) => (
    <Switch
      value={false}
      disabled
      trackColor={{ true: colors.green, false: colors.stroke }}
      thumbColor={colors.textDisabled}
      accessibilityLabel={label}
      accessibilityHint={t("mobile.settings.alerts_note")}
    />
  );

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Section title={t("mobile.settings.account")}>
        <Row first label={t("mobile.settings.sign_in")} desc={t("mobile.settings.sign_in_desc")}
             right={chevron} onPress={() => router.push("/auth")} />
        <Row label={t("mobile.settings.plan")} desc={t("mobile.settings.plan_desc")}
             right={<Text style={s.pill}>{t("mobile.settings.upgrade")}</Text>}
             onPress={() => router.push("/upgrade")} />
        <Row label={t("mobile.settings.report")} desc={t("mobile.settings.report_desc")}
             right={chevron} onPress={() => router.push("/report")} />
        <Row label={t("mobile.settings.family")} desc={t("mobile.settings.family_desc")}
             right={chevron} onPress={() => router.push("/family")} />
      </Section>

      <Section title={t("mobile.settings.skill")} footnote={t("mobile.settings.skill_note")}>
        {SKILL_OPTIONS.map(({ value, icon }, i) => {
          const on = skillLevel === value;
          const label = t(`mobile.settings.skill_${value}`);
          const desc = t(`mobile.settings.skill_${value}_desc`);
          return (
            <Row key={value} first={i === 0} icon={icon} label={label} desc={desc}
                 iconColor={on ? colors.green : colors.textMuted}
                 role="radio" selected={on} a11yLabel={`${label}. ${desc}`}
                 onPress={() => void handleSkillChange(value)}
                 right={<Ionicons name={on ? "radio-button-on" : "radio-button-off"} size={22}
                                  color={on ? colors.green : colors.textDisabled} />} />
          );
        })}
      </Section>

      <Section title={t("mobile.settings.alerts")} footnote={t("mobile.settings.alerts_note")}>
        <Row first label={t("mobile.settings.push")} desc={t("mobile.settings.push_desc")}
             right={comingSoonToggle(t("mobile.settings.push"))} />
        <Row label={t("mobile.settings.auto_check")} desc={t("mobile.settings.auto_check_desc")}
             right={comingSoonToggle(t("mobile.settings.auto_check"))} />
        <Row label={t("mobile.settings.weekly")} desc={t("mobile.settings.weekly_desc")}
             right={comingSoonToggle(t("mobile.settings.weekly"))} />
      </Section>

      <Section title={t("mobile.settings.data")}>
        <Row first icon="trash-outline" iconColor={colors.danger} tint={colors.danger}
             label={t("mobile.settings.clear")} desc={t("mobile.settings.clear_desc")}
             onPress={confirmClearHistory} />
      </Section>

      <Section title={t("mobile.settings.about")}>
        <Row first label={t("mobile.settings.privacy_policy")} right={chevron}
             onPress={() => void Linking.openURL("https://cleanway.ai/privacy-policy")} />
        <Row label={t("mobile.settings.terms")} right={chevron}
             onPress={() => void Linking.openURL("https://cleanway.ai/terms")} />
        <Row label={t("mobile.settings.version")} right={<Text style={s.value}>0.1.0</Text>} />
      </Section>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.settings.privacy_note")}</Text>
      </View>
    </ScrollView>
  );
}

function Section({ title, footnote, children }: {
  title: string; footnote?: string; children: ReactNode;
}) {
  return (
    <View style={s.section}>
      <Text style={s.sectionTitle}>{title}</Text>
      <View style={s.card}>{children}</View>
      {footnote ? (
        <View style={s.footnoteRow}>
          <Ionicons name="information-circle-outline" size={13} color={colors.textSecondary} />
          <Text style={s.footnote}>{footnote}</Text>
        </View>
      ) : null}
    </View>
  );
}

type RowProps = {
  label: string; desc?: string; right?: ReactNode; onPress?: () => void;
  first?: boolean; icon?: IconName; iconColor?: string; tint?: string;
  role?: "button" | "radio"; selected?: boolean; a11yLabel?: string;
};

function Row({
  label, desc, right, onPress, first, icon, iconColor, tint, role, selected, a11yLabel,
}: RowProps) {
  const inner = (
    <>
      {icon ? <Ionicons name={icon} size={18} color={iconColor ?? colors.textSecondary} /> : null}
      <View style={s.rowText}>
        <Text style={[s.rowLabel, tint ? { color: tint } : null]}>{label}</Text>
        {desc ? <Text style={s.rowDesc}>{desc}</Text> : null}
      </View>
      {right}
    </>
  );
  const style = [s.row, !first && s.rowBorder];
  if (!onPress) return <View style={style}>{inner}</View>;
  return (
    <TouchableOpacity
      style={style}
      onPress={onPress}
      activeOpacity={0.85}
      accessibilityRole={role ?? "button"}
      accessibilityState={role === "radio" ? { selected } : undefined}
      accessibilityLabel={a11yLabel}
    >
      {inner}
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },

  section: { marginTop: space.xxl },
  sectionTitle: { ...sectionHeader, marginBottom: space.sm, marginLeft: space.xs },
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, paddingVertical: space.xs,
  },

  row: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    minHeight: 52, paddingVertical: space.md,
  },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  rowText: { flex: 1 },
  rowLabel: { ...typo.body, fontWeight: "600", color: colors.textPrimary },
  rowDesc: { ...typo.caption, color: colors.textSecondary, marginTop: 2 },
  value: { ...typo.body, color: colors.textMuted },
  pill: {
    backgroundColor: colors.blue, color: "#FFFFFF", overflow: "hidden",
    borderRadius: radius.pill, paddingHorizontal: space.md, paddingVertical: 6,
    fontSize: 13, lineHeight: 18, fontWeight: "600",
  },

  footnoteRow: {
    flexDirection: "row", alignItems: "flex-start", gap: 6,
    marginTop: space.sm, paddingHorizontal: space.xs,
  },
  footnote: { ...typo.caption, color: colors.textSecondary, flex: 1 },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
