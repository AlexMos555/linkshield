import { useEffect, useState, useCallback, useRef, type ReactNode } from "react";
import {
  View, Text, StyleSheet, ScrollView, Switch, TouchableOpacity, Alert, Linking, I18nManager,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import * as SecureStore from "expo-secure-store";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../../src/utils/theme";
import { pruneOldChecks } from "../../src/services/database";
import { getSessionState, signOut } from "../../src/services/auth";
import { clearKeypair } from "../../src/lib/family-crypto";
import { setAuthToken, getAccountSettings } from "../../src/services/api";

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

/**
 * Push a settings patch to the account.
 *
 * Returns "ok" | "failed" | "signed_out" instead of void: the response used
 * to be discarded entirely, so "saved to your account" could be a silent
 * no-op — a 401 from an expired session, a 500, an offline PUT all looked
 * identical to success. The caller decides what to tell the user.
 */
async function pushSkillToApi(
  patch: Record<string, unknown>,
): Promise<"ok" | "failed" | "signed_out"> {
  try {
    const token = await SecureStore.getItemAsync("auth_token");
    if (!token) return "signed_out";
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
    const resp = await fetch(`${apiBase}/api/v1/user/settings`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(patch),
    });
    return resp.ok ? "ok" : "failed";
  } catch {
    // Offline — SecureStore stays authoritative locally.
    return "failed";
  }
}

export default function SettingsScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const [skillLevel, setSkillLevel] = useState<SkillLevel>("regular");
  const [sessionEmail, setSessionEmail] = useState<string | null>(null);
  // Set the moment the user taps a skill this focus; the in-flight remote
  // pull then may NOT adopt its (older) value over the fresh choice — the
  // pull raced the tap and snapped the selection back before this guard.
  const userPickedSkillRef = useRef(false);

  // On focus, not mount: the user goes to /auth, signs in, and comes BACK
  // to this mounted screen — a mount-only read would keep saying "Sign in".
  useFocusEffect(useCallback(() => {
    let cancelled = false;
    userPickedSkillRef.current = false;
    void (async () => {
      try {
        const st = await getSessionState();
        if (cancelled) return;
        // "offline" keeps showing who is signed in — a failed refresh is not
        // a sign-out, and flipping this row to "Sign in" told people to go
        // find a password they had not lost.
        setSessionEmail(st.kind === "ok" ? st.session.email : st.kind === "offline" ? st.email : null);
        if (st.kind !== "ok") return;
        // The other half of sync. The app only ever PUSHED settings, so a
        // skill level changed in the browser extension never reached this
        // phone. Signed in → the account is the source of truth.
        const { data } = await getAccountSettings();
        const remote = data?.skill_level;
        if (
          !cancelled &&
          !userPickedSkillRef.current &&
          typeof remote === "string" &&
          ["kids", "regular", "granny", "pro"].includes(remote)
        ) {
          setSkillLevel(remote as SkillLevel);
          try {
            await SecureStore.setItemAsync("skill_level", remote);
          } catch {
            // Local persist is best-effort; the UI already shows it.
          }
        }
      } catch {
        if (!cancelled) setSessionEmail(null);
      }
    })();
    return () => { cancelled = true; };
  }, []));

  function confirmSignOut(): void {
    Alert.alert(t("mobile.settings.sign_out_confirm_title"), t("mobile.settings.sign_out_confirm_body"), [
      { text: t("mobile.settings.clear_cancel"), style: "cancel" },
      {
        text: t("mobile.settings.sign_out"),
        style: "destructive",
        onPress: () => {
          void (async () => {
            await signOut();
            // The Family E2E secret key must leave with the account. It sat
            // in SecureStore after sign-out, so the next user of a shared
            // phone could decrypt the previous family's alerts.
            try {
              await clearKeypair();
            } catch {
              // Best-effort: the key is device-scoped; the account is gone.
            }
            setAuthToken(null);
            setSessionEmail(null);
          })();
        },
      },
    ]);
  }

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
    userPickedSkillRef.current = true;
    setSkillLevel(next);
    try {
      await SecureStore.setItemAsync("skill_level", next);
      const defaults = SKILL_DEFAULTS[next];
      await SecureStore.setItemAsync("font_scale", String(defaults.fontScale));
      await SecureStore.setItemAsync("voice_alerts", String(defaults.voiceAlerts));
    } catch {
      // Best-effort: UI state is still updated so the user sees the change
    }
    const pushed = await pushSkillToApi({
      skill_level: next,
      font_scale: SKILL_DEFAULTS[next].fontScale,
      voice_alerts_enabled: SKILL_DEFAULTS[next].voiceAlerts,
    });
    // Only a signed-in user was promised account sync, so only they are told
    // when it did not happen. "signed_out" is the normal local-only case.
    if (pushed === "failed") {
      Alert.alert(
        t("mobile.settings.sync_failed_title"),
        t("mobile.settings.sync_failed_body"),
      );
    }
  }

  function confirmClearHistory(): void {
    Alert.alert(t("mobile.settings.clear_confirm_title"), t("mobile.settings.clear_confirm_body"), [
      { text: t("mobile.settings.clear_cancel"), style: "cancel" },
      {
        text: t("mobile.settings.clear_confirm"),
        style: "destructive",
        // Was fire-and-forget: no await, errors swallowed, no confirmation.
        // The user tapped a destructive action and got silence either way.
        onPress: () => {
          void (async () => {
            try {
              await pruneOldChecks(0);
              Alert.alert(t("mobile.settings.clear_done_title"), t("mobile.settings.clear_done_body"));
            } catch {
              Alert.alert(t("mobile.settings.clear_failed_title"), t("mobile.settings.clear_failed_body"));
            }
          })();
        },
      },
    ]);
  }

  // Disclosure chevrons must point INTO the row's reading direction — a
  // forward-chevron in Arabic points out of the screen.
  const chevron = (
    <Ionicons
      name={I18nManager.isRTL ? "chevron-back" : "chevron-forward"}
      size={18}
      color={colors.textMuted}
    />
  );
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
        {/* The app had no signed-in state anywhere: after signing in, this row
            still said "Sign in", and no screen offered a way out. Now it shows
            who is signed in and signs them out — with a confirm, because for a
            security product "am I signed in?" should never be a mystery. */}
        {sessionEmail ? (
          <Row first label={sessionEmail} desc={t("mobile.settings.signed_in_desc")}
               right={<Text style={s.signOut}>{t("mobile.settings.sign_out")}</Text>}
               onPress={confirmSignOut} />
        ) : (
          <Row first label={t("mobile.settings.sign_in")} desc={t("mobile.settings.sign_in_desc")}
               right={chevron} onPress={() => router.push("/auth")} />
        )}
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
  signOut: { ...typo.body, fontWeight: "600", color: colors.danger },
});
