import { useEffect, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, Switch, TouchableOpacity, Alert, Linking,
} from "react-native";
import { useRouter } from "expo-router";
import * as SecureStore from "expo-secure-store";
import { colors, spacing, fontSize } from "../../src/utils/theme";
import { pruneOldChecks } from "../../src/services/database";

type SkillLevel = "kids" | "regular" | "granny" | "pro";

const SKILL_DEFAULTS: Record<SkillLevel, { fontScale: number; voiceAlerts: boolean }> = {
  kids:    { fontScale: 1.0, voiceAlerts: false },
  regular: { fontScale: 1.0, voiceAlerts: false },
  granny:  { fontScale: 1.3, voiceAlerts: true  },
  pro:     { fontScale: 1.0, voiceAlerts: false },
};

const SKILL_OPTIONS: Array<{ value: SkillLevel; label: string; desc: string; icon: string }> = [
  { value: "kids",    icon: "👶", label: "Kids",    desc: "Simple blocking with parental PIN. Strict mode." },
  { value: "regular", icon: "🙋", label: "Regular", desc: "Default. Clear warnings, balanced details." },
  { value: "granny",  icon: "👵", label: "Granny",  desc: "Large text, simple words, voice alerts." },
  { value: "pro",     icon: "🧑‍💻", label: "Pro",    desc: "Raw scores, threat types, technical details." },
];

async function pushSkillToApi(
  patch: Record<string, unknown>,
): Promise<void> {
  try {
    const token = await SecureStore.getItemAsync("auth_token");
    if (!token) return;
    const apiBase =
      (await SecureStore.getItemAsync("api_url")) ||
      "https://api.cleanway.ai";
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
  const [notifications, setNotifications] = useState(true);
  const [autoCheck, setAutoCheck] = useState(true);
  const [weeklyReport, setWeeklyReport] = useState(true);
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

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Account */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Account</Text>
        <TouchableOpacity style={styles.row} onPress={() => router.push("/auth")}>
          <View>
            <Text style={styles.rowLabel}>Sign In</Text>
            <Text style={styles.rowDesc}>Sync settings across devices</Text>
          </View>
          <Text style={styles.rowArrow}>&rarr;</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.row} onPress={() => router.push("/upgrade")}>
          <View>
            <Text style={styles.rowLabel}>Plan</Text>
            <Text style={styles.rowDesc}>Free &mdash; 10 checks/day</Text>
          </View>
          <Text style={[styles.upgradeBtn]}>Upgrade</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.row} onPress={() => router.push("/report")}>
          <View>
            <Text style={styles.rowLabel}>Weekly Report</Text>
            <Text style={styles.rowDesc}>Your protection summary</Text>
          </View>
          <Text style={styles.rowArrow}>&rarr;</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.row} onPress={() => router.push("/family")}>
          <View>
            <Text style={styles.rowLabel}>Family Hub</Text>
            <Text style={styles.rowDesc}>End-to-end encrypted alerts for loved ones</Text>
          </View>
          <Text style={styles.rowArrow}>&rarr;</Text>
        </TouchableOpacity>
      </View>

      {/* Skill Level */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Skill Level</Text>
        {SKILL_OPTIONS.map((opt) => {
          const isActive = skillLevel === opt.value;
          return (
            <TouchableOpacity
              key={opt.value}
              style={[styles.row, isActive && styles.rowActive]}
              onPress={() => handleSkillChange(opt.value)}
              accessibilityRole="radio"
              accessibilityState={{ selected: isActive }}
              accessibilityLabel={`${opt.label} mode. ${opt.desc}`}
            >
              <View style={{ flex: 1 }}>
                <Text style={styles.rowLabel}>
                  {opt.icon}  {opt.label}
                </Text>
                <Text style={styles.rowDesc}>{opt.desc}</Text>
              </View>
              <View
                style={[
                  styles.radioDot,
                  isActive && styles.radioDotActive,
                ]}
              />
            </TouchableOpacity>
          );
        })}
      </View>

      {/* Protection */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Protection</Text>
        <View style={styles.row}>
          <View style={{ flex: 1 }}>
            <Text style={styles.rowLabel}>Push Notifications</Text>
            <Text style={styles.rowDesc}>Alert when dangerous links detected</Text>
          </View>
          <Switch
            value={notifications}
            onValueChange={setNotifications}
            trackColor={{ true: colors.safe, false: colors.border }}
            thumbColor={colors.white}
          />
        </View>
        <View style={styles.row}>
          <View style={{ flex: 1 }}>
            <Text style={styles.rowLabel}>Auto-check shared links</Text>
            <Text style={styles.rowDesc}>Check links from clipboard</Text>
          </View>
          <Switch
            value={autoCheck}
            onValueChange={setAutoCheck}
            trackColor={{ true: colors.safe, false: colors.border }}
            thumbColor={colors.white}
          />
        </View>
        <View style={styles.row}>
          <View style={{ flex: 1 }}>
            <Text style={styles.rowLabel}>Weekly Report</Text>
            <Text style={styles.rowDesc}>Summary of your protection</Text>
          </View>
          <Switch
            value={weeklyReport}
            onValueChange={setWeeklyReport}
            trackColor={{ true: colors.safe, false: colors.border }}
            thumbColor={colors.white}
          />
        </View>
      </View>

      {/* Data */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Data</Text>
        <TouchableOpacity
          style={styles.row}
          onPress={() => {
            Alert.alert("Clear History", "Delete all check history from this device?", [
              { text: "Cancel", style: "cancel" },
              { text: "Clear", style: "destructive", onPress: () => pruneOldChecks(0) },
            ]);
          }}
        >
          <View>
            <Text style={[styles.rowLabel, { color: colors.dangerous }]}>Clear local history</Text>
            <Text style={styles.rowDesc}>Delete all checks stored on this device</Text>
          </View>
        </TouchableOpacity>
      </View>

      {/* About */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        <TouchableOpacity style={styles.row} onPress={() => Linking.openURL("https://cleanway.ai/privacy-policy")}>
          <Text style={styles.rowLabel}>Privacy Policy</Text>
          <Text style={styles.rowArrow}>&rarr;</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.row} onPress={() => Linking.openURL("https://cleanway.ai/terms")}>
          <Text style={styles.rowLabel}>Terms of Service</Text>
          <Text style={styles.rowArrow}>&rarr;</Text>
        </TouchableOpacity>
        <View style={styles.row}>
          <Text style={styles.rowLabel}>Version</Text>
          <Text style={styles.rowDesc}>0.1.0</Text>
        </View>
      </View>

      <Text style={styles.privacyNote}>
        {"\u{1F512}"} Your browsing data lives only on this device
      </Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  section: { backgroundColor: colors.bgCard, borderRadius: 14, marginBottom: spacing.lg, overflow: "hidden" },
  sectionTitle: {
    color: colors.textMuted, fontSize: fontSize.xs, fontWeight: "600",
    textTransform: "uppercase", letterSpacing: 0.5,
    padding: spacing.md, paddingBottom: spacing.xs,
  },
  row: {
    flexDirection: "row", justifyContent: "space-between", alignItems: "center",
    paddingHorizontal: spacing.md, paddingVertical: 14,
    borderTopWidth: 1, borderTopColor: colors.border,
  },
  rowLabel: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },
  rowDesc: { color: colors.textMuted, fontSize: fontSize.sm, marginTop: 2 },
  rowArrow: { color: colors.textMuted, fontSize: 18 },
  upgradeBtn: {
    backgroundColor: colors.primary, color: colors.white,
    paddingHorizontal: 14, paddingVertical: 6, borderRadius: 6,
    fontSize: fontSize.sm, fontWeight: "700", overflow: "hidden",
  },
  privacyNote: {
    textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm, marginTop: spacing.md,
  },
  rowActive: { backgroundColor: "rgba(34, 197, 94, 0.08)" },
  radioDot: {
    width: 20, height: 20, borderRadius: 10,
    borderWidth: 2, borderColor: colors.border,
  },
  radioDotActive: {
    borderColor: colors.safe,
    backgroundColor: colors.safe,
  },
});
