import { useState, useEffect, useCallback } from "react";
import {
  View, Text, StyleSheet, TouchableOpacity, TextInput,
  ScrollView, Alert, AppState, Platform,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import * as Haptics from "expo-haptics";
import * as Clipboard from "expo-clipboard";
import { colors, spacing, fontSize } from "../../src/utils/theme";
import { getStats } from "../../src/services/database";
import { getProtectionStatus, startProtection, stopProtection } from "../../src/services/vpn-manager";

export default function HomeScreen() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [protection, setProtection] = useState(getProtectionStatus());
  const [clipboardUrl, setClipboardUrl] = useState<string | null>(null);

  // Reload stats when tab is focused
  useFocusEffect(
    useCallback(() => {
      getStats().then(setStats).catch(() => {});
      checkClipboard();
    }, [])
  );

  // Check clipboard for URLs when app comes to foreground
  useEffect(() => {
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "active") checkClipboard();
    });
    return () => sub.remove();
  }, []);

  async function checkClipboard() {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && (text.startsWith("http://") || text.startsWith("https://") || text.match(/^[a-z0-9][-a-z0-9]*\.[a-z]{2,}/i))) {
        setClipboardUrl(text);
      } else {
        setClipboardUrl(null);
      }
    } catch {
      setClipboardUrl(null);
    }
  }

  function handleCheck() {
    const domain = url.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    if (!domain || !domain.includes(".")) {
      Alert.alert("Invalid URL", "Please enter a valid domain or URL.");
      return;
    }
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    router.push({ pathname: "/result", params: { domain } });
  }

  function handleClipboardCheck() {
    if (!clipboardUrl) return;
    const domain = clipboardUrl.replace(/^https?:\/\//, "").split("/")[0];
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    router.push({ pathname: "/result", params: { domain } });
    setClipboardUrl(null);
  }

  async function toggleProtection() {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    if (protection.active) {
      await stopProtection();
    } else {
      await startProtection();
    }
    setProtection(getProtectionStatus());
  }

  const modeLabels = { vpn: "VPN Protection", dns: "DNS Protection", manual: "Manual Mode" };

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Shield */}
      <TouchableOpacity style={styles.shieldContainer} onPress={toggleProtection} activeOpacity={0.7}>
        <View style={[styles.shield, protection.active ? styles.shieldOn : styles.shieldOff]}>
          <Text style={styles.shieldIcon}>{protection.active ? "\u{1F6E1}" : "\u26A0"}</Text>
        </View>
        <Text style={[styles.shieldLabel, { color: protection.active ? colors.safe : colors.caution }]}>
          {protection.active ? "Protected" : "Tap to Enable"}
        </Text>
        <Text style={styles.modeBadge}>{modeLabels[protection.mode]}</Text>
      </TouchableOpacity>

      {/* Clipboard Banner */}
      {clipboardUrl && (
        <TouchableOpacity style={styles.clipboardBanner} onPress={handleClipboardCheck} activeOpacity={0.8}>
          <Text style={styles.clipIcon}>{"\u{1F4CB}"}</Text>
          <View style={{ flex: 1 }}>
            <Text style={styles.clipTitle}>Link in clipboard</Text>
            <Text style={styles.clipUrl} numberOfLines={1}>{clipboardUrl}</Text>
          </View>
          <Text style={styles.clipAction}>Check &rarr;</Text>
        </TouchableOpacity>
      )}

      {/* Quick Check */}
      <View style={styles.card}>
        <Text style={styles.cardTitle}>Check a Link</Text>
        <View style={styles.inputRow}>
          <TextInput
            style={styles.input}
            placeholder="example.com"
            placeholderTextColor={colors.textMuted}
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            returnKeyType="go"
            onSubmitEditing={handleCheck}
          />
          <TouchableOpacity style={styles.checkBtn} onPress={handleCheck}>
            <Text style={styles.checkBtnText}>Check</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Stats */}
      <View style={styles.statsGrid}>
        <View style={styles.statCard}>
          <Text style={styles.statNum}>{stats.total_checks}</Text>
          <Text style={styles.statLabel}>Checked</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={[styles.statNum, { color: colors.dangerous }]}>{stats.threats_blocked}</Text>
          <Text style={styles.statLabel}>Blocked</Text>
        </View>
        <View style={styles.statCard}>
          <Text style={[styles.statNum, { color: colors.caution }]}>{stats.threats_warned}</Text>
          <Text style={styles.statLabel}>Warned</Text>
        </View>
      </View>

      {/* Quick Actions */}
      <View style={styles.actionsGrid}>
        <TouchableOpacity style={styles.actionBtn} onPress={() => router.push("/breach")}>
          <Text style={styles.actionIcon}>{"\u{1F513}"}</Text>
          <Text style={styles.actionText}>Breach Check</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={() => router.push("/check")}>
          <Text style={styles.actionIcon}>{"\u{1F517}"}</Text>
          <Text style={styles.actionText}>Check URL</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={() => router.push("/(tabs)/score")}>
          <Text style={styles.actionIcon}>{"\u{1F3AF}"}</Text>
          <Text style={styles.actionText}>Score</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={() => router.push("/scanner")}>
          <Text style={styles.actionIcon}>{"\u{1F4F7}"}</Text>
          <Text style={styles.actionText}>QR Scan</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.privacyNote}>{"\u{1F512}"} All data stays on your device</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 120 },

  shieldContainer: { alignItems: "center", marginVertical: spacing.xl },
  shield: {
    width: 130, height: 130, borderRadius: 65,
    alignItems: "center", justifyContent: "center", marginBottom: spacing.md,
  },
  shieldOn: { backgroundColor: colors.safeBg, borderWidth: 3, borderColor: colors.safe },
  shieldOff: { backgroundColor: colors.cautionBg, borderWidth: 3, borderColor: colors.caution },
  shieldIcon: { fontSize: 52 },
  shieldLabel: { fontSize: fontSize.xl, fontWeight: "800" },
  modeBadge: {
    color: colors.textMuted, fontSize: fontSize.xs, marginTop: 6,
    backgroundColor: colors.bgCard, paddingHorizontal: 12, paddingVertical: 4,
    borderRadius: 12, overflow: "hidden",
  },

  clipboardBanner: {
    flexDirection: "row", alignItems: "center", gap: spacing.md,
    backgroundColor: colors.primaryBg, borderRadius: 12, padding: spacing.md,
    marginBottom: spacing.lg, borderWidth: 1, borderColor: colors.primary + "40",
  },
  clipIcon: { fontSize: 24 },
  clipTitle: { color: colors.primary, fontSize: fontSize.sm, fontWeight: "600" },
  clipUrl: { color: colors.textSecondary, fontSize: fontSize.xs, marginTop: 2 },
  clipAction: { color: colors.primary, fontWeight: "700", fontSize: fontSize.md },

  card: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  cardTitle: { color: colors.white, fontSize: fontSize.lg, fontWeight: "700", marginBottom: spacing.md },
  inputRow: { flexDirection: "row", gap: spacing.sm },
  input: {
    flex: 1, backgroundColor: colors.bgInput, borderRadius: 10,
    padding: 14, color: colors.text, fontSize: fontSize.md,
    borderWidth: 1, borderColor: colors.border,
  },
  checkBtn: { backgroundColor: colors.accent, borderRadius: 10, paddingHorizontal: 20, justifyContent: "center" },
  checkBtnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.md },

  statsGrid: { flexDirection: "row", gap: spacing.sm, marginBottom: spacing.lg },
  statCard: { flex: 1, backgroundColor: colors.bgCard, borderRadius: 12, padding: spacing.md, alignItems: "center" },
  statNum: { fontSize: 24, fontWeight: "800", color: colors.white },
  statLabel: { fontSize: fontSize.xs, color: colors.textMuted, marginTop: 4 },

  actionsGrid: { flexDirection: "row", flexWrap: "wrap", gap: spacing.sm, marginBottom: spacing.lg },
  actionBtn: {
    width: "48%", backgroundColor: colors.bgCard, borderRadius: 12,
    padding: spacing.lg, alignItems: "center", borderWidth: 1, borderColor: colors.border,
  },
  actionIcon: { fontSize: 28, marginBottom: 8 },
  actionText: { color: colors.textSecondary, fontSize: fontSize.sm, fontWeight: "600" },

  privacyNote: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm },
});
