import { useState, useEffect, useCallback } from "react";
import {
  View, Text, StyleSheet, TouchableOpacity,
  ScrollView, Alert, AppState, Linking, Platform,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import * as Haptics from "expo-haptics";
import * as Clipboard from "expo-clipboard";
import { colors, spacing, fontSize } from "../../src/utils/theme";
import { getStats, saveCheck } from "../../src/services/database";
import { checkSingleDomain } from "../../src/services/api";

export default function HomeScreen() {
  const router = useRouter();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [isProtected, setIsProtected] = useState(true);
  const [clipboardUrl, setClipboardUrl] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<any>(null);
  const [checking, setChecking] = useState(false);

  // Reload on focus
  useFocusEffect(useCallback(() => {
    getStats().then(setStats).catch(() => {});
    checkClipboard();
  }, []));

  // Auto-check clipboard when app opens
  useEffect(() => {
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "active") checkClipboard();
    });
    checkClipboard();
    return () => sub.remove();
  }, []);

  // Handle incoming shared URLs (deep links)
  useEffect(() => {
    const handleUrl = ({ url }: { url: string }) => {
      if (url) autoCheck(extractDomain(url));
    };
    const sub = Linking.addEventListener("url", handleUrl);
    Linking.getInitialURL().then(url => { if (url) handleUrl({ url }); });
    return () => sub.remove();
  }, []);

  async function checkClipboard() {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && isUrl(text) && text !== clipboardUrl) {
        setClipboardUrl(text);
      }
    } catch {}
  }

  function extractDomain(url: string): string {
    try {
      if (url.startsWith("http")) return new URL(url).hostname;
    } catch {}
    return url.split("/")[0].toLowerCase();
  }

  function isUrl(text: string): boolean {
    return /^https?:\/\//i.test(text) || /^[a-z0-9][-a-z0-9]*\.[a-z]{2,}/i.test(text.trim());
  }

  async function autoCheck(domain: string) {
    if (!domain || !domain.includes(".") || checking) return;
    setChecking(true);
    setClipboardUrl(null);

    try {
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
      const result = await checkSingleDomain(domain);
      await saveCheck(result);
      setLastChecked(result);
      setStats(await getStats());

      if (result.level === "dangerous") {
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
        Alert.alert(
          "\u26A0\uFE0F Dangerous Link!",
          `${domain} scored ${result.score}/100.\n\n${result.reasons?.[0]?.detail || "Multiple risk signals detected."}`,
          [
            { text: "Details", onPress: () => router.push({ pathname: "/result", params: { domain } }) },
            { text: "OK", style: "cancel" },
          ]
        );
      } else if (result.level === "caution") {
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      } else {
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      }
    } catch (e) {
      Alert.alert("Check Failed", "Could not reach server. Try again.");
    } finally {
      setChecking(false);
    }
  }

  const levelColors: Record<string, string> = { safe: colors.safe, caution: colors.caution, dangerous: colors.dangerous };
  const levelIcons: Record<string, string> = { safe: "\u2705", caution: "\u26A0\uFE0F", dangerous: "\u274C" };
  const levelLabels: Record<string, string> = { safe: "Safe", caution: "Caution", dangerous: "Dangerous" };

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>

      {/* Shield */}
      <TouchableOpacity
        style={s.shieldWrap}
        onPress={() => { setIsProtected(!isProtected); Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium); }}
        activeOpacity={0.7}
      >
        <View style={[s.shield, isProtected ? s.shieldOn : s.shieldOff]}>
          <Text style={s.shieldIcon}>{isProtected ? "\u{1F6E1}" : "\u26A0"}</Text>
        </View>
        <Text style={[s.shieldLabel, { color: isProtected ? colors.safe : colors.caution }]}>
          {isProtected ? "Protected" : "Protection Off"}
        </Text>
        <Text style={s.shieldSub}>
          {isProtected ? "Monitoring links from clipboard & shared URLs" : "Tap to enable"}
        </Text>
      </TouchableOpacity>

      {/* Clipboard detection — this is the core UX */}
      {clipboardUrl && (
        <TouchableOpacity
          style={s.clipBanner}
          onPress={() => autoCheck(extractDomain(clipboardUrl))}
          activeOpacity={0.8}
        >
          <View style={s.clipLeft}>
            <Text style={s.clipIcon}>{"\u{1F517}"}</Text>
            <View style={{ flex: 1 }}>
              <Text style={s.clipTitle}>Link detected in clipboard</Text>
              <Text style={s.clipUrl} numberOfLines={1}>{clipboardUrl}</Text>
            </View>
          </View>
          <View style={s.clipBtn}>
            <Text style={s.clipBtnText}>Check</Text>
          </View>
        </TouchableOpacity>
      )}

      {/* Last checked result */}
      {lastChecked && (
        <TouchableOpacity
          style={[s.lastResult, { borderColor: (levelColors[lastChecked.level] || colors.border) + "40" }]}
          onPress={() => router.push({ pathname: "/result", params: { domain: lastChecked.domain } })}
        >
          <Text style={s.lastIcon}>{levelIcons[lastChecked.level] || "\u2753"}</Text>
          <View style={{ flex: 1 }}>
            <Text style={s.lastDomain}>{lastChecked.domain}</Text>
            <Text style={[s.lastLevel, { color: levelColors[lastChecked.level] || colors.textMuted }]}>
              {levelLabels[lastChecked.level] || "Unknown"} — Score: {lastChecked.score}/100
            </Text>
          </View>
          <Text style={s.lastArrow}>&rarr;</Text>
        </TouchableOpacity>
      )}

      {/* Stats */}
      <View style={s.statsRow}>
        <View style={s.stat}>
          <Text style={s.statNum}>{stats.total_checks}</Text>
          <Text style={s.statLabel}>Checked</Text>
        </View>
        <View style={s.stat}>
          <Text style={[s.statNum, { color: colors.dangerous }]}>{stats.threats_blocked}</Text>
          <Text style={s.statLabel}>Blocked</Text>
        </View>
        <View style={s.stat}>
          <Text style={[s.statNum, { color: colors.caution }]}>{stats.threats_warned}</Text>
          <Text style={s.statLabel}>Warned</Text>
        </View>
      </View>

      {/* Quick Actions */}
      <Text style={s.sectionTitle}>Tools</Text>
      <View style={s.actionsGrid}>
        <TouchableOpacity style={s.action} onPress={() => router.push("/check")}>
          <Text style={s.actionIcon}>{"\u{1F517}"}</Text>
          <Text style={s.actionText}>Check URL</Text>
        </TouchableOpacity>
        <TouchableOpacity style={s.action} onPress={() => router.push("/scanner")}>
          <Text style={s.actionIcon}>{"\u{1F4F7}"}</Text>
          <Text style={s.actionText}>QR Scan</Text>
        </TouchableOpacity>
        <TouchableOpacity style={s.action} onPress={() => router.push("/breach")}>
          <Text style={s.actionIcon}>{"\u{1F513}"}</Text>
          <Text style={s.actionText}>Breach Check</Text>
        </TouchableOpacity>
        <TouchableOpacity style={s.action} onPress={() => router.push("/report")}>
          <Text style={s.actionIcon}>{"\u{1F4CA}"}</Text>
          <Text style={s.actionText}>Weekly Report</Text>
        </TouchableOpacity>
      </View>

      {/* How it works */}
      <View style={s.howCard}>
        <Text style={s.howTitle}>How Cleanway protects you</Text>
        <View style={s.howRow}>
          <Text style={s.howIcon}>{"\u{1F4CB}"}</Text>
          <Text style={s.howText}>Copy a link anywhere — we detect and check it automatically</Text>
        </View>
        <View style={s.howRow}>
          <Text style={s.howIcon}>{"\u{1F4E4}"}</Text>
          <Text style={s.howText}>Share a link from any app → Cleanway checks it</Text>
        </View>
        <View style={s.howRow}>
          <Text style={s.howIcon}>{"\u{1F4F7}"}</Text>
          <Text style={s.howText}>Scan QR codes — we check the URL before you open it</Text>
        </View>
        <View style={s.howRow}>
          <Text style={s.howIcon}>{"\u{1F6E1}"}</Text>
          <Text style={s.howText}>VPN mode blocks dangerous sites before they load</Text>
        </View>
      </View>

      <Text style={s.privacy}>{"\u{1F512}"} Your browsing data never leaves this device</Text>
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 120 },

  shieldWrap: { alignItems: "center", marginVertical: spacing.lg },
  shield: { width: 120, height: 120, borderRadius: 60, alignItems: "center", justifyContent: "center", marginBottom: spacing.md },
  shieldOn: { backgroundColor: colors.safeBg, borderWidth: 3, borderColor: colors.safe },
  shieldOff: { backgroundColor: colors.cautionBg, borderWidth: 3, borderColor: colors.caution },
  shieldIcon: { fontSize: 48 },
  shieldLabel: { fontSize: fontSize.xl, fontWeight: "800" },
  shieldSub: { color: colors.textMuted, fontSize: fontSize.xs, marginTop: 4, textAlign: "center" },

  clipBanner: {
    flexDirection: "row", alignItems: "center", justifyContent: "space-between",
    backgroundColor: colors.primaryBg, borderRadius: 14, padding: spacing.md,
    marginBottom: spacing.lg, borderWidth: 1, borderColor: colors.primary + "40",
  },
  clipLeft: { flexDirection: "row", alignItems: "center", gap: spacing.sm, flex: 1 },
  clipIcon: { fontSize: 24 },
  clipTitle: { color: colors.primary, fontSize: fontSize.sm, fontWeight: "700" },
  clipUrl: { color: colors.textMuted, fontSize: fontSize.xs, marginTop: 2 },
  clipBtn: { backgroundColor: colors.primary, paddingHorizontal: 16, paddingVertical: 8, borderRadius: 8 },
  clipBtnText: { color: "white", fontWeight: "700", fontSize: fontSize.sm },

  lastResult: {
    flexDirection: "row", alignItems: "center", gap: spacing.md,
    backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.md,
    marginBottom: spacing.lg, borderWidth: 1,
  },
  lastIcon: { fontSize: 28 },
  lastDomain: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },
  lastLevel: { fontSize: fontSize.sm, marginTop: 2 },
  lastArrow: { color: colors.textMuted, fontSize: 20 },

  statsRow: { flexDirection: "row", gap: spacing.sm, marginBottom: spacing.lg },
  stat: { flex: 1, backgroundColor: colors.bgCard, borderRadius: 12, padding: spacing.md, alignItems: "center" },
  statNum: { fontSize: 24, fontWeight: "800", color: colors.white },
  statLabel: { fontSize: fontSize.xs, color: colors.textMuted, marginTop: 4 },

  sectionTitle: { color: colors.textMuted, fontSize: fontSize.xs, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: spacing.sm },

  actionsGrid: { flexDirection: "row", flexWrap: "wrap", gap: spacing.sm, marginBottom: spacing.lg },
  action: { width: "48%" as any, backgroundColor: colors.bgCard, borderRadius: 12, padding: spacing.lg, alignItems: "center", borderWidth: 1, borderColor: colors.border },
  actionIcon: { fontSize: 28, marginBottom: 8 },
  actionText: { color: colors.textSecondary, fontSize: fontSize.sm, fontWeight: "600" },

  howCard: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  howTitle: { color: colors.white, fontSize: fontSize.md, fontWeight: "700", marginBottom: spacing.md },
  howRow: { flexDirection: "row", alignItems: "flex-start", gap: spacing.sm, marginBottom: spacing.sm },
  howIcon: { fontSize: 16, marginTop: 2 },
  howText: { color: colors.textSecondary, fontSize: fontSize.sm, flex: 1, lineHeight: 20 },

  privacy: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.xs },
});
