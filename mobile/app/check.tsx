import { useState, useEffect } from "react";
import { View, Text, StyleSheet, TextInput, TouchableOpacity, Alert, ScrollView } from "react-native";
import { useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { getRecentChecks } from "../src/services/database";

export default function CheckScreen() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    getRecentChecks(10).then(checks => {
      const domains = [...new Set(checks.map((c: any) => c.domain))].slice(0, 5);
      setRecent(domains);
    }).catch(() => {});
  }, []);

  function handleCheck() {
    const domain = url.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    if (!domain || !domain.includes(".")) {
      Alert.alert("Invalid URL", "Please enter a valid domain or URL.");
      return;
    }
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    router.push({ pathname: "/result", params: { domain } });
  }

  async function handlePaste() {
    const text = await Clipboard.getStringAsync();
    if (text) {
      setUrl(text);
      Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    }
  }

  function quickCheck(domain: string) {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    router.push({ pathname: "/result", params: { domain } });
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.title}>Check a Link</Text>
      <Text style={s.subtitle}>Paste any URL or domain to check safety</Text>

      <TextInput
        style={s.input}
        placeholder="https://example.com or example.com"
        placeholderTextColor={colors.textMuted}
        value={url}
        onChangeText={setUrl}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        returnKeyType="go"
        onSubmitEditing={handleCheck}
        autoFocus
      />

      <View style={s.buttons}>
        <TouchableOpacity style={s.pasteBtn} onPress={handlePaste}>
          <Text style={s.pasteBtnText}>{"\u{1F4CB}"} Paste from clipboard</Text>
        </TouchableOpacity>
        <TouchableOpacity style={s.checkBtn} onPress={handleCheck}>
          <Text style={s.checkBtnText}>Check Safety</Text>
        </TouchableOpacity>
      </View>

      {/* Quick test domains */}
      <Text style={s.sectionTitle}>Try these</Text>
      <View style={s.quickGrid}>
        {["google.com", "paypa1-verify.tk", "pay-pal.com", "evil.netlify.app"].map(d => (
          <TouchableOpacity key={d} style={s.quickChip} onPress={() => quickCheck(d)}>
            <Text style={s.quickText}>{d}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {/* Recent */}
      {recent.length > 0 && (
        <>
          <Text style={s.sectionTitle}>Recent</Text>
          <View style={s.quickGrid}>
            {recent.map(d => (
              <TouchableOpacity key={d} style={s.recentChip} onPress={() => quickCheck(d)}>
                <Text style={s.recentText}>{d}</Text>
              </TouchableOpacity>
            ))}
          </View>
        </>
      )}
    </ScrollView>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  title: { fontSize: fontSize.xxl, fontWeight: "800", color: colors.white, textAlign: "center", marginTop: spacing.xl },
  subtitle: { fontSize: fontSize.md, color: colors.textSecondary, textAlign: "center", marginBottom: spacing.xl },
  input: {
    backgroundColor: colors.bgCard, borderRadius: 14, padding: 18,
    color: colors.text, fontSize: fontSize.lg, borderWidth: 1, borderColor: colors.border,
    marginBottom: spacing.md,
  },
  buttons: { gap: spacing.sm, marginBottom: spacing.xl },
  pasteBtn: {
    backgroundColor: colors.bgCard, borderRadius: 12, padding: 14,
    alignItems: "center", borderWidth: 1, borderColor: colors.border,
  },
  pasteBtnText: { color: colors.textSecondary, fontSize: fontSize.md },
  checkBtn: { backgroundColor: colors.accent, borderRadius: 12, padding: 16, alignItems: "center" },
  checkBtnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
  sectionTitle: {
    color: colors.textMuted, fontSize: fontSize.xs, fontWeight: "600",
    textTransform: "uppercase", letterSpacing: 0.5, marginBottom: spacing.sm,
  },
  quickGrid: { flexDirection: "row", flexWrap: "wrap", gap: spacing.sm, marginBottom: spacing.lg },
  quickChip: {
    backgroundColor: colors.bgCard, borderRadius: 20, paddingHorizontal: 14, paddingVertical: 8,
    borderWidth: 1, borderColor: colors.border,
  },
  quickText: { color: colors.textSecondary, fontSize: fontSize.sm },
  recentChip: {
    backgroundColor: colors.primaryBg, borderRadius: 20, paddingHorizontal: 14, paddingVertical: 8,
    borderWidth: 1, borderColor: colors.primary + "30",
  },
  recentText: { color: colors.primary, fontSize: fontSize.sm },
});
