import { useState, useEffect } from "react";
import { View, Text, StyleSheet, TextInput, TouchableOpacity, Alert, ScrollView } from "react-native";
import { useRouter, useLocalSearchParams } from "expo-router";
import * as Clipboard from "expo-clipboard";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { colors, type as t, space, radius, sectionHeader } from "../src/utils/theme";
import { getRecentChecks } from "../src/services/database";

export default function CheckScreen() {
  const router = useRouter();
  // paste=1: user tapped "Paste link" on the home card — an explicit action,
  // so reading the clipboard here is intentional (passive monitoring is killed).
  const { paste } = useLocalSearchParams<{ paste?: string }>();
  const [url, setUrl] = useState("");
  const [focused, setFocused] = useState(false);
  const [recent, setRecent] = useState<string[]>([]);

  useEffect(() => {
    getRecentChecks(10).then(checks => {
      const domains = [...new Set(checks.map((c: any) => c.domain))].slice(0, 5);
      setRecent(domains);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (paste === "1") void handlePaste();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paste]);

  function handleCheck() {
    const domain = url.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    if (!domain || !domain.includes(".")) {
      Alert.alert(
        "That doesn't look like a link",
        "Type a website name like example.com, or paste the whole link."
      );
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
    <ScrollView style={s.container} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled">
      <Text style={s.title}>Check a link</Text>
      <Text style={s.subtitle}>Paste any link or type a website name</Text>

      <TextInput
        style={[s.input, focused && s.inputFocused]}
        placeholder="example.com or paste a full link"
        placeholderTextColor={colors.textMuted}
        value={url}
        onChangeText={setUrl}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="url"
        returnKeyType="go"
        onSubmitEditing={handleCheck}
        autoFocus
      />

      <View style={s.buttons}>
        <TouchableOpacity style={s.pasteBtn} onPress={handlePaste} activeOpacity={0.85}>
          <Ionicons name="clipboard-outline" size={18} color={colors.textSecondary} />
          <Text style={s.pasteBtnText}>Paste from clipboard</Text>
        </TouchableOpacity>
        <TouchableOpacity style={s.checkBtn} onPress={handleCheck} activeOpacity={0.85}>
          <Text style={s.checkBtnText}>Check it</Text>
        </TouchableOpacity>
      </View>

      <Text style={s.sectionTitle}>Try these</Text>
      <View style={s.chipGrid}>
        {["google.com", "paypa1-verify.tk", "pay-pal.com", "evil.netlify.app"].map(d => (
          <TouchableOpacity key={d} style={s.tryChip} onPress={() => quickCheck(d)} activeOpacity={0.85}>
            <Text style={s.tryText}>{d}</Text>
          </TouchableOpacity>
        ))}
      </View>

      {recent.length > 0 && (
        <>
          <Text style={s.sectionTitle}>Recent</Text>
          <View style={s.chipGrid}>
            {recent.map(d => (
              <TouchableOpacity key={d} style={s.recentChip} onPress={() => quickCheck(d)} activeOpacity={0.85}>
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
  content: { paddingHorizontal: space.xl, paddingBottom: 100 },
  title: { ...t.title1, color: colors.textPrimary, marginTop: space.sm },
  subtitle: { ...t.body, color: colors.textSecondary, marginTop: 4, marginBottom: space.xxl },
  input: {
    height: 56,
    backgroundColor: colors.surfaceRaised,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control,
    paddingHorizontal: space.lg,
    color: colors.textPrimary, fontSize: 17,
    marginBottom: space.md,
  },
  inputFocused: { borderColor: colors.blue },
  buttons: { gap: space.sm, marginBottom: space.xxl + 4 },
  checkBtn: {
    height: 50, backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center",
  },
  checkBtnText: { color: "#FFFFFF", fontWeight: "600", fontSize: 17 },
  pasteBtn: {
    height: 50, flexDirection: "row", gap: space.sm,
    backgroundColor: colors.surface, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center",
    borderWidth: 1, borderColor: colors.stroke,
  },
  pasteBtnText: { color: colors.textSecondary, fontSize: 15, fontWeight: "600" },
  sectionTitle: { ...sectionHeader, marginBottom: space.sm },
  chipGrid: { flexDirection: "row", flexWrap: "wrap", gap: space.sm, marginBottom: space.xl },
  tryChip: {
    height: 36, justifyContent: "center",
    backgroundColor: colors.surface, borderRadius: radius.chip, paddingHorizontal: space.md,
    borderWidth: 1, borderColor: colors.stroke,
  },
  tryText: { color: colors.textSecondary, fontSize: 13, fontWeight: "600" },
  recentChip: {
    height: 36, justifyContent: "center",
    backgroundColor: colors.blueWash, borderRadius: radius.chip, paddingHorizontal: space.md,
    borderWidth: 1, borderColor: "#4C8DFF40",
  },
  recentText: { color: colors.blue, fontSize: 13, fontWeight: "600" },
});
