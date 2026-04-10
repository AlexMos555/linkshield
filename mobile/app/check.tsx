import { useState } from "react";
import { View, Text, StyleSheet, TextInput, TouchableOpacity, Alert } from "react-native";
import { useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";

export default function CheckScreen() {
  const router = useRouter();
  const [url, setUrl] = useState("");

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

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Check a Link</Text>
      <Text style={styles.subtitle}>
        Enter any URL or domain to check if it{"'"}s safe.
        Only the domain name is sent for analysis.
      </Text>

      <TextInput
        style={styles.input}
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

      <View style={styles.buttons}>
        <TouchableOpacity style={styles.pasteBtn} onPress={handlePaste}>
          <Text style={styles.pasteBtnText}>{"\u{1F4CB}"} Paste from clipboard</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.checkBtn} onPress={handleCheck}>
          <Text style={styles.checkBtnText}>Check Safety</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, padding: spacing.lg, justifyContent: "center" },
  title: { color: colors.white, fontSize: fontSize.xxl, fontWeight: "800", textAlign: "center" },
  subtitle: {
    color: colors.textSecondary, fontSize: fontSize.md, textAlign: "center",
    marginVertical: spacing.lg, lineHeight: 22,
  },
  input: {
    backgroundColor: colors.bgCard, borderRadius: 12, padding: 16,
    color: colors.text, fontSize: fontSize.lg, borderWidth: 1, borderColor: colors.border,
    marginBottom: spacing.md,
  },
  buttons: { gap: spacing.sm },
  pasteBtn: {
    backgroundColor: colors.bgCard, borderRadius: 10, padding: 14,
    alignItems: "center", borderWidth: 1, borderColor: colors.border,
  },
  pasteBtnText: { color: colors.textSecondary, fontSize: fontSize.md },
  checkBtn: { backgroundColor: colors.accent, borderRadius: 10, padding: 16, alignItems: "center" },
  checkBtnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
});
