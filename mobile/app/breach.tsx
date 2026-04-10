import { useState } from "react";
import {
  View, Text, StyleSheet, TextInput, TouchableOpacity, ScrollView, ActivityIndicator,
} from "react-native";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { checkBreach } from "../src/services/api";

export default function BreachScreen() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function handleCheck() {
    const trimmed = email.trim().toLowerCase();
    if (!trimmed || !trimmed.includes("@")) return;

    setLoading(true);
    setResult(null);

    try {
      // SHA-1 hash on device using pure JS (no crypto.subtle needed)
      const hash = sha1(trimmed);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);

      const data = await checkBreach(prefix);
      const match = data.suffixes?.find((s: any) => s.suffix === suffix);

      if (match) {
        setResult({ breached: true, count: match.count });
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      } else {
        setResult({ breached: false, count: 0 });
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      }
    } catch (e) {
      setResult({ error: "Could not check. Try again later." });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.icon}>{"\u{1F513}"}</Text>
        <Text style={styles.title}>Breach Check</Text>
        <Text style={styles.subtitle}>
          Check if your email appeared in data breaches.{"\n"}
          Your email is hashed on-device — we never see it.
        </Text>
      </View>

      <View style={styles.inputCard}>
        <TextInput
          style={styles.input}
          placeholder="your@email.com"
          placeholderTextColor={colors.textMuted}
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
          returnKeyType="go"
          onSubmitEditing={handleCheck}
        />
        <TouchableOpacity
          style={[styles.btn, loading && styles.btnDisabled]}
          onPress={handleCheck}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color={colors.white} />
          ) : (
            <Text style={styles.btnText}>Check</Text>
          )}
        </TouchableOpacity>
      </View>

      {result && !result.error && (
        <View style={[
          styles.resultCard,
          { borderColor: result.breached ? colors.dangerous + "40" : colors.safe + "40" }
        ]}>
          <Text style={styles.resultIcon}>
            {result.breached ? "\u274C" : "\u2705"}
          </Text>
          <Text style={[
            styles.resultTitle,
            { color: result.breached ? colors.dangerous : colors.safe }
          ]}>
            {result.breached ? "Breached!" : "No breaches found"}
          </Text>
          <Text style={styles.resultDesc}>
            {result.breached
              ? `Found in ${result.count} data breach(es). Change your passwords immediately.`
              : "This email was not found in any known data breaches."
            }
          </Text>
        </View>
      )}

      {result?.error && (
        <View style={[styles.resultCard, { borderColor: colors.caution + "40" }]}>
          <Text style={{ color: colors.caution, textAlign: "center" }}>{result.error}</Text>
        </View>
      )}

      <View style={styles.privacyCard}>
        <Text style={styles.privacyTitle}>{"\u{1F512}"} How k-anonymity works</Text>
        <Text style={styles.privacyText}>
          1. Your email is hashed with SHA-1 on this device{"\n"}
          2. Only the first 5 characters of the hash are sent{"\n"}
          3. Server returns ~500 matching suffixes{"\n"}
          4. Your device checks locally if your hash matches{"\n\n"}
          Result: nobody — not even us — ever sees your email or full hash.
        </Text>
      </View>
    </ScrollView>
  );
}

// ── Pure JS SHA-1 (no crypto.subtle needed — works in React Native) ──

function sha1(msg: string): string {
  function rotl(n: number, s: number) { return (n << s) | (n >>> (32 - s)); }

  const msgBytes: number[] = [];
  for (let i = 0; i < msg.length; i++) {
    const c = msg.charCodeAt(i);
    if (c < 0x80) msgBytes.push(c);
    else if (c < 0x800) { msgBytes.push(0xc0 | (c >> 6)); msgBytes.push(0x80 | (c & 0x3f)); }
    else { msgBytes.push(0xe0 | (c >> 12)); msgBytes.push(0x80 | ((c >> 6) & 0x3f)); msgBytes.push(0x80 | (c & 0x3f)); }
  }

  const bitLen = msgBytes.length * 8;
  msgBytes.push(0x80);
  while ((msgBytes.length % 64) !== 56) msgBytes.push(0);
  for (let i = 56; i >= 0; i -= 8) msgBytes.push(0); // high 32 bits = 0
  msgBytes[msgBytes.length - 4] = (bitLen >>> 24) & 0xff;
  msgBytes[msgBytes.length - 3] = (bitLen >>> 16) & 0xff;
  msgBytes[msgBytes.length - 2] = (bitLen >>> 8) & 0xff;
  msgBytes[msgBytes.length - 1] = bitLen & 0xff;

  let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
  const w = new Array(80);

  for (let offset = 0; offset < msgBytes.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = (msgBytes[offset + i * 4] << 24) | (msgBytes[offset + i * 4 + 1] << 16) |
             (msgBytes[offset + i * 4 + 2] << 8) | msgBytes[offset + i * 4 + 3];
    }
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f: number, k: number;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
      else { f = b ^ c ^ d; k = 0xCA62C1D6; }

      const temp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF;
      e = d; d = c; c = rotl(b, 30); b = a; a = temp;
    }

    h0 = (h0 + a) & 0xFFFFFFFF; h1 = (h1 + b) & 0xFFFFFFFF;
    h2 = (h2 + c) & 0xFFFFFFFF; h3 = (h3 + d) & 0xFFFFFFFF;
    h4 = (h4 + e) & 0xFFFFFFFF;
  }

  return [h0, h1, h2, h3, h4].map(v => (v >>> 0).toString(16).padStart(8, "0")).join("").toUpperCase();
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  header: { alignItems: "center", marginBottom: spacing.xl },
  icon: { fontSize: 48, marginBottom: spacing.sm },
  title: { color: colors.white, fontSize: fontSize.xxl, fontWeight: "800" },
  subtitle: { color: colors.textSecondary, fontSize: fontSize.md, textAlign: "center", marginTop: spacing.sm, lineHeight: 22 },
  inputCard: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg, marginBottom: spacing.lg },
  input: {
    backgroundColor: colors.bgInput, borderRadius: 10, padding: 14,
    color: colors.text, fontSize: fontSize.lg, borderWidth: 1, borderColor: colors.border,
    marginBottom: spacing.md,
  },
  btn: { backgroundColor: colors.primary, borderRadius: 10, padding: 14, alignItems: "center" },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: colors.white, fontWeight: "700", fontSize: fontSize.lg },
  resultCard: {
    backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.xl,
    alignItems: "center", marginBottom: spacing.lg, borderWidth: 1,
  },
  resultIcon: { fontSize: 48, marginBottom: spacing.sm },
  resultTitle: { fontSize: fontSize.xl, fontWeight: "800", marginBottom: spacing.sm },
  resultDesc: { color: colors.textSecondary, fontSize: fontSize.md, textAlign: "center", lineHeight: 22 },
  privacyCard: { backgroundColor: colors.bgCard, borderRadius: 14, padding: spacing.lg },
  privacyTitle: { color: colors.white, fontSize: fontSize.md, fontWeight: "700", marginBottom: spacing.md },
  privacyText: { color: colors.textMuted, fontSize: fontSize.sm, lineHeight: 20 },
});
