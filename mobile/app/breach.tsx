import { useState } from "react";
import {
  View, Text, StyleSheet, TextInput, TouchableOpacity, ScrollView, ActivityIndicator,
} from "react-native";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../src/utils/theme";
import { checkBreach } from "../src/services/api";

/**
 * Leaked-password check.
 *
 * Honesty contract: /api/v1/breach/check proxies HIBP's Pwned PASSWORDS
 * range API, so hashing an email and looking it up answers "has this string
 * leaked as somebody's password?" — NOT "which breaches was this address
 * in?". The extension twin (packages/extension-core/src/content/breach-check.js)
 * was disabled in 2026-06 for claiming the latter; here the copy states what
 * the lookup really does. A real breach report needs HIBP /breachedaccount.
 */

type BreachState =
  | { kind: "found"; count: number }
  | { kind: "clear" }
  | { kind: "error" };

export default function BreachScreen() {
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [focused, setFocused] = useState(false);
  const [result, setResult] = useState<BreachState | null>(null);
  const [loading, setLoading] = useState(false);

  const trimmed = email.trim().toLowerCase();
  const canCheck = trimmed.includes("@") && !loading;

  async function handleCheck() {
    if (!trimmed || !trimmed.includes("@")) return;

    setLoading(true);
    setResult(null);

    try {
      // SHA-1 hash on device using pure JS (no crypto.subtle needed)
      const hash = sha1(trimmed);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);

      const data = await checkBreach(prefix);
      const match = data.suffixes?.find(s => s.suffix === suffix);

      // The API deliberately returns padding rows with count 0 so a network
      // observer can't size-match a real hit. A padding row is not a hit, so
      // only a positive count may be shown as "found" — otherwise the card
      // reads "turned up 0 times", which is nonsense and scares people.
      if (match && match.count > 0) {
        setResult({ kind: "found", count: match.count });
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      } else {
        setResult({ kind: "clear" });
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      }
    } catch {
      setResult({ kind: "error" });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled">
      <Text style={s.title}>{t("mobile.breach.title")}</Text>
      <Text style={s.subtitle}>{t("mobile.breach.subtitle")}</Text>

      <View style={s.noteRow}>
        <Ionicons name="information-circle-outline" size={13} color={colors.textSecondary} />
        <Text style={s.note}>{t("mobile.breach.scope_note")}</Text>
      </View>

      <TextInput
        style={[s.input, focused && s.inputFocused]}
        placeholder={t("mobile.breach.placeholder")}
        placeholderTextColor={colors.textMuted}
        value={email}
        onChangeText={setEmail}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        autoCapitalize="none"
        autoCorrect={false}
        keyboardType="email-address"
        returnKeyType="go"
        onSubmitEditing={handleCheck}
        accessibilityLabel={t("mobile.breach.input_label")}
      />

      <TouchableOpacity
        style={[s.submit, !canCheck && s.submitDisabled]}
        onPress={handleCheck}
        disabled={!canCheck}
        activeOpacity={0.85}
        accessibilityRole="button"
        accessibilityState={{ disabled: !canCheck, busy: loading }}
        accessibilityLabel={t("mobile.breach.submit")}
      >
        {loading
          ? <ActivityIndicator color="#FFFFFF" />
          : <Text style={s.submitLabel}>{t("mobile.breach.submit")}</Text>}
      </TouchableOpacity>

      {result && <ResultCard state={result} />}

      <Text style={s.sectionTitle}>{t("mobile.breach.how_title")}</Text>
      <View style={s.card}>
        {[1, 2, 3, 4].map(n => (
          <Step key={n} n={n} text={t(`mobile.breach.how_step_${n}`)} first={n === 1} />
        ))}
      </View>

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>{t("mobile.breach.privacy")}</Text>
      </View>
    </ScrollView>
  );
}

// Colour is never the only cue: each tone carries an icon and a text label.
const TONES = {
  found: { color: colors.danger, stroke: colors.dangerStroke, wash: colors.dangerWash, icon: "alert-circle-outline" },
  clear: { color: colors.green, stroke: colors.greenStroke, wash: colors.greenWash, icon: "checkmark-circle-outline" },
  error: { color: colors.amber, stroke: colors.amberStroke, wash: colors.amberWash, icon: "cloud-offline-outline" },
} as const;

function ResultCard({ state }: { state: BreachState }) {
  const { t } = useTranslation();
  const tone = TONES[state.kind];
  const body = state.kind === "found"
    ? t("mobile.breach.found_body", { times: state.count })
    : t(`mobile.breach.${state.kind}_body`);

  return (
    <View style={[s.card, s.resultCard, { borderColor: tone.stroke }]}>
      <View style={[s.resultIcon, { backgroundColor: tone.wash }]}>
        <Ionicons name={tone.icon} size={22} color={tone.color} />
      </View>
      <View style={s.resultBodyCol}>
        <Text style={[s.resultTitle, { color: tone.color }]}>
          {t(`mobile.breach.${state.kind}_title`)}
        </Text>
        <Text style={s.resultText}>{body}</Text>
      </View>
    </View>
  );
}

function Step({ n, text, first }: { n: number; text: string; first?: boolean }) {
  return (
    <View style={[s.step, !first && s.stepBorder]}>
      <View style={s.stepBadge}><Text style={s.stepNum}>{n}</Text></View>
      <Text style={s.stepText}>{text}</Text>
    </View>
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

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  title: { ...typo.title1, color: colors.textPrimary },
  subtitle: { ...typo.body, color: colors.textSecondary, marginTop: 4 },

  noteRow: { flexDirection: "row", alignItems: "flex-start", gap: 6, marginTop: space.md, marginBottom: space.xl },
  note: { ...typo.caption, color: colors.textSecondary, flex: 1 },

  input: {
    height: 56, backgroundColor: colors.surfaceRaised, borderWidth: 1,
    borderColor: colors.stroke, borderRadius: radius.control, marginBottom: space.md,
    paddingHorizontal: space.lg, color: colors.textPrimary, fontSize: 17,
  },
  inputFocused: { borderColor: colors.blue },
  submit: {
    height: 50, backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginBottom: space.xxl,
  },
  submitDisabled: { opacity: 0.4 },
  submitLabel: { color: "#FFFFFF", fontSize: 17, fontWeight: "600" },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  resultCard: { flexDirection: "row", gap: space.md, marginBottom: space.xxl },
  resultIcon: {
    width: 40, height: 40, borderRadius: radius.icon,
    alignItems: "center", justifyContent: "center",
  },
  resultBodyCol: { flex: 1 },
  resultTitle: { ...typo.headline },
  resultText: { ...typo.body, color: colors.textSecondary, marginTop: 4 },

  sectionTitle: { ...sectionHeader, marginBottom: space.sm },
  step: { flexDirection: "row", alignItems: "center", gap: space.md, paddingVertical: 10 },
  stepBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  stepBadge: {
    width: 24, height: 24, borderRadius: 12, backgroundColor: colors.blueWash,
    alignItems: "center", justifyContent: "center",
  },
  stepNum: { fontSize: 13, fontWeight: "600", color: colors.blue },
  stepText: { ...typo.body, color: colors.textSecondary, flex: 1 },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
