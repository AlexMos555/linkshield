/**
 * Message check — "is this SMS a scam?", answered on the phone.
 *
 * Reached from the home card (paste the text) or by sharing a message to
 * Cleanway from the SMS app (the share router hands the text over in memory;
 * see src/services/message-handoff.ts).
 *
 * Privacy contract: the text lives in this screen's state and in the native
 * analyzer's memory, and nowhere else — not in a route param, not on disk,
 * not in a log, not on our server. Only the host of a link may be sent, to
 * the same domain-only check as a typed link (useMessageCheck).
 *
 * Android only: the analyzer is part of the local native module. Anywhere
 * else the screen says so instead of pretending to check.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, TextInput, TouchableOpacity, ActivityIndicator, Keyboard,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import * as Clipboard from "expo-clipboard";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../src/utils/theme";
import { useMessageCheck } from "../src/hooks/useMessageCheck";
import { takeHandedOffMessage } from "../src/services/message-handoff";
import { MessageResult } from "../src/components/message/MessageResult";

export default function MessageScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  // from=share: the share router left the text in the in-memory handoff.
  const { from } = useLocalSearchParams<{ from?: string }>();
  const fromShare = from === "share";
  // Taken exactly once, on the first render; a second take returns null.
  const [shared] = useState(() => (fromShare ? takeHandedOffMessage() : null));
  const [text, setText] = useState(shared ?? "");
  const [focused, setFocused] = useState(false);
  const [clipboardEmpty, setClipboardEmpty] = useState(false);
  const { state, check, retryLinks, reset } = useMessageCheck();
  const autoStarted = useRef(false);

  // Someone who shared a message wants the verdict, not a Check button.
  useEffect(() => {
    if (!shared || autoStarted.current) return;
    autoStarted.current = true;
    void check(shared);
  }, [shared, check]);

  // Same exit as shared.tsx: going back, never stacking a fresh tabs navigator.
  const leave = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

  // Explicit tap only — the clipboard is never read on its own.
  async function paste() {
    try {
      const clip = await Clipboard.getStringAsync();
      if (clip.trim()) {
        setText(clip);
        setClipboardEmpty(false);
        void Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
        return;
      }
    } catch {
      // Unreadable clipboard reads the same as an empty one.
    }
    setClipboardEmpty(true);
  }

  function submit() {
    const trimmed = text.trim();
    if (!trimmed) return;
    Keyboard.dismiss();
    void check(trimmed);
  }

  function another() {
    reset();
    setText("");
    setClipboardEmpty(false);
  }

  if (state.phase === "checking") {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.centerTitle}>{t("mobile.message.checking")}</Text>
        <Text style={s.centerBody}>{t("mobile.message.checking_sub")}</Text>
      </View>
    );
  }

  if (state.phase === "unavailable") {
    const failed = state.reason === "failed";
    return (
      <View style={s.center}>
        <Ionicons name="alert-circle-outline" size={44} color={colors.amber} />
        <Text style={s.centerTitle}>{t("mobile.message.error_title")}</Text>
        <Text style={s.centerBody}>
          {t(failed ? "mobile.message.error_failed" : "mobile.message.error_unsupported")}
        </Text>
        {failed && (
          <TouchableOpacity style={[s.checkBtn, s.fullWidth]} onPress={submit} activeOpacity={0.85} accessibilityRole="button">
            <Text style={s.checkLabel}>{t("mobile.message.try_again")}</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity style={[s.pasteBtn, s.fullWidth]} onPress={leave} activeOpacity={0.85} accessibilityRole="button">
          <Text style={s.pasteLabel}>{t("mobile.message.done")}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (state.phase === "done") {
    return (
      <ScrollView style={s.container} contentContainerStyle={s.content}>
        <MessageResult
          text={text}
          fromShare={fromShare}
          analysis={state.analysis}
          linkChecks={state.linkChecks}
          verdict={state.verdict}
          reasons={state.reasons}
          onRetry={() => void retryLinks()}
          onAnother={another}
          onDone={leave}
        />
        <PrivacyNote />
      </ScrollView>
    );
  }

  const canCheck = text.trim().length > 0;
  return (
    <ScrollView style={s.container} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled">
      <Text style={s.title}>{t("mobile.message.title")}</Text>
      <Text style={s.subtitle}>{t("mobile.message.subtitle")}</Text>

      <TextInput
        style={[s.input, focused && s.inputFocused]}
        value={text}
        onChangeText={(value) => {
          setText(value);
          setClipboardEmpty(false);
        }}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        placeholder={t("mobile.message.placeholder")}
        placeholderTextColor={colors.textMuted}
        accessibilityLabel={t("mobile.message.placeholder")}
        multiline
        textAlignVertical="top"
        // Someone's SMS: no autocorrect learning, no autofill service reading the field.
        autoCorrect={false}
        spellCheck={false}
        autoComplete="off"
        importantForAutofill="no"
      />

      <TouchableOpacity style={s.pasteBtn} onPress={paste} activeOpacity={0.85} accessibilityRole="button">
        <Ionicons name="clipboard-outline" size={20} color={colors.textPrimary} />
        <Text style={s.pasteLabel}>{t("mobile.message.paste")}</Text>
      </TouchableOpacity>
      {clipboardEmpty && <Text style={s.hint}>{t("mobile.message.paste_empty")}</Text>}

      <TouchableOpacity
        style={[s.checkBtn, !canCheck && s.checkBtnDisabled]}
        onPress={submit}
        disabled={!canCheck}
        activeOpacity={0.85}
        accessibilityRole="button"
        accessibilityState={{ disabled: !canCheck }}
      >
        <Text style={s.checkLabel}>{t("mobile.message.submit")}</Text>
      </TouchableOpacity>

      {text.length > 0 && (
        <TouchableOpacity style={s.clearBtn} onPress={another} activeOpacity={0.7} accessibilityRole="button">
          <Text style={s.clearLabel}>{t("mobile.message.clear")}</Text>
        </TouchableOpacity>
      )}

      <PrivacyNote />
    </ScrollView>
  );
}

function PrivacyNote() {
  const { t } = useTranslation();
  return (
    <View style={s.privacyRow}>
      <Ionicons name="lock-closed-outline" size={14} color={colors.textMuted} />
      <Text style={s.privacy}>{t("mobile.message.privacy")}</Text>
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, paddingHorizontal: space.xl, paddingBottom: 100,
  },
  centerTitle: { ...typo.title2, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  centerBody: { fontSize: 17, lineHeight: 24, color: colors.textSecondary, textAlign: "center", marginTop: space.sm, marginBottom: space.lg },
  fullWidth: { alignSelf: "stretch" },

  title: { ...typo.title1, color: colors.textPrimary, marginTop: space.sm },
  subtitle: { fontSize: 17, lineHeight: 24, color: colors.textSecondary, marginTop: space.xs, marginBottom: space.xl },
  input: {
    minHeight: 160, maxHeight: 320,
    backgroundColor: colors.surfaceRaised,
    borderWidth: 1, borderColor: colors.stroke, borderRadius: radius.control,
    paddingHorizontal: space.lg, paddingTop: space.md, paddingBottom: space.md,
    color: colors.textPrimary, fontSize: 18, lineHeight: 25,
    marginBottom: space.md,
  },
  inputFocused: { borderColor: colors.blue },

  pasteBtn: {
    minHeight: 54, flexDirection: "row", gap: space.sm,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control, alignItems: "center", justifyContent: "center",
    paddingHorizontal: space.lg, marginTop: space.sm,
  },
  pasteLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary },
  hint: { fontSize: 15, lineHeight: 21, color: colors.amber, marginTop: space.sm, paddingHorizontal: space.xs },
  checkBtn: {
    minHeight: 54, backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.md,
  },
  checkBtnDisabled: { opacity: 0.45 },
  checkLabel: { fontSize: 18, fontWeight: "600", color: "#FFFFFF" },
  clearBtn: {
    alignSelf: "center", minHeight: 48, justifyContent: "center",
    paddingHorizontal: space.lg, marginTop: space.xs,
  },
  clearLabel: { fontSize: 15, fontWeight: "600", color: colors.textSecondary },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xl, paddingHorizontal: space.md,
  },
  privacy: { fontSize: 14, lineHeight: 20, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
