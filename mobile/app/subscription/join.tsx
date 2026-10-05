/**
 * "I have a code from a relative" (billing plan §2.4): six digits, one
 * button. Offered on first run and from the hub. The server answers every
 * bad code the same way, so the screen can only say "ask for a new one".
 */
import { useState } from "react";
import { Alert, StyleSheet, Text, TextInput } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Screen } from "../../src/components/billing/Ui";
import { billing } from "../../src/services/billing";
import { colors, radius, space } from "../../src/utils/theme";

const CODE_SHAPE = /^\d{6}$/;

function joinErrorKey(code: string): string {
  switch (code) {
    case "code_invalid":
      return "mobile.billing.join_invalid";
    case "code_format":
      return "mobile.billing.join_format";
    case "already_subscribed":
      return "mobile.billing.join_already";
    case "no_free_seats":
      return "mobile.billing.join_no_seats";
    case "network":
    case "timeout":
      return "mobile.billing.join_network";
    default:
      return "mobile.billing.join_invalid";
  }
}

export default function JoinScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const { from, code: prefilled } = useLocalSearchParams<{ from?: string; code?: string }>();
  const [code, setCode] = useState(prefilled && CODE_SHAPE.test(prefilled) ? prefilled : "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    const digits = code.replace(/\D/g, "");
    if (!CODE_SHAPE.test(digits)) {
      setError(t("mobile.billing.join_format"));
      return;
    }
    setBusy(true);
    const result = await billing.claim(digits);
    setBusy(false);
    if (!result.data) {
      setError(t(joinErrorKey(result.error.code)));
      return;
    }
    setError(null);
    Alert.alert(t("mobile.billing.join_done_title"), t("mobile.billing.join_done_body"), [
      { text: t("mobile.billing.done"), onPress: () => router.replace(from === "onboarding" ? "/(tabs)" : "/subscription") },
    ]);
  }

  return (
    <Screen>
      <Text style={s.body} nativeID="join-label">{t("mobile.billing.join_body")}</Text>
      <TextInput
        style={[s.input, error && s.inputBad]}
        value={code}
        onChangeText={(v) => { setCode(v.replace(/\D/g, "").slice(0, 6)); setError(null); }}
        keyboardType="number-pad"
        maxLength={6}
        autoFocus
        textAlign="center"
        placeholder="000000"
        placeholderTextColor={colors.textMuted}
        accessibilityLabel={t("mobile.billing.join_body")}
        accessibilityLabelledBy="join-label"
      />
      {error ? <Text style={s.error} accessibilityLiveRegion="polite">{error}</Text> : null}
      <BigButton label={t("mobile.billing.join_cta")} onPress={() => void submit()} busy={busy} disabled={code.length < 6} icon="link-outline" />
    </Screen>
  );
}

const s = StyleSheet.create({
  body: { fontSize: 17, lineHeight: 24, color: colors.textSecondary },
  input: {
    minHeight: 76, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke, backgroundColor: colors.bgInput,
    color: colors.textPrimary, fontSize: 36, fontWeight: "700", letterSpacing: 10, paddingHorizontal: space.lg,
  },
  inputBad: { borderColor: colors.danger },
  error: { fontSize: 16, lineHeight: 22, color: colors.danger },
});
