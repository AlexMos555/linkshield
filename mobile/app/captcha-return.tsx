/**
 * Deep-link sink for the optional captcha flow: `cleanway://captcha-return`.
 *
 * The hosted challenge page (landing/app/auth/captcha) redirects here with the
 * nonce it was given and the token it earned. This screen hands both to the
 * captcha service and pops straight back to /auth, which stayed mounted
 * underneath with the typed email intact.
 *
 * Why a dedicated route rather than redirecting into `cleanway://auth`:
 * /auth keeps its state (the email the user typed) instead of remounting, and
 * we don't have to bet on React Navigation's push-vs-merge behaviour for a
 * deep link aimed at the already-focused route.
 *
 * UNREACHABLE unless EXPO_PUBLIC_CAPTCHA_URL is set — nothing navigates here
 * and no captcha page exists to redirect here.
 *
 * Cold-start case: if the OS killed the app while the browser was open there
 * is no pending request to satisfy (the promise died with the JS context), so
 * the delivery is dropped and we land on /auth. The user retypes their email.
 * Accepted — the alternative is persisting a challenge across process death
 * for a token that expires in minutes anyway.
 */

import { useEffect } from "react";
import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { deliverCaptchaToken } from "../src/services/captcha";

/** expo-router hands back `string | string[]` for a repeated query param. */
function firstValue(v: string | string[] | undefined): string {
  if (Array.isArray(v)) return v[0] ?? "";
  return v ?? "";
}

export default function CaptchaReturnScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const params = useLocalSearchParams<{ nonce?: string; token?: string }>();
  const nonce = firstValue(params.nonce);
  const token = firstValue(params.token);

  useEffect(() => {
    deliverCaptchaToken(nonce, token);
    if (router.canGoBack()) router.back();
    else router.replace("/auth");
  }, [nonce, token, router]);

  return (
    <View style={styles.container}>
      <ActivityIndicator color={colors.primary} />
      <Text style={styles.label}>{t("mobile.auth.captcha_wait")}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: colors.bg,
    alignItems: "center",
    justifyContent: "center",
    gap: spacing.md,
    padding: spacing.xl,
  },
  label: {
    color: colors.textSecondary,
    fontSize: fontSize.md,
    textAlign: "center",
  },
});
