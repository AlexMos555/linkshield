import { useState, useRef, useCallback, useEffect } from "react";
import {
  View, Text, StyleSheet, TextInput, TouchableOpacity, ActivityIndicator,
} from "react-native";
import { useRouter } from "expo-router";
import { useTranslation } from "react-i18next";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { setAuthToken } from "../src/services/api";
import {
  sendEmailOtp,
  verifyEmailOtp,
  validateEmail,
  isValidOtpCode,
  OTP_CODE_LEN,
  AuthError,
} from "../src/services/auth";
import { isSupabaseConfigured } from "../src/services/supabase";

/**
 * Passwordless sign-in: enter email → receive a 6-digit code → enter it.
 *
 * Unified with the web (same Supabase project), so the SAME email is the SAME
 * account on both surfaces and settings/family sync just works. No password to
 * remember (grandma-friendly), no fragile web→app token handoff. An account is
 * entirely optional — "continue without an account" keeps the free on-device
 * protection working with zero sign-in.
 */

type Step = "email" | "code";

// Must be >= Supabase's per-address email-OTP rate limit (default 60s), or the
// "Resend" button would deterministically 429 the moment the countdown ends.
// 62s gives a small margin over the server window.
const RESEND_COOLDOWN_S = 62;

export default function AuthScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const cooldownTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Stop the resend countdown if the screen unmounts mid-tick (e.g. the user
  // signs in) — otherwise the interval leaks and setState fires after unmount.
  useEffect(() => () => {
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
  }, []);

  const startCooldown = useCallback(() => {
    setCooldown(RESEND_COOLDOWN_S);
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
    cooldownTimer.current = setInterval(() => {
      setCooldown((c) => {
        if (c <= 1 && cooldownTimer.current) {
          clearInterval(cooldownTimer.current);
          cooldownTimer.current = null;
        }
        return c - 1;
      });
    }, 1000);
  }, []);

  const notConfigured = !isSupabaseConfigured();

  async function requestCode(): Promise<void> {
    setError(null);
    if (notConfigured) {
      setError(t("mobile.auth.not_configured"));
      return;
    }
    if (validateEmail(email)) {
      setError(t("mobile.auth.err_email"));
      return;
    }
    setLoading(true);
    try {
      await sendEmailOtp(email.trim());
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      setStep("code");
      setCode("");
      startCooldown();
    } catch (e: unknown) {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      setError(e instanceof AuthError ? e.message : t("mobile.auth.generic_error"));
    } finally {
      setLoading(false);
    }
  }

  async function submitCode(): Promise<void> {
    setError(null);
    if (!isValidOtpCode(code)) {
      setError(t("mobile.auth.err_code"));
      return;
    }
    setLoading(true);
    try {
      const session = await verifyEmailOtp(email.trim(), code);
      setAuthToken(session.accessToken);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      router.replace("/(tabs)");
    } catch (e: unknown) {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      // A wrong/expired code is the common case — name it plainly.
      const wrong = e instanceof AuthError && (e.status === 401 || e.status === 403 || e.code === "otp_expired");
      setError(wrong ? t("mobile.auth.err_code_wrong")
        : e instanceof AuthError ? e.message : t("mobile.auth.generic_error"));
    } finally {
      setLoading(false);
    }
  }

  const changeEmail = () => {
    setError(null);
    setCode("");
    setStep("email");
  };

  return (
    <View style={styles.container}>
      <Text style={styles.icon}>{"\u{1F6E1}"}</Text>

      {step === "email" ? (
        <>
          <Text style={styles.title}>{t("mobile.auth.otp_title")}</Text>
          <Text style={styles.subtitle}>{t("mobile.auth.otp_sub")}</Text>

          <View style={styles.form}>
            <TextInput
              style={styles.input}
              placeholder={t("mobile.auth.email_ph")}
              placeholderTextColor={colors.textMuted}
              value={email}
              onChangeText={setEmail}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="email-address"
              textContentType="emailAddress"
              accessibilityLabel={t("mobile.auth.email_ph")}
              editable={!loading}
              onSubmitEditing={() => void requestCode()}
              returnKeyType="send"
            />

            {error && <Text style={styles.errorText}>{error}</Text>}

            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={() => void requestCode()}
              disabled={loading}
              accessibilityRole="button"
              accessibilityLabel={t("mobile.auth.otp_send")}
            >
              {loading
                ? <ActivityIndicator color="#0B1220" />
                : <Text style={styles.btnText}>{t("mobile.auth.otp_send")}</Text>}
            </TouchableOpacity>

            <TouchableOpacity style={styles.skipBtn} onPress={() => router.replace("/(tabs)")}>
              <Text style={styles.skipText}>{t("mobile.auth.skip")}</Text>
            </TouchableOpacity>
          </View>
        </>
      ) : (
        <>
          <Text style={styles.title}>{t("mobile.auth.code_title")}</Text>
          <Text style={styles.subtitle}>{t("mobile.auth.code_sub", { email: email.trim() })}</Text>

          <View style={styles.form}>
            <TextInput
              style={[styles.input, styles.codeInput]}
              placeholder={"000000"}
              placeholderTextColor={colors.textMuted}
              value={code}
              onChangeText={(v) => setCode(v.replace(/\D/g, "").slice(0, OTP_CODE_LEN))}
              keyboardType="number-pad"
              // iOS can surface an email-delivered code from Mail via
              // oneTimeCode; no Android "sms-otp" hint — the code comes by email,
              // not SMS, so that autofill channel would never fire.
              textContentType="oneTimeCode"
              maxLength={OTP_CODE_LEN}
              accessibilityLabel={t("mobile.auth.code_title")}
              editable={!loading}
              autoFocus
              onSubmitEditing={() => void submitCode()}
              returnKeyType="done"
            />

            {error && <Text style={styles.errorText}>{error}</Text>}

            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={() => void submitCode()}
              disabled={loading}
              accessibilityRole="button"
              accessibilityLabel={t("mobile.auth.code_verify")}
            >
              {loading
                ? <ActivityIndicator color="#0B1220" />
                : <Text style={styles.btnText}>{t("mobile.auth.code_verify")}</Text>}
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.switchBtn}
              onPress={() => void requestCode()}
              disabled={loading || cooldown > 0}
            >
              <Text style={[styles.switchText, cooldown > 0 && styles.switchDisabled]}>
                {cooldown > 0
                  ? t("mobile.auth.code_resend_in", { seconds: cooldown })
                  : t("mobile.auth.code_resend")}
              </Text>
            </TouchableOpacity>

            <TouchableOpacity style={styles.switchBtn} onPress={changeEmail}>
              <Text style={styles.forgotText}>{t("mobile.auth.code_change_email")}</Text>
            </TouchableOpacity>
          </View>
        </>
      )}

      <Text style={styles.note}>{t("mobile.auth.privacy")}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, justifyContent: "center", padding: spacing.xl },
  icon: { fontSize: 48, textAlign: "center", marginBottom: spacing.md },
  title: { fontSize: fontSize.xxl, fontWeight: "800", color: colors.white, textAlign: "center" },
  subtitle: { fontSize: fontSize.md, color: colors.textSecondary, textAlign: "center", marginBottom: spacing.xl },
  form: { gap: spacing.md },
  input: {
    backgroundColor: colors.bgCard, borderRadius: 12, padding: 16,
    color: colors.text, fontSize: fontSize.lg, borderWidth: 1, borderColor: colors.border,
  },
  codeInput: {
    textAlign: "center", fontSize: 28, letterSpacing: 8, fontWeight: "700",
  },
  btn: { backgroundColor: colors.accent, borderRadius: 12, padding: 16, alignItems: "center" },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: "#0B1220", fontWeight: "700", fontSize: fontSize.lg },
  switchBtn: { alignItems: "center", padding: spacing.md },
  switchText: { color: colors.primary, fontSize: fontSize.md },
  switchDisabled: { color: colors.textMuted },
  forgotText: { color: colors.textSecondary, fontSize: fontSize.sm },
  skipBtn: { alignItems: "center", padding: spacing.sm },
  skipText: { color: colors.textMuted, fontSize: fontSize.sm },
  errorText: {
    color: colors.dangerous, fontSize: fontSize.sm,
    textAlign: "center", paddingHorizontal: spacing.sm,
  },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.xs, marginTop: spacing.xl },
});
