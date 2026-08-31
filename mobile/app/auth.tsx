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
import {
  isCaptchaRequired,
  requestCaptchaToken,
  cancelCaptcha,
} from "../src/services/captcha";

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
  // Absolute wall-clock deadline, not a tick counter: RN suspends JS while the
  // app is backgrounded, which is EXACTLY when the user leaves to read the
  // email. A counting-down integer would freeze there and "resend" would stay
  // disabled long after the server window had actually passed.
  const cooldownUntil = useRef<number>(0);

  // Stop the resend countdown if the screen unmounts mid-tick (e.g. the user
  // signs in) — otherwise the interval leaks and setState fires after unmount.
  useEffect(() => () => {
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
    // Drop any captcha challenge still waiting on a deep link, so its promise
    // (and its AppState listener) can't outlive the screen. No-op when captcha
    // is not configured — nothing is ever pending.
    cancelCaptcha();
  }, []);

  const startCooldown = useCallback(() => {
    cooldownUntil.current = Date.now() + RESEND_COOLDOWN_S * 1000;
    setCooldown(RESEND_COOLDOWN_S);
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
    cooldownTimer.current = setInterval(() => {
      const left = Math.ceil((cooldownUntil.current - Date.now()) / 1000);
      if (left <= 0) {
        if (cooldownTimer.current) clearInterval(cooldownTimer.current);
        cooldownTimer.current = null;
        setCooldown(0);
        return;
      }
      setCooldown(left);
    }, 1000);
  }, []);

  const notConfigured = !isSupabaseConfigured();

  async function requestCode(): Promise<void> {
    setError(null);
    if (notConfigured) {
      setError(t("mobile.auth.not_configured"));
      return;
    }
    // Validate the TRIMMED value — it is what we send. A pasted address often
    // carries a trailing space, and the anchored regex would reject it while the
    // request would have succeeded.
    const cleanEmail = email.trim();
    if (validateEmail(cleanEmail)) {
      setError(t("mobile.auth.err_email"));
      return;
    }
    setLoading(true);
    try {
      // OPTIONAL captcha. With EXPO_PUBLIC_CAPTCHA_URL unset — today's state —
      // isCaptchaRequired() is false, this block is skipped entirely and the
      // call below is byte-for-byte the request it has always been.
      let captchaToken: string | undefined;
      if (isCaptchaRequired()) {
        // Name it `token`, not `t` — `t` is the i18n function above.
        const token = await requestCaptchaToken();
        if (!token) {
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
          setError(t("mobile.auth.err_captcha"));
          return;
        }
        captchaToken = token;
      }
      await sendEmailOtp(cleanEmail, captchaToken);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
      setStep("code");
      setCode("");
      startCooldown();
    } catch (e: unknown) {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      // GoTrue's own messages are English-only; showing them raw would put
      // English in front of a Russian-speaking user. Map the two cases worth
      // distinguishing and fall back to our translated generic message.
      const offline = e instanceof AuthError && (e.code === "network_error" || e.code === "timeout");
      // 429 is a likely early-launch answer: the project-wide email quota is
      // small until real SMTP is wired, and GoTrue also caps per address.
      const limited = e instanceof AuthError && e.status === 429;
      // The reverse failure mode, and the one worth naming BEFORE captcha is
      // ever turned on: the Supabase switch is server-side and project-wide, so
      // the instant it is flipped every already-installed build that sends no
      // token starts getting 400 captcha_failed. Without this branch that reads
      // as the generic "Something went wrong" — an undiagnosable launch
      // incident instead of a one-line answer.
      const captchaRejected = e instanceof AuthError && e.code === "captcha_failed";
      setError(
        t(captchaRejected
            ? (isCaptchaRequired()
                // We sent a token and the server refused it — retryable.
                ? "mobile.auth.err_captcha"
                // This build has no captcha wired but the server now demands
                // one: only a newer app can sign in.
                : "mobile.auth.err_captcha_update")
          : limited ? "mobile.auth.err_rate_limited"
          : offline ? "mobile.auth.err_network"
          : "mobile.auth.generic_error"),
      );
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
      leaveAuth();
    } catch (e: unknown) {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      // A wrong/expired code is the common case — name it plainly.
      const wrong =
        e instanceof AuthError &&
        (e.status === 400 || e.status === 401 || e.status === 403 || e.code === "otp_expired");
      const offline = e instanceof AuthError && (e.code === "network_error" || e.code === "timeout");
      setError(
        t(wrong ? "mobile.auth.err_code_wrong"
          : offline ? "mobile.auth.err_network"
          : "mobile.auth.generic_error"),
      );
    } finally {
      setLoading(false);
    }
  }

  // /auth is always PUSHED (from Settings or Family), so replacing the route
  // with "/(tabs)" stacked a SECOND tabs navigator on top of the first — the
  // user ended up with a back-stack that walks into a duplicate app. Go back to
  // whatever opened us when we can, and only fall back to a replace otherwise.
  const leaveAuth = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

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

            <TouchableOpacity style={styles.skipBtn} onPress={leaveAuth}>
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
