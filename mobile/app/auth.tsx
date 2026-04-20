import { useState } from "react";
import {
  View, Text, StyleSheet, TextInput, TouchableOpacity, Alert, ActivityIndicator,
} from "react-native";
import { useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { setAuthToken } from "../src/services/api";
import {
  signIn,
  signUp,
  sendPasswordResetEmail,
  validateEmail,
  validatePassword,
  AuthError,
} from "../src/services/auth";
import { isSupabaseConfigured } from "../src/services/supabase";

type Mode = "login" | "register" | "reset";

export default function AuthScreen() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleAuth(): Promise<void> {
    setError(null);

    if (!isSupabaseConfigured()) {
      setError(
        "Authentication is not configured. Contact support@linkshield.io.",
      );
      return;
    }

    const emailError = validateEmail(email);
    if (emailError) {
      setError(emailError);
      return;
    }
    if (mode !== "reset") {
      const pwError = validatePassword(password);
      if (pwError) {
        setError(pwError);
        return;
      }
    }

    setLoading(true);
    try {
      if (mode === "login") {
        const session = await signIn(email, password);
        setAuthToken(session.accessToken);
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        router.replace("/(tabs)");
      } else if (mode === "register") {
        const session = await signUp(email, password);
        if (session) {
          setAuthToken(session.accessToken);
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
          router.replace("/(tabs)");
        } else {
          Alert.alert(
            "Check your email",
            "We sent a confirmation link. Click it to activate your account.",
          );
          setMode("login");
          setPassword("");
        }
      } else {
        await sendPasswordResetEmail(email);
        Alert.alert(
          "Check your email",
          "If an account exists for this address, we've sent a link to reset your password.",
        );
        setMode("login");
      }
    } catch (e: unknown) {
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      if (e instanceof AuthError) {
        setError(e.message);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  const titleFor: Record<Mode, string> = {
    login: "Welcome Back",
    register: "Create Account",
    reset: "Reset Password",
  };
  const subtitleFor: Record<Mode, string> = {
    login: "Sign in to sync across devices",
    register: "Start your free protection",
    reset: "We'll email you a link to set a new password",
  };
  const ctaFor: Record<Mode, string> = {
    login: "Sign In",
    register: "Create Account",
    reset: "Send Reset Link",
  };

  return (
    <View style={styles.container}>
      <Text style={styles.icon}>{"\u{1F6E1}"}</Text>
      <Text style={styles.title}>{titleFor[mode]}</Text>
      <Text style={styles.subtitle}>{subtitleFor[mode]}</Text>

      <View style={styles.form}>
        <TextInput
          style={styles.input}
          placeholder="Email"
          placeholderTextColor={colors.textMuted}
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="email-address"
          accessibilityLabel="Email address"
          editable={!loading}
        />
        {mode !== "reset" && (
          <TextInput
            style={styles.input}
            placeholder="Password"
            placeholderTextColor={colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            autoCapitalize="none"
            autoCorrect={false}
            accessibilityLabel="Password"
            editable={!loading}
          />
        )}

        {error && <Text style={styles.errorText}>{error}</Text>}

        <TouchableOpacity
          style={[styles.btn, loading && styles.btnDisabled]}
          onPress={handleAuth}
          disabled={loading}
          accessibilityRole="button"
          accessibilityLabel={ctaFor[mode]}
        >
          {loading ? (
            <ActivityIndicator color={colors.safeBg} />
          ) : (
            <Text style={styles.btnText}>{ctaFor[mode]}</Text>
          )}
        </TouchableOpacity>

        {mode === "login" && (
          <TouchableOpacity
            style={styles.switchBtn}
            onPress={() => { setError(null); setMode("reset"); }}
          >
            <Text style={styles.forgotText}>Forgot password?</Text>
          </TouchableOpacity>
        )}

        <TouchableOpacity
          style={styles.switchBtn}
          onPress={() => {
            setError(null);
            setMode(mode === "login" ? "register" : "login");
          }}
        >
          <Text style={styles.switchText}>
            {mode === "login"
              ? "Don't have an account? Sign Up"
              : "Already have an account? Sign In"}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.skipBtn}
          onPress={() => router.replace("/(tabs)")}
        >
          <Text style={styles.skipText}>Continue without account</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.note}>
        {"\u{1F512}"} Your browsing data stays on-device regardless
      </Text>
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
  btn: { backgroundColor: colors.accent, borderRadius: 12, padding: 16, alignItems: "center" },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
  switchBtn: { alignItems: "center", padding: spacing.md },
  switchText: { color: colors.primary, fontSize: fontSize.md },
  forgotText: { color: colors.textSecondary, fontSize: fontSize.sm },
  skipBtn: { alignItems: "center", padding: spacing.sm },
  skipText: { color: colors.textMuted, fontSize: fontSize.sm },
  errorText: {
    color: colors.dangerous, fontSize: fontSize.sm,
    textAlign: "center", paddingHorizontal: spacing.sm,
  },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.xs, marginTop: spacing.xl },
});
