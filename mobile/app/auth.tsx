import { useState } from "react";
import {
  View, Text, StyleSheet, TextInput, TouchableOpacity, Alert, ActivityIndicator,
} from "react-native";
import { useRouter } from "expo-router";
import * as SecureStore from "expo-secure-store";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { setAuthToken } from "../src/services/api";

export default function AuthScreen() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleAuth() {
    if (!email.includes("@") || password.length < 6) {
      Alert.alert("Invalid input", "Enter a valid email and password (6+ chars).");
      return;
    }

    setLoading(true);
    try {
      const endpoint = mode === "login"
        ? "/auth/v1/token?grant_type=password"
        : "/auth/v1/signup";

      const SUPABASE_URL = "https://YOUR_PROJECT.supabase.co"; // TODO: from config
      const SUPABASE_ANON = "YOUR_ANON_KEY"; // TODO: from config

      const resp = await fetch(`${SUPABASE_URL}${endpoint}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": SUPABASE_ANON,
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await resp.json();

      if (data.access_token) {
        await SecureStore.setItemAsync("auth_token", data.access_token);
        await SecureStore.setItemAsync("refresh_token", data.refresh_token || "");
        await SecureStore.setItemAsync("user_email", email);
        setAuthToken(data.access_token);
        Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
        router.replace("/(tabs)");
      } else if (data.msg || data.error_description) {
        Alert.alert("Error", data.msg || data.error_description || "Authentication failed");
      } else if (mode === "register") {
        Alert.alert("Check your email", "We sent a confirmation link. Check your inbox.");
      }
    } catch (e: any) {
      Alert.alert("Connection error", "Could not reach server. Try again later.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.icon}>{"\u{1F6E1}"}</Text>
      <Text style={styles.title}>{mode === "login" ? "Welcome Back" : "Create Account"}</Text>
      <Text style={styles.subtitle}>
        {mode === "login" ? "Sign in to sync across devices" : "Start your free protection"}
      </Text>

      <View style={styles.form}>
        <TextInput
          style={styles.input}
          placeholder="Email"
          placeholderTextColor={colors.textMuted}
          value={email}
          onChangeText={setEmail}
          autoCapitalize="none"
          keyboardType="email-address"
        />
        <TextInput
          style={styles.input}
          placeholder="Password"
          placeholderTextColor={colors.textMuted}
          value={password}
          onChangeText={setPassword}
          secureTextEntry
        />

        <TouchableOpacity
          style={[styles.btn, loading && styles.btnDisabled]}
          onPress={handleAuth}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color={colors.safeBg} />
          ) : (
            <Text style={styles.btnText}>
              {mode === "login" ? "Sign In" : "Create Account"}
            </Text>
          )}
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.switchBtn}
          onPress={() => setMode(mode === "login" ? "register" : "login")}
        >
          <Text style={styles.switchText}>
            {mode === "login" ? "Don't have an account? Sign Up" : "Already have an account? Sign In"}
          </Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.skipBtn} onPress={() => router.replace("/(tabs)")}>
          <Text style={styles.skipText}>Continue without account</Text>
        </TouchableOpacity>
      </View>

      <Text style={styles.note}>{"\u{1F512}"} Your browsing data stays on-device regardless</Text>
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
  skipBtn: { alignItems: "center", padding: spacing.sm },
  skipText: { color: colors.textMuted, fontSize: fontSize.sm },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.xs, marginTop: spacing.xl },
});
