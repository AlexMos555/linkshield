import { useEffect } from "react";
import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { restoreSession } from "../src/services/auth";
import { setAuthToken } from "../src/services/api";

export default function RootLayout() {
  // Restore previously-persisted Supabase session on cold boot. Runs once.
  // - Valid token > 2 min from expiry: use as-is.
  // - Near/past expiry: transparent refresh via refresh_token.
  // - Any failure: leave token null; guest mode still works.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const session = await restoreSession();
        if (!cancelled && session) {
          setAuthToken(session.accessToken);
        }
      } catch {
        // Silent — never block UI on auth restore failures.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <StatusBar style="light" />
      <Stack
        screenOptions={{
          headerStyle: { backgroundColor: "#0f172a" },
          headerTintColor: "#f8fafc",
          headerTitleStyle: { fontWeight: "700" },
          contentStyle: { backgroundColor: "#0f172a" },
        }}
      >
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        <Stack.Screen name="check" options={{ title: "Check Link" }} />
        <Stack.Screen name="result" options={{ title: "Result" }} />
        <Stack.Screen name="breach" options={{ title: "Breach Check" }} />
        <Stack.Screen name="scanner" options={{ title: "QR Scanner" }} />
        <Stack.Screen name="onboarding" options={{ headerShown: false }} />
        <Stack.Screen name="shared" options={{ title: "Link Check", presentation: "modal" }} />
        <Stack.Screen name="auth" options={{ headerShown: false }} />
        <Stack.Screen name="upgrade" options={{ title: "Upgrade" }} />
        <Stack.Screen name="report" options={{ title: "Weekly Report" }} />
      </Stack>
    </>
  );
}
