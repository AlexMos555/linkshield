import { Stack } from "expo-router";
import { StatusBar } from "expo-status-bar";

export default function RootLayout() {
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
        <Stack.Screen name="auth" options={{ headerShown: false }} />
        <Stack.Screen name="upgrade" options={{ title: "Upgrade" }} />
        <Stack.Screen name="report" options={{ title: "Weekly Report" }} />
      </Stack>
    </>
  );
}
