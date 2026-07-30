import { useEffect } from "react";
import { Stack, useRouter } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { ShareIntentProvider, useShareIntentContext } from "expo-share-intent";
import { restoreSession } from "../src/services/auth";
import { setAuthToken } from "../src/services/api";
// Side-effecting import: initialises i18next at boot so every screen
// can immediately `useTranslation()`. Previously the module was authored
// but never imported anywhere — all 10 locales were dead code on
// device, and every string fell back to the en hard-coded literal.
// (Audit mobile-ts HIGH mobile-i18n-dead-code.)
import "../src/i18n";
// Side-effecting import: initialises @sentry/react-native with the
// PII scrubber + privacy-conservative defaults. No-op when
// EXPO_PUBLIC_SENTRY_DSN is unset (dev / Expo Go) so this stays a
// zero-cost import in those environments.
import "../src/lib/sentry";
import { AccountLockedModal } from "../src/components/AccountLockedModal";

/**
 * Bridges an inbound "Share -> Cleanway" (iOS Share Extension / Android ACTION_SEND,
 * both created by the expo-share-intent config plugin) into the existing /shared
 * screen, which runs the full domain check and shows the verdict + haptics.
 *
 * !! UNVERIFIED: the Expo SDK 52 toolchain can't run in the authoring env (Node 25).
 * Requires `npx expo prebuild` + a dev-client build + on-device test.
 * See mobile/SHARE_FLOW.md.
 */
function ShareIntentRouter() {
  const router = useRouter();
  const { hasShareIntent, shareIntent, resetShareIntent } = useShareIntentContext();

  useEffect(() => {
    if (!hasShareIntent) return;
    const shared = shareIntent?.webUrl ?? shareIntent?.text ?? "";
    if (shared) {
      router.push({ pathname: "/shared", params: { url: shared } });
    }
    resetShareIntent();
  }, [hasShareIntent, shareIntent]);

  return null;
}

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
    <ShareIntentProvider options={{ resetOnBackground: true }}>
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
      {/* Global overlay — subscribes to accountLockedEvents and renders
          the restore CTA whenever any authed call returns 410 Gone. */}
      <ShareIntentRouter />
      <AccountLockedModal />
    </ShareIntentProvider>
  );
}
