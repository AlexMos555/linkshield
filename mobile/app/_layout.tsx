import { useEffect } from "react";
import { Stack, useRouter } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { useFonts } from "expo-font";
import { useTranslation } from "react-i18next";
import { Ionicons } from "@expo/vector-icons";
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
  const { t } = useTranslation();

  // Preload the icon font, and shout if it fails.
  //
  // On 2026-08-05 every icon in the app — tab bar, shield hero, every card and
  // chevron — was drawing as blank space on Android while the surrounding text
  // rendered fine. @expo/vector-icons loads its font lazily and swallows the
  // failure, so nothing was logged and several passes of "design" work were in
  // fact invisible on device. Loading it here surfaced the real cause:
  //
  //   ExpoAsset.downloadAsync rejected
  //   → Module 'expo.modules.interfaces.filesystem.AppDirectories' not found
  //
  // expo-asset was declared but its native peer expo-file-system was not, so
  // no asset could ever be fetched. Adding that dependency is the actual fix;
  // this preload stays as the tripwire that would have caught it on day one.
  const [fontsLoaded, fontError] = useFonts(Ionicons.font);
  useEffect(() => {
    if (fontError) console.warn("[cleanway] icon font failed to load:", fontError);
  }, [fontError]);

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

  // Deliberately NOT gated on fontsLoaded. Blocking the tree until the font
  // resolves was tried and left the app on an empty screen indefinitely — the
  // promise never settled and never rejected — so a missing glyph became a
  // dead app. Icons are cosmetic; the app is not. Render immediately and let
  // the glyphs appear when (if) the font arrives.
  void fontsLoaded;

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
        {/* Titles go through i18n. They were hardcoded English literals, so the
            navigation bar stayed in English in all 10 locales — on a product
            whose whole point is being readable by someone's grandmother in her
            own language. */}
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        <Stack.Screen name="check" options={{ title: t("mobile.check.title") }} />
        <Stack.Screen name="result" options={{ title: t("mobile.nav.result") }} />
        <Stack.Screen name="breach" options={{ title: t("mobile.breach.title") }} />
        <Stack.Screen name="scanner" options={{ title: t("mobile.nav.scanner") }} />
        <Stack.Screen name="onboarding" options={{ headerShown: false }} />
        <Stack.Screen name="shared" options={{ title: t("mobile.nav.shared"), presentation: "modal" }} />
        <Stack.Screen name="auth" options={{ headerShown: false }} />
        <Stack.Screen name="upgrade" options={{ title: t("mobile.nav.upgrade") }} />
        <Stack.Screen name="report" options={{ title: t("mobile.report.title") }} />
      </Stack>
      {/* Global overlay — subscribes to accountLockedEvents and renders
          the restore CTA whenever any authed call returns 410 Gone. */}
      <ShareIntentRouter />
      <AccountLockedModal />
    </ShareIntentProvider>
  );
}
