/**
 * The two screens nobody should normally see. Both used to be expo-router's
 * own, in English, for developers:
 *
 *  - AppErrorScreen — what app/_layout.tsx's ErrorBoundary renders when a
 *    screen throws during render. Without a boundary a render error is fatal
 *    in a release build: the app closed, and on Android the shield went down
 *    with it (the VPN service runs in the same process) until the system
 *    restarted it. A repeated deep-link param did exactly that —
 *    cleanway:///shared?url=a&url=b, which any app or web page can open.
 *  - UnknownLinkScreen — app/+not-found.tsx, for a cleanway:// path this
 *    build has no screen for. expo-router's default said "Unmatched Route"
 *    and linked a sitemap listing every route of the app.
 */
import { useEffect } from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { router, type ErrorBoundaryProps } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { Sentry } from "../lib/sentry";
import { colors, type as typo, space, radius } from "../utils/theme";

export function AppErrorScreen({ error, retry }: ErrorBoundaryProps) {
  const { t } = useTranslation();

  // React catches the error here, so the global handler — and with it Sentry
  // (a no-op without a DSN) — would otherwise never hear of it.
  useEffect(() => {
    Sentry.captureException(error);
  }, [error]);

  // The boundary replaced the whole navigator, and the crashed screen's state
  // went with it. Start again from home: the replace gives the root a fresh
  // route; the retry re-renders the layout should the replace not go through.
  const goHome = () => {
    try {
      router.replace("/");
    } catch {
      // Navigation not ready: the retry below still starts from home.
    }
    void retry();
  };

  return (
    <Notice
      icon="alert-circle-outline"
      title={t("mobile.fallback.error_title")}
      body={t("mobile.fallback.error_body")}
      action={t("mobile.fallback.home")}
      onAction={goHome}
    />
  );
}

export function UnknownLinkScreen() {
  const { t } = useTranslation();
  return (
    <Notice
      icon="link-outline"
      title={t("mobile.fallback.not_found_title")}
      body={t("mobile.fallback.not_found_body")}
      action={t("mobile.fallback.home")}
      // Back to the home screen already in the stack, or home in this
      // screen's place on a cold start from the link.
      onAction={() => router.dismissTo("/")}
    />
  );
}

interface NoticeProps {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  body: string;
  action: string;
  onAction: () => void;
}

function Notice({ icon, title, body, action, onAction }: NoticeProps) {
  return (
    <View style={s.center} accessibilityLiveRegion="polite">
      <StatusBar style="light" />
      <Ionicons name={icon} size={44} color={colors.amber} />
      <Text style={s.title} accessibilityRole="header">{title}</Text>
      <Text style={s.body}>{body}</Text>
      <TouchableOpacity style={s.button} onPress={onAction} activeOpacity={0.85} accessibilityRole="button">
        <Text style={s.buttonLabel}>{action}</Text>
      </TouchableOpacity>
    </View>
  );
}

const s = StyleSheet.create({
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, paddingHorizontal: space.xl,
  },
  title: { ...typo.headline, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  body: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },
  button: {
    minHeight: 50, backgroundColor: colors.blueFill, borderRadius: radius.control,
    paddingHorizontal: space.xxl, alignSelf: "stretch",
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  buttonLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
});
