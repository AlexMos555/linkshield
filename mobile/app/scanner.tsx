import { useState, useRef, useCallback } from "react";
import {
  View, Text, StyleSheet, TouchableOpacity, Alert, ActivityIndicator, Linking,
} from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import { useRouter, useFocusEffect } from "expo-router";
import * as Haptics from "expo-haptics";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../src/utils/theme";
import { toCheckableHost } from "../src/utils/host";

/**
 * QR scanner (docs/design/shield-checklist-design.md §1 tokens, §6 a11y).
 *
 * The viewfinder ring is blue, not green: green is reserved for verified
 * protection states, and an aiming frame verifies nothing.
 */

const FRAME = 260;

export default function ScannerScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const [permission, requestPermission] = useCameraPermissions();
  // A ref, not state: setScanned(true) does not take effect until the next
  // render, and the camera can deliver two frames of the same code inside
  // that window — pushing /result twice for one scan.
  const scanLock = useRef(false);

  // Re-read the permission when the screen regains focus. Sending the user
  // to Settings and then never asking again left "Open Settings" as a dead
  // end: they granted the camera, came back, and still saw the same wall.
  useFocusEffect(useCallback(() => {
    scanLock.current = false;
    void requestPermission();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []));

  if (!permission) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.startingText}>{t("mobile.scanner.starting")}</Text>
      </View>
    );
  }

  if (!permission.granted) {
    // canAskAgain === false means the OS will silently ignore another
    // prompt, so the only honest action left is a jump to Settings.
    const blocked = !permission.canAskAgain;
    return (
      <View style={s.center}>
        <PermissionCard
          body={t(blocked ? "mobile.scanner.permission_blocked_body" : "mobile.scanner.permission_body")}
          actionLabel={t(blocked ? "mobile.scanner.permission_settings" : "mobile.scanner.permission_allow")}
          onAction={() => void (blocked ? Linking.openSettings() : requestPermission())}
        />
      </View>
    );
  }

  function handleBarCodeScanned({ data }: { data: string }) {
    if (scanLock.current) return;
    scanLock.current = true;
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

    // A QR payload is arbitrary text. The old parser handed anything containing
    // a dot straight to the server — a wifi config, a vCard, a URL with a token
    // in its query — under a privacy line promising only the website name is
    // sent. src/utils/host.ts reduces it to a hostname or refuses.
    const domain = toCheckableHost(data);

    if (!domain) {
      Alert.alert(t("mobile.scanner.no_link_title"), t("mobile.scanner.no_link_body"), [
        { text: t("mobile.scanner.scan_again"), onPress: () => { scanLock.current = false; } },
      ]);
      return;
    }

    router.push({ pathname: "/result", params: { domain } });
  }

  return (
    <View style={s.container}>
      <CameraView
        style={s.camera}
        onBarcodeScanned={handleBarCodeScanned}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
      >
        {/* Dimmed surround with a clear cut-out around the viewfinder. */}
        <View style={s.dim} />
        <View style={s.frameRow}>
          <View style={s.dim} />
          <View style={s.frame} />
          <View style={s.dim} />
        </View>

        <View style={[s.dim, s.footer]}>
          <Text style={s.instruction}>{t("mobile.scanner.instruction")}</Text>
          <Text style={s.instructionSub}>{t("mobile.scanner.instruction_sub")}</Text>

          <View style={s.privacyRow}>
            <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
            <Text style={s.privacy}>{t("mobile.scanner.privacy")}</Text>
          </View>
        </View>
      </CameraView>
    </View>
  );
}

function PermissionCard({
  body, actionLabel, onAction,
}: {
  body: string;
  actionLabel: string;
  onAction: () => void;
}) {
  const { t } = useTranslation();
  return (
    <View style={s.card}>
      <View style={s.iconBox}>
        <Ionicons name="camera-outline" size={22} color={colors.textSecondary} />
      </View>
      <Text style={s.cardTitle}>{t("mobile.scanner.permission_title")}</Text>
      <Text style={s.cardBody}>{body}</Text>
      <TouchableOpacity
        style={s.primaryBtn}
        onPress={onAction}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Text style={s.primaryLabel}>{actionLabel}</Text>
      </TouchableOpacity>
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  camera: { flex: 1, width: "100%" },

  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, paddingHorizontal: space.xl, paddingBottom: 100,
  },
  startingText: { ...typo.body, color: colors.textSecondary, marginTop: space.lg },

  // Permission state
  card: {
    width: "100%",
    backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
    alignItems: "center",
  },
  iconBox: {
    width: 48, height: 48, borderRadius: radius.icon,
    backgroundColor: colors.surfaceRaised,
    alignItems: "center", justifyContent: "center",
  },
  cardTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.md },
  cardBody: {
    ...typo.body, color: colors.textSecondary,
    textAlign: "center", marginTop: space.sm,
  },
  primaryBtn: {
    height: 50, alignSelf: "stretch",
    backgroundColor: colors.blue, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  // Camera overlay
  dim: { flex: 1, backgroundColor: "#0B1220B3" },
  frameRow: { flexDirection: "row", height: FRAME },
  frame: {
    width: FRAME, height: FRAME,
    borderWidth: 2, borderColor: colors.blue,
    borderRadius: radius.card, backgroundColor: "transparent",
  },
  footer: { alignItems: "center", paddingTop: space.xxl, paddingHorizontal: space.xl },
  instruction: { ...typo.headline, color: colors.textPrimary, textAlign: "center" },
  instructionSub: {
    ...typo.body, color: colors.textSecondary,
    textAlign: "center", marginTop: space.xs,
  },

  secondaryBtn: {
    height: 50, flexDirection: "row", gap: space.sm, alignSelf: "stretch",
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  secondaryLabel: { fontSize: 15, fontWeight: "600", color: colors.blue },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
