import { useState, useEffect } from "react";
import { View, Text, StyleSheet, TouchableOpacity, Alert } from "react-native";
import { CameraView, useCameraPermissions } from "expo-camera";
import { useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";

export default function ScannerScreen() {
  const router = useRouter();
  const [permission, requestPermission] = useCameraPermissions();
  const [scanned, setScanned] = useState(false);

  if (!permission) {
    return <View style={styles.container}><Text style={styles.text}>Loading camera...</Text></View>;
  }

  if (!permission.granted) {
    return (
      <View style={styles.container}>
        <Text style={styles.icon}>{"\u{1F4F7}"}</Text>
        <Text style={styles.title}>Camera Access</Text>
        <Text style={styles.text}>LinkShield needs camera access to scan QR codes and check if links are safe.</Text>
        <TouchableOpacity style={styles.btn} onPress={requestPermission}>
          <Text style={styles.btnText}>Allow Camera</Text>
        </TouchableOpacity>
      </View>
    );
  }

  function handleBarCodeScanned({ data }: { data: string }) {
    if (scanned) return;
    setScanned(true);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);

    // Extract domain from scanned URL
    let domain = data;
    try {
      if (data.startsWith("http")) {
        domain = new URL(data).hostname;
      }
    } catch {}

    if (!domain.includes(".")) {
      Alert.alert("Not a URL", "The scanned QR code doesn't contain a valid URL.", [
        { text: "Scan Again", onPress: () => setScanned(false) },
      ]);
      return;
    }

    router.push({ pathname: "/result", params: { domain } });
  }

  return (
    <View style={styles.container}>
      <CameraView
        style={styles.camera}
        onBarcodeScanned={scanned ? undefined : handleBarCodeScanned}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
      >
        <View style={styles.overlay}>
          <View style={styles.scanFrame} />
          <Text style={styles.scanText}>Point at a QR code to check the link</Text>
        </View>
      </CameraView>

      {scanned && (
        <TouchableOpacity style={styles.rescanBtn} onPress={() => setScanned(false)}>
          <Text style={styles.rescanText}>Scan Again</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, alignItems: "center", justifyContent: "center" },
  camera: { flex: 1, width: "100%" },
  overlay: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "rgba(0,0,0,0.4)" },
  scanFrame: {
    width: 250, height: 250, borderWidth: 3, borderColor: colors.safe,
    borderRadius: 20, backgroundColor: "transparent",
  },
  scanText: { color: colors.white, fontSize: fontSize.md, marginTop: spacing.lg, textAlign: "center" },
  icon: { fontSize: 48, marginBottom: spacing.md },
  title: { color: colors.white, fontSize: fontSize.xxl, fontWeight: "800", marginBottom: spacing.sm },
  text: { color: colors.textSecondary, fontSize: fontSize.md, textAlign: "center", padding: spacing.xl, lineHeight: 24 },
  btn: { backgroundColor: colors.accent, paddingHorizontal: 32, paddingVertical: 16, borderRadius: 12, marginTop: spacing.lg },
  btnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
  rescanBtn: {
    position: "absolute", bottom: 60,
    backgroundColor: colors.bgCard, paddingHorizontal: 32, paddingVertical: 14, borderRadius: 12,
  },
  rescanText: { color: colors.white, fontWeight: "700", fontSize: fontSize.md },
});
