import { useState } from "react";
import {
  View, Text, StyleSheet, TouchableOpacity, Dimensions,
} from "react-native";
import { useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { setSetting } from "../src/services/database";

const { width } = Dimensions.get("window");

const slides = [
  {
    icon: "\u{1F6E1}",
    title: "Automatic Protection",
    desc: "LinkShield checks every link you open against 9 threat intelligence sources and an ML model. Dangerous sites are blocked before they can harm you.",
  },
  {
    icon: "\u{1F512}",
    title: "Your Data, Your Device",
    desc: "Your browsing history never leaves this device. We only see domain names for safety checks. Even if our servers are breached, your data is safe.",
  },
  {
    icon: "\u{26A1}",
    title: "Set & Forget",
    desc: "Enable protection once — LinkShield works silently in the background. VPN mode checks every domain. No action needed from you.",
  },
];

export default function OnboardingScreen() {
  const router = useRouter();
  const [page, setPage] = useState(0);

  async function finish() {
    await setSetting("onboarding_done", "true");
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    router.replace("/(tabs)");
  }

  function next() {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (page < slides.length - 1) {
      setPage(page + 1);
    } else {
      finish();
    }
  }

  const slide = slides[page];

  return (
    <View style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.icon}>{slide.icon}</Text>
        <Text style={styles.title}>{slide.title}</Text>
        <Text style={styles.desc}>{slide.desc}</Text>
      </View>

      {/* Dots */}
      <View style={styles.dots}>
        {slides.map((_, i) => (
          <View key={i} style={[styles.dot, i === page && styles.dotActive]} />
        ))}
      </View>

      {/* Buttons */}
      <View style={styles.buttons}>
        {page < slides.length - 1 ? (
          <>
            <TouchableOpacity onPress={finish}>
              <Text style={styles.skipText}>Skip</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.nextBtn} onPress={next}>
              <Text style={styles.nextBtnText}>Next &rarr;</Text>
            </TouchableOpacity>
          </>
        ) : (
          <TouchableOpacity style={[styles.nextBtn, styles.startBtn]} onPress={finish}>
            <Text style={styles.nextBtnText}>Get Started</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, justifyContent: "space-between", padding: spacing.xl },
  content: { flex: 1, alignItems: "center", justifyContent: "center" },
  icon: { fontSize: 80, marginBottom: spacing.xl },
  title: { fontSize: 28, fontWeight: "800", color: colors.white, textAlign: "center", marginBottom: spacing.md },
  desc: {
    fontSize: fontSize.lg, color: colors.textSecondary, textAlign: "center",
    lineHeight: 26, maxWidth: width * 0.8,
  },
  dots: { flexDirection: "row", justifyContent: "center", gap: 8, marginBottom: spacing.xl },
  dot: { width: 8, height: 8, borderRadius: 4, backgroundColor: colors.border },
  dotActive: { backgroundColor: colors.safe, width: 24 },
  buttons: {
    flexDirection: "row", justifyContent: "space-between", alignItems: "center",
    paddingBottom: spacing.xl,
  },
  skipText: { color: colors.textMuted, fontSize: fontSize.md, padding: spacing.md },
  nextBtn: {
    backgroundColor: colors.accent, paddingHorizontal: 32, paddingVertical: 16,
    borderRadius: 12,
  },
  startBtn: { flex: 1, alignItems: "center" },
  nextBtnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.lg },
});
