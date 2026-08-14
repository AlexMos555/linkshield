import { useState } from "react";
import {
  View, Text, StyleSheet, TouchableOpacity, Dimensions,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";
import { setSetting } from "../src/services/database";

const { width } = Dimensions.get("window");

// Every sentence here is checked against what the app actually does. The old
// slides promised "checks every link you open" (nothing on iOS does), cited
// "9 threat intelligence sources" (the API itself says 16), and claimed
// "even if our servers are breached, your data is safe" — an overclaim this
// product's own privacy doc refuses to make.
const slides = [
  {
    icon: "search-outline" as const,
    titleKey: "mobile.onboarding.s1_title",
    descKey: "mobile.onboarding.s1_desc",
  },
  {
    icon: "lock-closed-outline" as const,
    titleKey: "mobile.onboarding.s2_title",
    descKey: "mobile.onboarding.s2_desc",
  },
  {
    icon: "shield-outline" as const,
    titleKey: "mobile.onboarding.s3_title",
    descKey: "mobile.onboarding.s3_desc",
  },
];

export default function OnboardingScreen() {
  const router = useRouter();
  const { t } = useTranslation();
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
        <Ionicons name={slide.icon} size={72} color={colors.safe} style={styles.iconGlyph} />
        <Text style={styles.title}>{t(slide.titleKey)}</Text>
        <Text style={styles.desc}>{t(slide.descKey)}</Text>
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
              <Text style={styles.skipText}>{t("mobile.onboarding.skip")}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.nextBtn} onPress={next}>
              <Text style={styles.nextBtnText}>{t("mobile.onboarding.next")}</Text>
            </TouchableOpacity>
          </>
        ) : (
          <TouchableOpacity style={[styles.nextBtn, styles.startBtn]} onPress={finish}>
            <Text style={styles.nextBtnText}>{t("mobile.onboarding.start")}</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg, justifyContent: "space-between", padding: spacing.xl },
  content: { flex: 1, alignItems: "center", justifyContent: "center" },
  iconGlyph: { alignSelf: "center", marginBottom: spacing.xl },
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
