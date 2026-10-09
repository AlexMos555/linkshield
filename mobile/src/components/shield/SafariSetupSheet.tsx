import { Modal, View, Text, StyleSheet, TouchableOpacity, ScrollView } from "react-native";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import { SAFARI_SETUP_STEP_KEYS } from "../../utils/platform-features";

/**
 * How to switch on the Safari extension. iOS lets no app flip the switch,
 * so this lists the steps in Settings, plus two shortcuts: "Open Safari
 * settings" (iOS 26.2+ only — older iOS has no way to open that page) and
 * "Test it in Safari", which opens cleanway.ai where the extension tells the
 * app it runs; the home card then says "On".
 */
export function SafariSetupSheet({ visible, canOpenSettings, onOpenSettings, onTest, onClose }: {
  visible: boolean;
  canOpenSettings: boolean;
  onOpenSettings: () => void;
  onTest: () => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View style={s.scrim}>
        <TouchableOpacity style={s.scrimTap} activeOpacity={1} onPress={onClose} accessibilityLabel={t("mobile.ios.safari_setup_close")} />
        <View style={s.sheet}>
          <ScrollView bounces={false} contentContainerStyle={s.content}>
            <Text style={s.title} accessibilityRole="header">{t("mobile.ios.safari_setup_title")}</Text>
            {SAFARI_SETUP_STEP_KEYS.map((key, i) => (
              <View key={key} style={s.step}>
                <View style={s.num}>
                  <Text style={s.numLabel}>{i + 1}</Text>
                </View>
                <Text style={s.stepText}>{t(key)}</Text>
              </View>
            ))}
            <Text style={s.why}>{t("mobile.ios.safari_setup_why")}</Text>
            {canOpenSettings && (
              <TouchableOpacity style={s.primary} onPress={onOpenSettings} activeOpacity={0.85} accessibilityRole="button">
                <Text style={s.primaryLabel}>{t("mobile.ios.safari_setup_open_settings")}</Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity
              style={canOpenSettings ? s.secondary : s.primary}
              onPress={onTest}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Text style={canOpenSettings ? s.secondaryLabel : s.primaryLabel}>{t("mobile.ios.safari_setup_test")}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={s.close} onPress={onClose} activeOpacity={0.85} accessibilityRole="button">
              <Text style={s.closeLabel}>{t("mobile.ios.safari_setup_close")}</Text>
            </TouchableOpacity>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

const s = StyleSheet.create({
  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  scrimTap: { flex: 1 },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    maxHeight: "88%",
  },
  content: { padding: space.xxl, paddingBottom: space.huge },
  title: { ...typo.headline, color: colors.textPrimary, marginBottom: space.md },
  step: { flexDirection: "row", alignItems: "flex-start", gap: space.md, marginTop: space.md },
  num: {
    width: 24, height: 24, borderRadius: 12, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: 1,
  },
  numLabel: { fontSize: 13, fontWeight: "700", color: "#FFFFFF" },
  stepText: { ...typo.body, color: colors.textPrimary, flex: 1 },
  why: { ...typo.caption, color: colors.textSecondary, marginTop: space.lg },
  primary: {
    minHeight: 50, paddingHorizontal: space.lg, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondary: {
    minHeight: 50, paddingHorizontal: space.lg, borderRadius: radius.control,
    borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center", marginTop: space.md,
  },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.blue },
  close: { minHeight: 44, alignItems: "center", justifyContent: "center", marginTop: space.sm },
  closeLabel: { fontSize: 15, fontWeight: "600", color: colors.textSecondary },
});
