import { View, Text, StyleSheet, Modal, TouchableOpacity, ScrollView, Linking } from "react-native";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import { SMS_FILTER_SETUP } from "../../utils/platform-features";

/**
 * How to turn on the iPhone's scam-text filter (docs/IOS.md §5). iOS lets
 * only the person switch an SMS filter on, in Settings → Apps → Messages →
 * Unknown & Spam → SMS Filtering, and never tells the app whether they did —
 * so this sheet gives the steps and says plainly what the filter does and
 * does not do. There is no public link to the Messages settings page (the
 * private settings URLs are a review rejection); "Open Settings" opens
 * Cleanway's own page, one level below Apps.
 */
export function SmsFilterSetupSheet({ visible, onClose }: { visible: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View style={s.scrim}>
        <View style={s.sheet}>
          <ScrollView bounces={false} contentContainerStyle={s.scroll}>
            <Text style={s.title} accessibilityRole="header">{t(SMS_FILTER_SETUP.titleKey)}</Text>
            <Text style={s.body}>{t(SMS_FILTER_SETUP.leadKey)}</Text>
            {SMS_FILTER_SETUP.stepKeys.map((key, i) => (
              <View key={key} style={s.step}>
                <View style={s.stepNum}>
                  <Text style={s.stepNumLabel}>{i + 1}</Text>
                </View>
                <Text style={s.stepText}>{t(key)}</Text>
              </View>
            ))}
            <Text style={s.older}>{t(SMS_FILTER_SETUP.olderKey)}</Text>
            {SMS_FILTER_SETUP.noteKeys.map((key) => (
              <Text key={key} style={s.note}>{t(key)}</Text>
            ))}
          </ScrollView>
          <TouchableOpacity
            style={s.primary}
            onPress={() => { void Linking.openSettings().catch(() => undefined); }}
            activeOpacity={0.85}
            accessibilityRole="button"
          >
            <Text style={s.primaryLabel}>{t(SMS_FILTER_SETUP.openSettingsKey)}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={s.secondary} onPress={onClose} activeOpacity={0.85} accessibilityRole="button">
            <Text style={s.secondaryLabel}>{t(SMS_FILTER_SETUP.doneKey)}</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

const s = StyleSheet.create({
  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    paddingHorizontal: space.xxl, paddingTop: space.xxl, paddingBottom: space.huge,
    maxHeight: "88%",
  },
  scroll: { paddingBottom: space.sm },
  title: { ...typo.headline, color: colors.textPrimary },
  body: { ...typo.body, color: colors.textSecondary, marginTop: space.sm },
  step: { flexDirection: "row", alignItems: "flex-start", gap: space.md, marginTop: space.lg },
  stepNum: {
    width: 26, height: 26, borderRadius: 13, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center",
  },
  stepNumLabel: { fontSize: 14, fontWeight: "700", color: "#FFFFFF" },
  stepText: { ...typo.body, color: colors.textPrimary, flex: 1, paddingTop: 2 },
  older: { ...typo.caption, color: colors.textMuted, marginTop: space.md },
  note: { ...typo.caption, color: colors.textSecondary, marginTop: space.md },
  primary: {
    minHeight: 50, paddingHorizontal: space.lg, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.lg,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondary: { minHeight: 48, alignItems: "center", justifyContent: "center", marginTop: space.sm },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.blue },
});
