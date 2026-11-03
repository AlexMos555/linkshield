import { View, Text, StyleSheet, Pressable, Linking } from "react-native";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../utils/theme";
import { GOOGLE_ADVISORY_LINKS } from "../../utils/google-advisory";

/**
 * "Advisory provided by Google", linked to the Web Risk Advisory, and the
 * learn-more links — under a verdict one of whose reasons is Google's
 * (src/utils/google-advisory.ts hasGoogleAdvisory). Web Risk's rules for
 * warnings ask for both; a verdict on other sources shows none of it.
 * The words are the extension's (extension.advisory), the same on every
 * surface.
 */
export function GoogleAdvisory() {
  const { t } = useTranslation();
  const open = (url: string) => () => void Linking.openURL(url).catch(() => undefined);
  return (
    <View style={s.box}>
      <Pressable onPress={open(GOOGLE_ADVISORY_LINKS.advisory)} style={s.target} accessibilityRole="link">
        <Text style={s.credit}>{t("extension.advisory.google")}</Text>
      </Pressable>
      <View style={s.moreRow}>
        <Text style={s.more}>{t("extension.advisory.learn_more")}</Text>
        <Pressable onPress={open(GOOGLE_ADVISORY_LINKS.phishing)} style={s.target} accessibilityRole="link">
          <Text style={s.link}>{t("extension.advisory.learn_phishing")}</Text>
        </Pressable>
        <Text style={s.more} accessibilityElementsHidden importantForAccessibility="no">·</Text>
        <Pressable onPress={open(GOOGLE_ADVISORY_LINKS.malware)} style={s.target} accessibilityRole="link">
          <Text style={s.link}>{t("extension.advisory.learn_malware")}</Text>
        </Pressable>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  box: { borderTopWidth: 1, borderTopColor: colors.hairline, marginTop: space.sm, paddingTop: space.xs },
  // 44 pt tall: a finger, not a pointer, has to hit these.
  target: { minHeight: 44, justifyContent: "center" },
  credit: { ...typo.caption, color: colors.blue, textDecorationLine: "underline" },
  moreRow: { flexDirection: "row", flexWrap: "wrap", alignItems: "center", columnGap: space.sm },
  more: { ...typo.caption, color: colors.textMuted },
  link: { ...typo.caption, color: colors.blue, textDecorationLine: "underline" },
});
