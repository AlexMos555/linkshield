import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius, sectionHeader } from "../../utils/theme";
import { iosLeadKey, type IosLayer, type IosLayerId } from "../../utils/platform-features";

type IconName = keyof typeof Ionicons.glyphMap;

const ICONS: Record<IosLayerId, IconName> = {
  safari: "compass-outline",
  sms_filter: "chatbubble-ellipses-outline",
  dns: "globe-outline",
};

/**
 * How an iPhone is protected (src/utils/platform-features.ts): the Safari
 * extension, the scam-text filter and DNS protection, each with its honest
 * status. A layer that is not built yet says "Coming soon" — no switch, no
 * chevron, not tappable. When a later build reports a layer as "setup",
 * its row offers [onSetUp]; "on" shows a check, and its row opens the same
 * flow (to see the state, or to remove it).
 */
export function IosProtectionCard({ layers, onSetUp }: {
  layers: IosLayer[];
  onSetUp?: (id: IosLayerId) => void;
}) {
  const { t } = useTranslation();
  return (
    <View>
      <Text style={s.header} accessibilityRole="header">{t("mobile.ios.header")}</Text>
      <View style={s.card}>
        <Text style={s.lead}>{t(iosLeadKey(layers))}</Text>
        {layers.map((layer) => {
          const ready = layer.status !== "coming";
          const row = (
            <>
              <Ionicons
                name={ICONS[layer.id]}
                size={20}
                color={layer.status === "on" ? colors.green : ready ? colors.textSecondary : colors.textDisabled}
              />
              <View style={s.rowText}>
                <Text style={[s.title, !ready && s.titleMuted]}>{t(layer.titleKey)}</Text>
                <Text style={s.line}>{t(layer.lineKey)}</Text>
              </View>
              {layer.status === "on" ? (
                <Ionicons name="checkmark-circle" size={22} color={colors.green} accessibilityLabel={t("mobile.ios.on")} />
              ) : layer.status === "setup" ? (
                <Text style={s.setUp}>{t("mobile.ios.set_up")}</Text>
              ) : (
                <View style={s.pill}>
                  <Text style={s.pillLabel}>{t("mobile.ios.coming")}</Text>
                </View>
              )}
            </>
          );
          return ready && onSetUp ? (
            <TouchableOpacity
              key={layer.id}
              style={[s.row, s.rowBorder]}
              onPress={() => onSetUp(layer.id)}
              activeOpacity={0.85}
              accessibilityRole="button"
              accessibilityLabel={`${t(layer.titleKey)}, ${t(layer.status === "on" ? "mobile.ios.on" : "mobile.ios.set_up")}`}
            >
              {row}
            </TouchableOpacity>
          ) : (
            <View key={layer.id} style={[s.row, s.rowBorder]} accessibilityState={{ disabled: !ready }}>
              {row}
            </View>
          );
        })}
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  header: { ...sectionHeader, marginBottom: space.sm },
  card: {
    backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card,
  },
  lead: { ...typo.body, color: colors.textSecondary, paddingHorizontal: space.lg, paddingVertical: 14 },
  row: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    paddingVertical: 14, paddingHorizontal: space.lg, minHeight: 56,
  },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  rowText: { flex: 1 },
  title: { fontSize: 15, fontWeight: "600", color: colors.textPrimary },
  titleMuted: { color: colors.textSecondary },
  line: { ...typo.caption, color: colors.textSecondary, marginTop: 2 },
  setUp: { fontSize: 15, fontWeight: "600", color: colors.blue },
  pill: {
    backgroundColor: "#FFFFFF0A",
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.pill, paddingHorizontal: 10, paddingVertical: 4,
  },
  pillLabel: { fontSize: 12, fontWeight: "600", color: colors.textMuted },
});
