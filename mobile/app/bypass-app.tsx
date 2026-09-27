import { useEffect, useMemo, useState } from "react";
import {
  View, Text, StyleSheet, SectionList, TouchableOpacity, Alert, Image, ActivityIndicator,
} from "react-native";
import { useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius, sectionHeader } from "../src/utils/theme";
import { pickableBypassApps, addBypassApp, groupPickable, type BypassApp } from "../modules/cleanway-vpn";

/**
 * "An app asks me to turn off the VPN" — pick it, and it runs outside the
 * shield while everything else stays protected (AppExclusions.kt).
 *
 * Apps known to ask come first; that is nearly always the one. The list is
 * the apps on this phone's home screen, read on the phone and never sent
 * anywhere. Choosing is behind a confirmation that says what it costs; a
 * browser gets a stronger one, because without the filter everything opened
 * in it goes unchecked.
 */
export default function BypassAppScreen() {
  const router = useRouter();
  const { t, i18n } = useTranslation();
  // undefined: loading; null: this build cannot list apps.
  const [apps, setApps] = useState<BypassApp[] | null | undefined>(undefined);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let alive = true;
    void pickableBypassApps().then((list) => {
      if (alive) setApps(list);
    });
    return () => {
      alive = false;
    };
  }, []);

  const sections = useMemo(() => {
    if (!apps) return [];
    const { suggested, others } = groupPickable(apps, i18n.language);
    return [
      ...(suggested.length > 0 ? [{ key: "suggested", title: t("mobile.bypass.suggested"), data: suggested }] : []),
      ...(others.length > 0 ? [{ key: "all", title: t("mobile.bypass.all"), data: others }] : []),
    ];
  }, [apps, i18n.language, t]);

  function confirm(app: BypassApp) {
    Alert.alert(
      t("mobile.bypass.confirm_title", { app: app.label }),
      t(app.isBrowser ? "mobile.bypass.confirm_browser" : "mobile.bypass.confirm_body", { app: app.label }),
      [
        { text: t("mobile.bypass.cancel"), style: "cancel" },
        {
          text: t("mobile.bypass.confirm"),
          style: app.isBrowser ? "destructive" : "default",
          onPress: () => void save(app),
        },
      ],
    );
  }

  async function save(app: BypassApp) {
    if (saving) return;
    setSaving(true);
    const ok = await addBypassApp(app.package);
    setSaving(false);
    if (ok) {
      router.back();
    } else {
      Alert.alert(t("mobile.bypass.save_failed"));
    }
  }

  if (apps === undefined) {
    return (
      <View style={[s.container, s.center]}>
        <ActivityIndicator color={colors.textSecondary} />
        <Text style={s.muted}>{t("mobile.bypass.loading")}</Text>
      </View>
    );
  }

  return (
    <SectionList
      style={s.container}
      contentContainerStyle={s.content}
      sections={sections}
      keyExtractor={(item) => item.package}
      stickySectionHeadersEnabled={false}
      ListHeaderComponent={<Text style={s.intro}>{t("mobile.bypass.intro")}</Text>}
      ListEmptyComponent={
        <Text style={s.muted}>{t(apps === null ? "mobile.bypass.failed" : "mobile.bypass.empty")}</Text>
      }
      renderSectionHeader={({ section }) => <Text style={s.sectionTitle}>{section.title}</Text>}
      renderItem={({ item }) => (
        <TouchableOpacity
          style={s.row}
          onPress={() => confirm(item)}
          disabled={saving}
          activeOpacity={0.85}
          accessibilityRole="button"
          accessibilityLabel={item.isBrowser ? `${item.label}, ${t("mobile.bypass.browser_tag")}` : item.label}
        >
          {item.icon ? (
            <Image source={{ uri: item.icon }} style={s.icon} accessibilityIgnoresInvertColors />
          ) : (
            <View style={[s.icon, s.iconFallback]}>
              <Ionicons name="apps-outline" size={22} color={colors.textSecondary} />
            </View>
          )}
          <Text style={s.label} numberOfLines={2}>{item.label}</Text>
          {item.isBrowser ? <Text style={s.tag}>{t("mobile.bypass.browser_tag")}</Text> : null}
        </TouchableOpacity>
      )}
    />
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  center: { alignItems: "center", justifyContent: "center", gap: space.md },
  content: { paddingHorizontal: space.xl, paddingTop: space.lg, paddingBottom: 100 },
  intro: { ...typo.body, color: colors.textPrimary, marginBottom: space.sm },
  muted: { ...typo.body, color: colors.textSecondary, marginTop: space.lg, textAlign: "center" },
  sectionTitle: { ...sectionHeader, marginTop: space.xxl, marginBottom: space.sm, marginLeft: space.xs },
  row: {
    flexDirection: "row", alignItems: "center", gap: space.md,
    minHeight: 60, paddingVertical: space.md, paddingHorizontal: space.lg, marginBottom: space.sm,
    backgroundColor: colors.surface, borderColor: colors.stroke, borderWidth: 1, borderRadius: radius.control,
  },
  icon: { width: 40, height: 40, borderRadius: radius.icon },
  iconFallback: { alignItems: "center", justifyContent: "center", backgroundColor: colors.surfaceRaised },
  label: { ...typo.body, fontWeight: "600", color: colors.textPrimary, flex: 1 },
  tag: {
    ...typo.caption, color: colors.amber, backgroundColor: colors.amberWash, overflow: "hidden",
    borderRadius: radius.chip, paddingHorizontal: space.sm, paddingVertical: 2,
  },
});
