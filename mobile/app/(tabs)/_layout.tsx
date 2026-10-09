import { Platform } from "react-native";
import { Tabs } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useTranslation } from "react-i18next";
import { colors } from "../../src/utils/theme";

interface TabIconProps {
  focused: boolean;
  color: string;
}

/** Outline at rest, filled when active — quiet, no emoji, one green accent. */
function icon(outline: keyof typeof Ionicons.glyphMap, filled: keyof typeof Ionicons.glyphMap) {
  return ({ focused, color }: TabIconProps) => (
    <Ionicons name={focused ? filled : outline} size={24} color={color} />
  );
}

export default function TabLayout() {
  const { t } = useTranslation();
  // The bar's height INCLUDES the bottom inset (bottom-tabs pads by it). The
  // fixed 84 fits an iPhone (home indicator inside it). Since targetSdk 35+ the
  // app is drawn edge-to-edge on Android too, and the 3-button navigation bar
  // (48 dp) then covered the tab labels — so on Android the bar is its content
  // height plus the inset the phone reports.
  const insets = useSafeAreaInsets();
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: colors.bg },
        headerShadowVisible: false,
        headerTintColor: colors.textPrimary,
        headerTitleStyle: { fontSize: 17, fontWeight: "600" },
        // The header has a fixed height: at the largest accessibility text
        // sizes the title grew past it and was cut in half (iOS simulator,
        // Dynamic Type AX-XL). iOS's own navigation titles stay put too; the
        // screens' content still follows the person's text size.
        headerTitleAllowFontScaling: false,
        tabBarStyle: {
          backgroundColor: colors.bg,
          borderTopWidth: 1,
          borderTopColor: colors.hairline,
          height: Platform.OS === "android" ? 62 + insets.bottom : 84,
          paddingTop: 6,
        },
        tabBarActiveTintColor: colors.green,
        tabBarInactiveTintColor: colors.textMuted,
        tabBarLabelStyle: { fontSize: 11, fontWeight: "600" },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: t("mobile.tabs.shield"),
          headerTitle: "Cleanway",
          tabBarIcon: icon("shield-outline", "shield"),
        }}
      />
      <Tabs.Screen
        name="history"
        options={{
          title: t("mobile.tabs.history"),
          tabBarIcon: icon("time-outline", "time"),
        }}
      />
      <Tabs.Screen
        name="score"
        options={{
          title: t("mobile.tabs.score"),
          tabBarIcon: icon("speedometer-outline", "speedometer"),
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: t("mobile.tabs.settings"),
          tabBarIcon: icon("settings-outline", "settings"),
        }}
      />
    </Tabs>
  );
}
