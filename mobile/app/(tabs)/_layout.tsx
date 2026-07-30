import { Tabs } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
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
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: colors.bg },
        headerShadowVisible: false,
        headerTintColor: colors.textPrimary,
        headerTitleStyle: { fontSize: 17, fontWeight: "600" },
        tabBarStyle: {
          backgroundColor: colors.bg,
          borderTopWidth: 1,
          borderTopColor: colors.hairline,
          height: 84,
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
          title: "Shield",
          headerTitle: "Cleanway",
          tabBarIcon: icon("shield-outline", "shield"),
        }}
      />
      <Tabs.Screen
        name="history"
        options={{
          title: "History",
          tabBarIcon: icon("time-outline", "time"),
        }}
      />
      <Tabs.Screen
        name="score"
        options={{
          title: "Score",
          tabBarIcon: icon("speedometer-outline", "speedometer"),
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: "Settings",
          tabBarIcon: icon("settings-outline", "settings"),
        }}
      />
    </Tabs>
  );
}
