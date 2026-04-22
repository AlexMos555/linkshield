import { Tabs } from "expo-router";
import { Text } from "react-native";

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerStyle: { backgroundColor: "#0f172a" },
        headerTintColor: "#f8fafc",
        tabBarStyle: {
          backgroundColor: "#0f172a",
          borderTopColor: "#1e293b",
          height: 56,
          paddingBottom: 6,
        },
        tabBarActiveTintColor: "#22c55e",
        tabBarInactiveTintColor: "#64748b",
        tabBarLabelStyle: { fontSize: 10 },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "Shield",
          headerTitle: "Cleanway",
          tabBarIcon: ({ color }) => <Text style={{ fontSize: 20, color }}>&#x1F6E1;</Text>,
        }}
      />
      <Tabs.Screen
        name="history"
        options={{
          title: "History",
          tabBarIcon: ({ color }) => <Text style={{ fontSize: 20, color }}>&#x1F4CB;</Text>,
        }}
      />
      <Tabs.Screen
        name="score"
        options={{
          title: "Score",
          tabBarIcon: ({ color }) => <Text style={{ fontSize: 20, color }}>&#x1F3AF;</Text>,
        }}
      />
      <Tabs.Screen
        name="settings"
        options={{
          title: "Settings",
          tabBarIcon: ({ color }) => <Text style={{ fontSize: 20, color }}>&#x2699;</Text>,
        }}
      />
    </Tabs>
  );
}
