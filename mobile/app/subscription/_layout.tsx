import { Stack } from "expo-router";
import { useTranslation } from "react-i18next";

/**
 * The subscription screens (billing plan §2.5). Reachable only when the
 * build's billing switch is on: Settings and the home card link here, and
 * the hub redirects home otherwise.
 */
export default function SubscriptionLayout() {
  const { t } = useTranslation();
  return (
    <Stack
      screenOptions={{
        headerStyle: { backgroundColor: "#0f172a" },
        headerTintColor: "#f8fafc",
        headerTitleStyle: { fontWeight: "700" },
        contentStyle: { backgroundColor: "#0f172a" },
      }}
    >
      <Stack.Screen name="index" options={{ title: t("mobile.billing.title") }} />
      <Stack.Screen name="plans" options={{ title: t("mobile.billing.plans_title") }} />
      <Stack.Screen name="checkout" options={{ title: t("mobile.billing.checkout_title") }} />
      <Stack.Screen name="sms" options={{ title: t("mobile.billing.sms_title"), headerBackVisible: false }} />
      <Stack.Screen name="add-phone" options={{ title: t("mobile.billing.add_title") }} />
      <Stack.Screen name="join" options={{ title: t("mobile.billing.join_title") }} />
      <Stack.Screen name="devices" options={{ title: t("mobile.billing.devices_title") }} />
    </Stack>
  );
}
