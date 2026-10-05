/**
 * The phones on this subscription (billing plan §2.4), for the payer: which
 * one is this, which one pays, when each joined, and "remove this phone" —
 * with a confirmation that says what happens to protection on that phone.
 */
import { useCallback, useState } from "react";
import { Alert, StyleSheet, Text, View } from "react-native";
import { useFocusEffect } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Card, Hint, Screen, Spinner } from "../../src/components/billing/Ui";
import { useBilling } from "../../src/hooks/useBilling";
import type { DevicesAnswer, SeatDevice } from "../../src/lib/billing-api";
import { billing } from "../../src/services/billing";
import { errorCopyKey } from "../../src/utils/billing-copy";
import { calendarDate } from "../../src/utils/relative-time";
import { colors, radius, space } from "../../src/utils/theme";

export default function DevicesScreen() {
  const { t, i18n } = useTranslation();
  const b = useBilling();
  const [answer, setAnswer] = useState<DevicesAnswer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [removing, setRemoving] = useState<string | null>(null);

  const load = useCallback(async () => {
    const result = await billing.listDevices();
    if (result.data) {
      setAnswer(result.data);
      setError(null);
    } else {
      setError(result.error.code);
    }
    setLoading(false);
  }, []);

  useFocusEffect(useCallback(() => {
    void load();
  }, [load]));

  function confirmRemove(device: SeatDevice) {
    const bodyKey = device.is_this_device
      ? "mobile.billing.device_remove_self"
      : b.lapsePolicy === "basic" ? "mobile.billing.device_remove_confirm_basic" : "mobile.billing.device_remove_confirm_off";
    Alert.alert(t("mobile.billing.device_remove_confirm_title"), t(bodyKey), [
      { text: t("mobile.billing.cancel_keep"), style: "cancel" },
      { text: t("mobile.billing.device_remove_do"), style: "destructive", onPress: () => void remove(device.device_id) },
    ]);
  }

  async function remove(deviceId: string) {
    setRemoving(deviceId);
    const result = await billing.removeSeat(deviceId);
    setRemoving(null);
    if (!result.data) {
      const key = errorCopyKey(result.error.code);
      Alert.alert(t("mobile.billing.devices_failed"), key ? t(key) : t("mobile.billing.error_generic", { code: result.error.code }));
      return;
    }
    await load();
  }

  if (loading) return <Screen><Spinner /></Screen>;

  if (!answer) {
    const key = errorCopyKey(error);
    return (
      <Screen>
        <Hint icon="alert-circle-outline">{key ? t(key) : t("mobile.billing.devices_failed")}</Hint>
        <BigButton label={t("mobile.billing.retry")} onPress={() => { setLoading(true); void load(); }} />
      </Screen>
    );
  }

  return (
    <Screen>
      <Text style={s.count}>{t("mobile.billing.devices_count", { used: answer.seats_used, total: answer.seats_total })}</Text>
      {answer.devices.map((device) => (
        <Card key={device.device_id}>
          <View style={s.row}>
            <Text style={s.name}>{t(device.is_this_device ? "mobile.billing.device_this" : "mobile.billing.device_other")}</Text>
            {device.role === "owner" && <Text style={s.pill}>{t("mobile.billing.device_owner")}</Text>}
          </View>
          <Text style={s.date}>{t("mobile.billing.device_added", { date: calendarDate(device.claimed_at * 1000, i18n.language) })}</Text>
          {answer.is_payer && (
            <BigButton
              kind="danger"
              label={t("mobile.billing.device_remove")}
              onPress={() => confirmRemove(device)}
              busy={removing === device.device_id}
            />
          )}
        </Card>
      ))}
      {!answer.is_payer && <Hint>{t("mobile.billing.devices_not_payer")}</Hint>}
    </Screen>
  );
}

const s = StyleSheet.create({
  count: { fontSize: 17, lineHeight: 24, color: colors.textSecondary },
  row: { flexDirection: "row", alignItems: "center", gap: space.sm },
  name: { fontSize: 20, fontWeight: "700", color: colors.textPrimary, flex: 1 },
  pill: {
    backgroundColor: colors.greenWash, color: colors.green, overflow: "hidden", borderRadius: radius.pill,
    paddingHorizontal: space.md, paddingVertical: 6, fontSize: 14, fontWeight: "600",
  },
  date: { fontSize: 16, color: colors.textSecondary },
});
