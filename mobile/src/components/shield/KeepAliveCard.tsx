import { View, Text, StyleSheet, TouchableOpacity, Alert } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

import { colors, type as typo, space, radius } from "../../utils/theme";
import { keepAliveRows, keepAliveTodo, type KeepAliveRow, type KeepAliveRowState, type KeepAliveShield } from "../../utils/keep-alive";
import type { KeepAlive } from "../../hooks/useKeepAlive";

/**
 * "Keep protection on" — the protection health list on the home screen.
 *
 * Phones stop background apps to save battery, and with them the shield; the
 * person only finds out (if ever) when they next open the app. Each row is one
 * thing that keeps it running, ticked only when the phone itself says so
 * (src/utils/keep-alive.ts). Every action opens a system screen the person
 * acts on, after a plain-words explanation of why — nothing is switched for
 * them.
 */

const ICON: Record<KeepAliveRowState, { name: keyof typeof Ionicons.glyphMap; color: string }> = {
  ok: { name: "checkmark-circle", color: colors.green },
  todo: { name: "alert-circle-outline", color: colors.amber },
  optional: { name: "add-circle-outline", color: colors.textSecondary },
  manual: { name: "help-circle-outline", color: colors.textSecondary },
  unknown: { name: "time-outline", color: colors.textSecondary },
};

interface Props {
  shield: KeepAliveShield;
  keepAlive: KeepAlive;
}

export function KeepAliveCard({ shield, keepAlive }: Props) {
  const { t } = useTranslation();
  const { status, notifications } = keepAlive;
  const rows = keepAliveRows({ shield, status, notifications });
  const todo = keepAliveTodo(rows);

  /** Say why before Android's own dialog, which only asks "let this app run in the background?". */
  function explainBattery() {
    Alert.alert(
      t("mobile.keep_alive.battery_explain_title"),
      t("mobile.keep_alive.battery_explain_body"),
      [
        { text: t("mobile.keep_alive.explain_cancel"), style: "cancel" },
        { text: t("mobile.keep_alive.explain_continue"), onPress: keepAlive.requestBattery },
      ],
      { cancelable: true },
    );
  }

  /** The phone maker's own manager: steps first (the screens differ by firmware), then the screen. */
  function explainOem() {
    if (!status.oem) return;
    Alert.alert(
      t(`mobile.keep_alive.oem_title_${status.oem}`),
      `${t(`mobile.keep_alive.oem_steps_${status.oem}`)}\n\n${t("mobile.keep_alive.oem_note")}`,
      [
        { text: t("mobile.keep_alive.explain_cancel"), style: "cancel" },
        { text: t("mobile.keep_alive.action_open_settings"), onPress: keepAlive.openOemSettings },
      ],
      { cancelable: true },
    );
  }

  function actionFor(row: KeepAliveRow): { label: string; onPress: () => void } | null {
    switch (row.id) {
      case "battery":
        return row.state === "todo" ? { label: t("mobile.keep_alive.action_allow"), onPress: explainBattery } : null;
      case "oem":
        return { label: t("mobile.keep_alive.action_how"), onPress: explainOem };
      case "notifications":
        return row.state === "todo"
          ? { label: t("mobile.keep_alive.action_turn_on"), onPress: () => void keepAlive.turnOnNotifications() }
          : null;
      case "always_on":
        // Also when on: Settings → VPN is where it is switched back off.
        return { label: t("mobile.keep_alive.action_open"), onPress: keepAlive.openAlwaysOn };
      default:
        // The shield itself is turned (back) on with the screen's main button.
        return null;
    }
  }

  return (
    <View style={s.card}>
      <Text style={s.title} accessibilityRole="header">{t("mobile.keep_alive.title")}</Text>
      <Text style={s.intro}>
        {todo > 0 ? t("mobile.keep_alive.intro") : t("mobile.keep_alive.all_set")}
      </Text>
      {rows.map((row) => {
        const action = actionFor(row);
        const label = rowLabel(t, row, shield, status.oem);
        const icon = ICON[row.state];
        const stateWord = t(`mobile.keep_alive.state_${row.state}`);
        const body = (
          <>
            <Ionicons name={icon.name} size={20} color={icon.color} />
            <Text style={[s.rowText, row.state === "todo" && { color: colors.amber }]}>{label}</Text>
            {action && <Text style={s.action}>{action.label}</Text>}
          </>
        );
        return action ? (
          <TouchableOpacity
            key={row.id}
            style={s.row}
            onPress={action.onPress}
            activeOpacity={0.7}
            accessibilityRole="button"
            accessibilityLabel={t("mobile.keep_alive.row_a11y", { label, state: stateWord })}
            accessibilityHint={action.label}
          >
            {body}
          </TouchableOpacity>
        ) : (
          <View
            key={row.id}
            style={s.row}
            accessible
            accessibilityLabel={t("mobile.keep_alive.row_a11y", { label, state: stateWord })}
          >
            {body}
          </View>
        );
      })}
    </View>
  );
}

function rowLabel(t: TFunction, row: KeepAliveRow, shield: KeepAliveShield, oem: string | null): string {
  switch (row.id) {
    case "running":
      return t(`mobile.keep_alive.running_${shield}`);
    case "battery":
      return t(row.state === "ok" ? "mobile.keep_alive.battery_ok" : "mobile.keep_alive.battery_todo");
    case "oem":
      return t(`mobile.keep_alive.oem_row_${oem ?? "samsung"}`);
    case "notifications":
      return t(row.state === "ok" ? "mobile.keep_alive.notifications_ok" : "mobile.keep_alive.notifications_todo");
    case "always_on":
      return t(row.state === "ok" ? "mobile.keep_alive.always_on_ok" : "mobile.keep_alive.always_on_optional");
  }
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface,
    borderRadius: radius.card,
    paddingHorizontal: space.lg,
    paddingTop: space.lg,
    paddingBottom: space.sm,
  },
  title: { ...typo.headline, color: colors.textPrimary },
  intro: { ...typo.caption, color: colors.textSecondary, marginTop: space.xs, marginBottom: space.sm },
  // 44pt minimum: every row with an action is a button as a whole.
  row: { flexDirection: "row", alignItems: "center", gap: space.sm, minHeight: 44, paddingVertical: space.xs },
  rowText: { ...typo.body, color: colors.textPrimary, flex: 1 },
  action: { fontSize: 15, fontWeight: "600", color: colors.blue },
});
