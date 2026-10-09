/**
 * The plans as the store (Google Play, App Store) sells them — monthly and yearly, each with the
 * store's own price in the person's currency (never a price typed into the
 * app). One is chosen; the paywall's button buys it. Shown only in the
 * store builds (app/paywall.tsx).
 */
import { View, Text, StyleSheet, Pressable, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius } from "../../utils/theme";
import { BILLING_STORE, type StorePlan, type StorePlansResult } from "../../services/store-billing";
import { storeCopyKeys, type PlanPeriod } from "../../utils/store-billing";

export type StorePlansState = { kind: "loading" } | StorePlansResult;

export function StorePlans({ state, selected, onSelect, onRetry, devices }: {
  state: StorePlansState;
  selected: PlanPeriod;
  onSelect: (period: PlanPeriod) => void;
  onRetry: () => void;
  devices: number;
}) {
  const { t } = useTranslation();
  const copy = storeCopyKeys(BILLING_STORE);

  if (state.kind === "loading") {
    return (
      <View style={s.status} accessibilityLiveRegion="polite">
        <ActivityIndicator color={colors.textSecondary} />
        <Text style={s.statusText}>{t(copy.pricesLoading)}</Text>
      </View>
    );
  }
  if (state.kind !== "ok") {
    // "unavailable" never reaches here (the paywall says "coming soon" instead).
    const body = state.kind === "empty" ? t(copy.pricesEmpty) : t(copy.pricesFailed);
    return (
      <View style={s.status} accessibilityLiveRegion="polite">
        <Text style={s.statusText}>{body}</Text>
        {state.kind === "error" && (
          <Pressable onPress={onRetry} style={s.retry} accessibilityRole="button">
            <Text style={s.retryLabel}>{t("mobile.paywall.retry")}</Text>
          </Pressable>
        )}
      </View>
    );
  }

  return (
    <View style={s.list} accessibilityRole="radiogroup">
      {state.plans.map((plan) => (
        <PlanRow key={plan.period} plan={plan} on={plan.period === selected} onPress={() => onSelect(plan.period)} />
      ))}
      <Text style={s.devices}>{t("mobile.paywall.devices_note", { n: devices })}</Text>
    </View>
  );
}

function PlanRow({ plan, on, onPress }: { plan: StorePlan; on: boolean; onPress: () => void }) {
  const { t } = useTranslation();
  const name = t(plan.period === "year" ? "mobile.paywall.plan_year" : "mobile.paywall.plan_month");
  const price = t(plan.period === "year" ? "mobile.paywall.per_year" : "mobile.paywall.per_month", {
    price: plan.priceString,
  });
  const save = plan.savePercent !== null ? t("mobile.paywall.save_percent", { n: plan.savePercent }) : null;
  return (
    <Pressable
      onPress={onPress}
      style={[s.row, on && s.rowOn]}
      accessibilityRole="radio"
      accessibilityState={{ selected: on, checked: on }}
      accessibilityLabel={[name, price, save].filter(Boolean).join(". ")}
    >
      <Ionicons name={on ? "radio-button-on" : "radio-button-off"} size={24} color={on ? colors.green : colors.textDisabled} />
      <View style={s.rowText}>
        <Text style={s.name}>{name}</Text>
        <Text style={s.price}>{price}</Text>
      </View>
      {save && <Text style={s.save}>{save}</Text>}
    </Pressable>
  );
}

const s = StyleSheet.create({
  status: { alignItems: "center", gap: space.sm, marginTop: space.xxl, paddingHorizontal: space.md },
  statusText: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, textAlign: "center" },
  retry: { minHeight: 44, justifyContent: "center", paddingHorizontal: space.lg },
  retryLabel: { fontSize: 15, fontWeight: "600", color: colors.blue },

  list: { marginTop: space.xxl, gap: space.sm },
  row: {
    flexDirection: "row", alignItems: "center", gap: space.md, minHeight: 64,
    paddingHorizontal: space.lg, paddingVertical: space.md,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke, borderRadius: radius.card,
  },
  rowOn: { borderColor: colors.green, backgroundColor: colors.greenWash },
  rowText: { flex: 1 },
  name: { fontSize: 17, lineHeight: 22, fontWeight: "700", color: colors.textPrimary },
  price: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: 2 },
  save: {
    fontSize: 13, lineHeight: 18, fontWeight: "700", color: "#0B1220", backgroundColor: colors.green,
    borderRadius: radius.pill, overflow: "hidden", paddingHorizontal: space.sm, paddingVertical: 4,
  },
  devices: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, textAlign: "center", marginTop: space.xs },
});
