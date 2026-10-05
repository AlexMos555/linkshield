/**
 * The plans (billing plan §2.1): what the server lists at `/plans`, nothing
 * hard-coded — a price change is a setting there, not a release here. Each
 * card says the price, how many phones, and what is included in plain words.
 */
import { useEffect, useState } from "react";
import { Text, StyleSheet, View } from "react-native";
import { useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Card, CardTitle, CheckLine, Hint, Screen, Spinner } from "../../src/components/billing/Ui";
import { useBilling } from "../../src/hooks/useBilling";
import type { PlanInfo } from "../../src/lib/billing-api";
import { billing } from "../../src/services/billing";
import { planLabel } from "../../src/utils/billing-copy";
import { colors, space } from "../../src/utils/theme";

const FEATURE_KEYS = [
  "mobile.billing.feature_block",
  "mobile.billing.feature_fresh",
  "mobile.billing.feature_links",
  "mobile.billing.feature_family",
  "mobile.billing.feature_cancel",
] as const;

function seatsKey(seats: number): string {
  if (seats <= 1) return "mobile.billing.plan_seats_solo";
  if (seats <= 3) return "mobile.billing.plan_seats_3";
  return "mobile.billing.plan_seats_5";
}

export default function PlansScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const b = useBilling();
  const [loaded, setLoaded] = useState(b.plans !== null);

  useEffect(() => {
    let alive = true;
    void billing.loadPlans().finally(() => {
      if (alive) setLoaded(true);
    });
    return () => {
      alive = false;
    };
  }, []);

  const plans: PlanInfo[] = [...(b.plans?.plans ?? [])].sort((a, c) => a.seats - c.seats);
  const currentPlan = b.view.kind === "active" ? b.view.plan : null;

  if (!loaded) return <Screen><Spinner /></Screen>;

  return (
    <Screen>
      <Text style={s.subtitle}>{t("mobile.billing.plans_subtitle")}</Text>
      {plans.length === 0 && (
        <>
          <Hint icon="alert-circle-outline">{t("mobile.billing.plans_failed")}</Hint>
          <BigButton label={t("mobile.billing.retry")} onPress={() => { setLoaded(false); void billing.loadPlans().finally(() => setLoaded(true)); }} />
        </>
      )}
      {plans.map((plan) => (
        <Card key={plan.code} tone={plan.code === currentPlan ? "green" : "neutral"}>
          <CardTitle>{planLabel(t, plan.code)}</CardTitle>
          <Text style={s.price}>{t("mobile.billing.plan_price", { price: plan.price_rub })}</Text>
          <Text style={s.seats}>{t(seatsKey(plan.seats))}</Text>
          <Text style={s.includes}>{t("mobile.billing.plan_includes")}</Text>
          <View style={s.features}>
            {FEATURE_KEYS.filter((k) => plan.seats > 1 || k !== "mobile.billing.feature_family").map((k) => (
              <CheckLine key={k}>{t(k)}</CheckLine>
            ))}
          </View>
          {plan.code === currentPlan ? (
            <Text style={s.current}>{t("mobile.billing.current_plan")}</Text>
          ) : (
            <BigButton
              label={t("mobile.billing.choose")}
              a11yLabel={`${t("mobile.billing.choose")}: ${planLabel(t, plan.code)}, ${t("mobile.billing.plan_price", { price: plan.price_rub })}`}
              onPress={() => router.push({ pathname: "/subscription/checkout", params: { plan: plan.code } })}
            />
          )}
        </Card>
      ))}
      {b.view.kind === "no_trial" && b.plans && <Hint>{t("mobile.billing.trial_note", { days: b.plans.trialDays })}</Hint>}
    </Screen>
  );
}

const s = StyleSheet.create({
  subtitle: { fontSize: 17, lineHeight: 24, color: colors.textSecondary },
  price: { fontSize: 30, lineHeight: 36, fontWeight: "800", color: colors.textPrimary },
  seats: { fontSize: 17, color: colors.textSecondary },
  includes: { fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.6, color: colors.textMuted, marginTop: space.sm },
  features: { gap: 6, marginBottom: space.sm },
  current: { fontSize: 17, fontWeight: "600", color: colors.green, textAlign: "center", paddingVertical: space.md },
});
