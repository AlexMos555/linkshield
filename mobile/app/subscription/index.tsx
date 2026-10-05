/**
 * The subscription hub (billing plan §2.5): one honest card about where this
 * phone stands — trial with its days, active with the next charge, a failed
 * charge with its window, cancelled with its end date, lapsed with what
 * protection is left — and under it only the buttons that apply.
 *
 * Cancel is one tap plus one confirmation, and the confirmation says plainly
 * when protection changes and into what (basic or off), with the date.
 */
import { useState } from "react";
import { Alert, Text, StyleSheet } from "react-native";
import { Redirect, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Card, CardBody, CardTitle, Hint, Screen, Spinner, type Tone } from "../../src/components/billing/Ui";
import { useBilling } from "../../src/hooks/useBilling";
import { billing, type BillingState } from "../../src/services/billing";
import { planLabel, errorCopyKey } from "../../src/utils/billing-copy";
import { type BillingView, canCancel, canManageSeats, cancelOutcome, offersPlans } from "../../src/utils/billing-view";
import { calendarDate } from "../../src/utils/relative-time";
import { colors } from "../../src/utils/theme";

export default function SubscriptionScreen() {
  const router = useRouter();
  const { t, i18n } = useTranslation();
  const b = useBilling();
  const [cancelling, setCancelling] = useState(false);

  if (!b.enabled || b.view.kind === "hidden") return <Redirect href="/(tabs)" />;
  if (!b.ready) return <Screen><Spinner /></Screen>;
  const v = b.view;
  const date = (sec: number) => calendarDate(sec * 1000, i18n.language);

  function confirmCancel() {
    const outcome = cancelOutcome(v, b.lapsePolicy);
    const key = outcome.then === "basic"
      ? (outcome.protectedUntil ? "mobile.billing.cancel_confirm_basic" : "mobile.billing.cancel_confirm_basic_no_date")
      : (outcome.protectedUntil ? "mobile.billing.cancel_confirm_off" : "mobile.billing.cancel_confirm_off_no_date");
    Alert.alert(
      t("mobile.billing.cancel_confirm_title"),
      t(key, { date: outcome.protectedUntil ? date(outcome.protectedUntil) : "" }),
      [
        { text: t("mobile.billing.cancel_keep"), style: "cancel" },
        { text: t("mobile.billing.cancel_do"), style: "destructive", onPress: () => void doCancel() },
      ],
      { cancelable: true },
    );
  }

  async function doCancel() {
    setCancelling(true);
    const result = await billing.cancel();
    setCancelling(false);
    if (result.data) Alert.alert(t("mobile.billing.cancel_done_title"), t("mobile.billing.cancel_done_body"));
    else Alert.alert(t("mobile.billing.cancel_failed_title"), t("mobile.billing.cancel_failed_body"));
  }

  const errorKey = b.nativeApplied === false ? "mobile.billing.native_missing" : errorCopyKey(b.error);

  return (
    <Screen>
      <StatusCard view={v} state={b} date={date} />
      {errorKey && <Hint icon="alert-circle-outline">{t(errorKey)}</Hint>}
      {!errorKey && b.error && <Hint icon="alert-circle-outline">{t("mobile.billing.error_generic", { code: b.error })}</Hint>}

      {v.kind === "unknown" && <BigButton label={t("mobile.billing.retry")} onPress={() => void billing.refresh()} busy={b.busy} />}
      {v.kind === "pending" && (
        <BigButton label={t("mobile.billing.pending_open")} onPress={() => router.push({ pathname: "/subscription/sms", params: { phone: "", provider: "" } })} />
      )}
      {offersPlans(v) && <BigButton label={t("mobile.billing.choose_plan")} onPress={() => router.push("/subscription/plans")} icon="card-outline" />}
      {offersPlans(v) && <BigButton kind="secondary" label={t("mobile.billing.join_title")} onPress={() => router.push("/subscription/join")} icon="people-outline" />}
      {canManageSeats(v) && <BigButton kind="secondary" label={t("mobile.billing.add_phone")} onPress={() => router.push("/subscription/add-phone")} icon="person-add-outline" />}
      {canManageSeats(v) && <BigButton kind="secondary" label={t("mobile.billing.devices")} onPress={() => router.push("/subscription/devices")} icon="phone-portrait-outline" />}
      {canCancel(v) && <BigButton kind="danger" label={t("mobile.billing.cancel")} onPress={confirmCancel} busy={cancelling} />}
    </Screen>
  );
}

function StatusCard({ view, state, date }: { view: BillingView; state: BillingState; date: (sec: number) => string }) {
  const { t } = useTranslation();
  const copy = statusCopy(view, state, t, date);
  return (
    <Card tone={copy.tone}>
      <CardTitle tone={copy.tone}>{copy.title}</CardTitle>
      {copy.lines.map((line) => <CardBody key={line}>{line}</CardBody>)}
      {copy.hint ? <Hint>{copy.hint}</Hint> : null}
      {view.kind === "unknown" && <Text style={s.quiet}>{t("mobile.billing.loading")}</Text>}
    </Card>
  );
}

type StatusCopy = { tone: Tone; title: string; lines: string[]; hint?: string };

function statusCopy(
  view: BillingView, state: BillingState,
  t: (k: string, o?: Record<string, unknown>) => string, date: (sec: number) => string,
): StatusCopy {
  const thenKey = state.lapsePolicy === "basic" ? "mobile.billing.grace_then_basic" : "mobile.billing.grace_then_off";
  switch (view.kind) {
    case "unknown":
      return { tone: "neutral", title: t("mobile.billing.unknown_title"), lines: [t("mobile.billing.unknown_body")] };
    case "no_trial":
      return { tone: "neutral", title: t("mobile.billing.no_trial_title"), lines: [t("mobile.billing.no_trial_body", { days: state.plans?.trialDays ?? 14 })] };
    case "trial":
      return {
        tone: view.ending ? "amber" : "green",
        title: view.daysLeft > 0 ? t("mobile.billing.trial_days_left", { count: view.daysLeft }) : t("mobile.billing.trial_ends_today"),
        lines: [t("mobile.billing.trial_body")],
        hint: view.ending ? t("mobile.billing.trial_ending_hint") : undefined,
      };
    case "active": {
      const lines = [t("mobile.billing.active_plan", { plan: planLabel(t, view.plan) })];
      if (view.source === "promo") lines.push(t("mobile.billing.promo_body"));
      else if (!view.isPayer) lines.push(t("mobile.billing.active_member_body"));
      else {
        if (view.nextChargeAt && view.priceRub !== null) lines.push(t("mobile.billing.active_next_charge", { date: date(view.nextChargeAt), price: view.priceRub }));
        else if (view.priceRub !== null) lines.push(t("mobile.billing.active_price_only", { price: view.priceRub }));
        if (view.seatsTotal !== null) lines.push(t("mobile.billing.active_seats", { used: view.seatsUsed ?? 0, total: view.seatsTotal }));
      }
      return { tone: "green", title: t("mobile.billing.active_title"), lines };
    }
    case "grace":
      return {
        tone: "amber", title: t("mobile.billing.grace_title"),
        lines: [t("mobile.billing.grace_body", { count: view.daysLeft })],
        hint: t(thenKey, { date: date(view.graceUntil) }),
      };
    case "cancelled":
      return {
        tone: "neutral", title: t("mobile.billing.cancelled_title"),
        lines: [view.periodEnd ? t("mobile.billing.cancelled_body", { date: date(view.periodEnd) }) : t("mobile.billing.cancelled_body_no_date")],
        hint: t("mobile.billing.resume_hint"),
      };
    case "pending":
      return { tone: "neutral", title: t("mobile.billing.pending_title"), lines: [t("mobile.billing.pending_body")] };
    case "legacy":
      return { tone: "green", title: t("mobile.billing.legacy_title"), lines: [t("mobile.billing.legacy_body")] };
    case "lapsed":
      return {
        tone: view.mode === "off" ? "danger" : "amber",
        title: t(view.after === "subscription" ? "mobile.billing.lapsed_sub_title" : "mobile.billing.lapsed_trial_title"),
        lines: [t(view.mode === "off" ? "mobile.billing.lapsed_off_body" : "mobile.billing.lapsed_basic_body")],
      };
    default:
      return { tone: "neutral", title: t("mobile.billing.title"), lines: [] };
  }
}

const s = StyleSheet.create({
  quiet: { fontSize: 15, color: colors.textMuted },
});
