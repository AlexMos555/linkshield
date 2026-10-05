import { useTranslation } from "react-i18next";

import type { ProtectionMode } from "../../lib/entitlement";
import type { BillingView } from "../../utils/billing-view";
import { calendarDate } from "../../utils/relative-time";
import { BigButton, Card, CardBody, CardTitle, type Tone } from "./Ui";

interface BillingCardProps {
  view: BillingView;
  mode: ProtectionMode;
  onOpen: () => void;
}

/**
 * The home screen's one line about the subscription — only when there is
 * something a person should know: the trial's days, a failed charge, a lapse,
 * an SMS still to answer. An active subscription says nothing here: the
 * hero already says "protected", and a second green card is noise.
 */
export function BillingCard({ view, mode, onOpen }: BillingCardProps) {
  const { t, i18n } = useTranslation();
  const copy = cardCopy(view, mode, t, i18n.language);
  if (!copy) return null;
  return (
    <Card tone={copy.tone}>
      <CardTitle tone={copy.tone}>{copy.title}</CardTitle>
      <CardBody>{copy.body}</CardBody>
      <BigButton kind={copy.tone === "neutral" ? "secondary" : "primary"} label={t("mobile.billing.card_open")} onPress={onOpen} />
    </Card>
  );
}

type Copy = { tone: Tone; title: string; body: string };

function cardCopy(view: BillingView, mode: ProtectionMode, t: (k: string, o?: Record<string, unknown>) => string, lang: string): Copy | null {
  switch (view.kind) {
    case "trial":
      return {
        tone: view.ending ? "amber" : "neutral",
        title: view.daysLeft > 0 ? t("mobile.billing.trial_days_left", { count: view.daysLeft }) : t("mobile.billing.trial_ends_today"),
        body: t(view.ending ? "mobile.billing.trial_ending_hint" : "mobile.billing.trial_body"),
      };
    case "grace":
      return { tone: "amber", title: t("mobile.billing.grace_title"), body: t("mobile.billing.grace_body", { count: view.daysLeft }) };
    case "lapsed":
      return {
        tone: mode === "off" ? "danger" : "amber",
        title: t(view.after === "subscription" ? "mobile.billing.lapsed_sub_title" : "mobile.billing.lapsed_trial_title"),
        body: t(mode === "off" ? "mobile.billing.lapsed_off_body" : "mobile.billing.lapsed_basic_body"),
      };
    case "pending":
      return { tone: "neutral", title: t("mobile.billing.pending_title"), body: t("mobile.billing.pending_body") };
    case "cancelled":
      return {
        tone: "neutral",
        title: t("mobile.billing.cancelled_title"),
        body: view.periodEnd
          ? t("mobile.billing.cancelled_body", { date: calendarDate(view.periodEnd * 1000, lang) })
          : t("mobile.billing.cancelled_body_no_date"),
      };
    default:
      return null;
  }
}
