import * as React from "react";
import { Heading, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface SubscriptionCancelEmailProps {
  locale: Locale;
  firstName: string;
  activeUntil: string;       // localized date
  reactivateUrl: string;
  unsubscribeUrl: string;
}

export function subject(locale: Locale): string {
  return t(locale, "email.subscription_cancel.subject");
}

export default function SubscriptionCancelEmail({
  locale,
  firstName,
  activeUntil,
  reactivateUrl,
  unsubscribeUrl,
}: SubscriptionCancelEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.subscription_cancel.body_p1")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Text style={{ fontSize: "16px", margin: "0 0 8px" }}>
        {t(locale, "email.common.greeting_casual", { name: firstName })}
      </Text>

      <Heading style={{ fontSize: "24px", fontWeight: 800, margin: "0 0 16px" }}>
        {t(locale, "email.subscription_cancel.title")}
      </Heading>

      <Text style={{ fontSize: "15px", margin: "0 0 16px" }}>
        {t(locale, "email.subscription_cancel.body_p1")}
      </Text>

      <Text style={{ fontSize: "14px", color: "#475569", margin: "0 0 16px" }}>
        {t(locale, "email.subscription_cancel.body_p2_keep_free")}
      </Text>

      <Text style={{ fontSize: "14px", color: "#0f172a", backgroundColor: "#ecfdf5", padding: "12px 16px", borderRadius: "8px", margin: "20px 0" }}>
        📅 {t(locale, "email.subscription_cancel.date_label", { date: activeUntil })}
      </Text>

      <Cta href={reactivateUrl} label={t(locale, "email.subscription_cancel.cta_reactivate")} />

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
