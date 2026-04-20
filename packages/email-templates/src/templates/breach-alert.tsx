import * as React from "react";
import { Heading, Section, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface BreachAlertEmailProps {
  locale: Locale;
  firstName: string;
  affectedSite: string;  // e.g. "Acme Cloud (data-breach-date: 2026-03-15)"
  changePasswordUrl: string;
  unsubscribeUrl: string;
}

export function subject(locale: Locale): string {
  return t(locale, "email.breach_alert.subject");
}

export default function BreachAlertEmail({
  locale,
  firstName,
  affectedSite,
  changePasswordUrl,
  unsubscribeUrl,
}: BreachAlertEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.breach_alert.preheader")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Section style={{ backgroundColor: "#fef2f2", borderRadius: "10px", padding: "20px", margin: "0 0 24px", borderLeft: "4px solid #dc2626" }}>
        <Text style={{ fontSize: "14px", color: "#991b1b", margin: 0, fontWeight: 600 }}>
          ⚠️ {t(locale, "email.breach_alert.title")}
        </Text>
      </Section>

      <Text style={{ fontSize: "16px", margin: "0 0 12px" }}>
        {t(locale, "email.common.greeting_formal", { name: firstName })}
      </Text>

      <Text style={{ fontSize: "15px", margin: "0 0 12px" }}>{t(locale, "email.breach_alert.body_p1")}</Text>

      <Text style={{ fontSize: "14px", color: "#475569", fontFamily: "ui-monospace, Menlo, monospace", backgroundColor: "#f1f5f9", padding: "12px", borderRadius: "6px", margin: "0 0 20px" }}>
        {affectedSite}
      </Text>

      <Text style={{ fontSize: "15px", margin: "0 0 20px" }}>
        {t(locale, "email.breach_alert.body_p2_recommendation")}
      </Text>

      <Cta href={changePasswordUrl} label={t(locale, "email.breach_alert.cta_change_password")} />

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
