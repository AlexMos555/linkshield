import * as React from "react";
import { Column, Heading, Row, Section, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface ReceiptEmailProps {
  locale: Locale;
  firstName: string;
  planLabel: string;        // localized: "Personal (Monthly)" etc. — passed in from backend
  amountFormatted: string;  // e.g. "$5.99" — backend formats using Intl.NumberFormat
  nextBillingDate: string;  // localized date
  invoiceUrl: string;
  unsubscribeUrl: string;
}

export function subject(locale: Locale): string {
  return t(locale, "email.receipt.subject");
}

const rowStyle = {
  padding: "10px 0",
  borderBottom: "1px solid #e2e8f0",
};
const labelStyle = { fontSize: "13px", color: "#64748b", textTransform: "uppercase" as const, letterSpacing: "0.05em" };
const valueStyle = { fontSize: "16px", fontWeight: 600, color: "#0f172a", textAlign: "right" as const };

export default function ReceiptEmail({
  locale,
  firstName,
  planLabel,
  amountFormatted,
  nextBillingDate,
  invoiceUrl,
  unsubscribeUrl,
}: ReceiptEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.receipt.body_p1")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Text style={{ fontSize: "16px", margin: "0 0 8px" }}>
        {t(locale, "email.common.greeting_formal", { name: firstName })}
      </Text>

      <Heading style={{ fontSize: "24px", fontWeight: 800, margin: "0 0 16px" }}>
        {t(locale, "email.receipt.title")}
      </Heading>

      <Text style={{ fontSize: "15px", margin: "0 0 20px" }}>{t(locale, "email.receipt.body_p1")}</Text>

      <Section style={{ backgroundColor: "#f8fafc", borderRadius: "10px", padding: "16px 20px", margin: "16px 0" }}>
        <Row style={rowStyle}>
          <Column style={labelStyle}>{t(locale, "email.receipt.plan_label")}</Column>
          <Column style={valueStyle}>{planLabel}</Column>
        </Row>
        <Row style={rowStyle}>
          <Column style={labelStyle}>{t(locale, "email.receipt.amount_label")}</Column>
          <Column style={valueStyle}>{amountFormatted}</Column>
        </Row>
      </Section>

      <Text style={{ fontSize: "14px", color: "#475569", margin: "0 0 20px" }}>
        {t(locale, "email.receipt.next_billing", { date: nextBillingDate })}
      </Text>

      <Cta href={invoiceUrl} label={t(locale, "email.receipt.invoice_link")} />

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
