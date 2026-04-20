import * as React from "react";
import { Column, Heading, Row, Section, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface WeeklyReportEmailProps {
  locale: Locale;
  firstName: string;
  blocksCount: number;      // scams blocked this week
  checksCount: number;      // total links checked
  percentile: number;       // 0-100 — "safer than X%"
  fullReportUrl: string;
  unsubscribeUrl: string;
}

export function subject(locale: Locale): string {
  return t(locale, "email.weekly_report.subject");
}

const statCell = {
  backgroundColor: "#f1f5f9",
  borderRadius: "10px",
  padding: "20px 12px",
  textAlign: "center" as const,
};
const statNum = { fontSize: "32px", fontWeight: 800, color: "#0f172a", margin: "0 0 4px", lineHeight: 1 };
const statLabel = { fontSize: "12px", color: "#64748b", margin: 0 };

export default function WeeklyReportEmail({
  locale,
  firstName,
  blocksCount,
  checksCount,
  percentile,
  fullReportUrl,
  unsubscribeUrl,
}: WeeklyReportEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.weekly_report.preheader")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Text style={{ fontSize: "16px", margin: "0 0 8px" }}>
        {t(locale, "email.common.greeting_casual", { name: firstName })}
      </Text>

      <Heading style={{ fontSize: "24px", fontWeight: 800, margin: "0 0 12px" }}>
        {t(locale, "email.weekly_report.title")}
      </Heading>

      <Text style={{ fontSize: "15px", margin: "0 0 20px" }}>
        {t(locale, "email.weekly_report.body_p1")}
      </Text>

      <Row style={{ marginBottom: "16px" }}>
        <Column style={{ width: "50%", paddingRight: "6px" }}>
          <Section style={{ ...statCell, backgroundColor: "#fef2f2" }}>
            <Text style={{ ...statNum, color: "#dc2626" }}>{blocksCount.toLocaleString()}</Text>
            <Text style={statLabel}>{t(locale, "email.weekly_report.stat_blocks_label")}</Text>
          </Section>
        </Column>
        <Column style={{ width: "50%", paddingLeft: "6px" }}>
          <Section style={statCell}>
            <Text style={statNum}>{checksCount.toLocaleString()}</Text>
            <Text style={statLabel}>{t(locale, "email.weekly_report.stat_checks_label")}</Text>
          </Section>
        </Column>
      </Row>

      <Section style={{ backgroundColor: "#ecfdf5", borderRadius: "10px", padding: "14px 20px", margin: "20px 0" }}>
        <Text style={{ fontSize: "14px", color: "#065f46", margin: 0 }}>
          🎯 {t(locale, "email.weekly_report.percentile_body", { pct: percentile })}
        </Text>
      </Section>

      <Cta href={fullReportUrl} label={t(locale, "email.weekly_report.cta_view_full")} />

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
