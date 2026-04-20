import * as React from "react";
import { Heading, Section, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface WelcomeEmailProps {
  locale: Locale;
  firstName: string;
  scanInboxUrl: string;
  unsubscribeUrl: string;
  viewInBrowserUrl?: string;
}

export function subject(locale: Locale, _props?: Partial<WelcomeEmailProps>): string {
  return t(locale, "email.welcome.subject");
}

export default function WelcomeEmail({
  locale,
  firstName,
  scanInboxUrl,
  unsubscribeUrl,
  viewInBrowserUrl,
}: WelcomeEmailProps): React.ReactElement {
  const listItems = [1, 2, 3, 4].map((i) => t(locale, `email.welcome.list_item_${i}`));
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.welcome.preheader")}
      unsubscribeUrl={unsubscribeUrl}
      viewInBrowserUrl={viewInBrowserUrl}
    >
      <Text style={{ fontSize: "16px", margin: "0 0 20px" }}>
        {t(locale, "email.common.greeting_casual", { name: firstName })}
      </Text>

      <Heading style={{ fontSize: "28px", fontWeight: 800, margin: "0 0 16px" }}>
        {t(locale, "email.welcome.hero_title")}
      </Heading>

      <Text style={{ fontSize: "16px", margin: "0 0 16px" }}>{t(locale, "email.welcome.body_p1")}</Text>

      <Section style={{ backgroundColor: "#ecfdf5", borderRadius: "10px", padding: "16px 20px", margin: "20px 0" }}>
        {listItems.map((label) => (
          <Text
            key={label}
            style={{ fontSize: "14px", margin: "6px 0", color: "#064e3b" }}
          >
            ✅ {label}
          </Text>
        ))}
      </Section>

      <Text style={{ fontSize: "14px", color: "#475569", margin: "0 0 20px" }}>
        {t(locale, "email.welcome.body_p2")}
      </Text>

      <Cta href={scanInboxUrl} label={t(locale, "email.welcome.cta_scan")} />

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
