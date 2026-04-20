import * as React from "react";
import { Heading, Section, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

/**
 * Sent to the family member who was added to Granny Mode by a family admin.
 * Language uses extra-simple vocabulary — recipient is likely 60+.
 * We intentionally NEVER use "phishing" / "scam" terminology in greeting —
 * words used are literal: "fake bank website", "delivery notice", "STOP sign".
 */
export interface GrannyModeInviteEmailProps {
  locale: Locale;
  familyAdminName: string;  // "your grandson Alex" or "твой внук Саша"
  setupUrl: string;
  unsubscribeUrl: string;
}

export function subject(
  locale: Locale,
  props: Pick<GrannyModeInviteEmailProps, "familyAdminName">,
): string {
  return t(locale, "email.granny_mode_invite.subject", { name: props.familyAdminName });
}

export default function GrannyModeInviteEmail({
  locale,
  familyAdminName,
  setupUrl,
  unsubscribeUrl,
}: GrannyModeInviteEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.granny_mode_invite.preheader")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Heading style={{ fontSize: "26px", fontWeight: 800, margin: "0 0 20px", lineHeight: 1.3 }}>
        {t(locale, "email.granny_mode_invite.title")}
      </Heading>

      <Text style={{ fontSize: "17px", margin: "0 0 20px", lineHeight: 1.6 }}>
        {t(locale, "email.granny_mode_invite.body_p1_to_grandchild", { name: familyAdminName })}
      </Text>

      <Section style={{ backgroundColor: "#fef2f2", borderRadius: "10px", padding: "16px 20px", margin: "20px 0", borderLeft: "4px solid #dc2626" }}>
        <Text style={{ fontSize: "15px", color: "#7f1d1d", margin: 0, lineHeight: 1.6 }}>
          {t(locale, "email.granny_mode_invite.body_p2_what_it_does")}
        </Text>
      </Section>

      <Cta href={setupUrl} label={t(locale, "email.granny_mode_invite.cta_setup")} />

      <Text style={{ fontSize: "14px", color: "#475569", margin: "24px 0 0", lineHeight: 1.6 }}>
        💬 {t(locale, "email.granny_mode_invite.reassurance", { name: familyAdminName })}
      </Text>

      <Text style={{ fontSize: "14px", margin: "20px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
