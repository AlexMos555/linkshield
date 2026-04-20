import * as React from "react";
import { Heading, Text } from "@react-email/components";
import { Cta, Shell } from "../components/Shell.js";
import { t, type Locale } from "../helpers/i18n.js";

export interface FamilyInviteEmailProps {
  locale: Locale;
  inviterName: string;
  acceptUrl: string;
  unsubscribeUrl: string;
}

export function subject(locale: Locale, props: Pick<FamilyInviteEmailProps, "inviterName">): string {
  return t(locale, "email.family_invite.subject", { name: props.inviterName });
}

export default function FamilyInviteEmail({
  locale,
  inviterName,
  acceptUrl,
  unsubscribeUrl,
}: FamilyInviteEmailProps): React.ReactElement {
  return (
    <Shell
      locale={locale}
      preheader={t(locale, "email.family_invite.preheader")}
      unsubscribeUrl={unsubscribeUrl}
    >
      <Heading style={{ fontSize: "24px", fontWeight: 800, margin: "0 0 16px" }}>
        {t(locale, "email.family_invite.title")}
      </Heading>

      <Text style={{ fontSize: "15px", margin: "0 0 20px" }}>
        {t(locale, "email.family_invite.body_p1", { name: inviterName })}
      </Text>

      <Cta href={acceptUrl} label={t(locale, "email.family_invite.cta_accept")} />

      <Text style={{ fontSize: "13px", color: "#475569", margin: "24px 0 0", lineHeight: 1.6 }}>
        🔒 {t(locale, "email.family_invite.body_p2_security")}
      </Text>

      <Text style={{ fontSize: "14px", margin: "24px 0 0" }}>{t(locale, "email.common.signature")}</Text>
    </Shell>
  );
}
