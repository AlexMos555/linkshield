/**
 * @linkshield/email-templates — public entry point.
 *
 * Registry of all transactional email templates.
 * Backend code uses `renderTemplate(templateKey, locale, props)` to produce
 * HTML + plaintext + subject, provider-agnostic.
 */
import WelcomeEmail, {
  subject as welcomeSubject,
  type WelcomeEmailProps,
} from "./templates/welcome.js";
import ReceiptEmail, {
  subject as receiptSubject,
  type ReceiptEmailProps,
} from "./templates/receipt.js";
import WeeklyReportEmail, {
  subject as weeklyReportSubject,
  type WeeklyReportEmailProps,
} from "./templates/weekly-report.js";
import FamilyInviteEmail, {
  subject as familyInviteSubject,
  type FamilyInviteEmailProps,
} from "./templates/family-invite.js";
import BreachAlertEmail, {
  subject as breachAlertSubject,
  type BreachAlertEmailProps,
} from "./templates/breach-alert.js";
import SubscriptionCancelEmail, {
  subject as subscriptionCancelSubject,
  type SubscriptionCancelEmailProps,
} from "./templates/subscription-cancel.js";
import GrannyModeInviteEmail, {
  subject as grannyModeInviteSubject,
  type GrannyModeInviteEmailProps,
} from "./templates/granny-mode-invite.js";

export type TemplateKey =
  | "welcome"
  | "receipt"
  | "weekly_report"
  | "family_invite"
  | "breach_alert"
  | "subscription_cancel"
  | "granny_mode_invite";

export interface TemplateMeta<P> {
  component: (props: P) => React.ReactElement;
  subject: (locale: import("./helpers/i18n.js").Locale, props: P) => string;
}

export const TEMPLATES = {
  welcome: {
    component: WelcomeEmail,
    subject: (locale, _props: WelcomeEmailProps) => welcomeSubject(locale),
  },
  receipt: {
    component: ReceiptEmail,
    subject: (locale, _props: ReceiptEmailProps) => receiptSubject(locale),
  },
  weekly_report: {
    component: WeeklyReportEmail,
    subject: (locale, _props: WeeklyReportEmailProps) => weeklyReportSubject(locale),
  },
  family_invite: {
    component: FamilyInviteEmail,
    subject: (locale, props: FamilyInviteEmailProps) => familyInviteSubject(locale, props),
  },
  breach_alert: {
    component: BreachAlertEmail,
    subject: (locale, _props: BreachAlertEmailProps) => breachAlertSubject(locale),
  },
  subscription_cancel: {
    component: SubscriptionCancelEmail,
    subject: (locale, _props: SubscriptionCancelEmailProps) => subscriptionCancelSubject(locale),
  },
  granny_mode_invite: {
    component: GrannyModeInviteEmail,
    subject: (locale, props: GrannyModeInviteEmailProps) => grannyModeInviteSubject(locale, props),
  },
} as const satisfies Record<TemplateKey, TemplateMeta<any>>;

export type {
  WelcomeEmailProps,
  ReceiptEmailProps,
  WeeklyReportEmailProps,
  FamilyInviteEmailProps,
  BreachAlertEmailProps,
  SubscriptionCancelEmailProps,
  GrannyModeInviteEmailProps,
};
export { SUPPORTED_LOCALES, type Locale } from "./helpers/i18n.js";

// Re-export individual templates so consumers can import directly if needed
export {
  WelcomeEmail,
  ReceiptEmail,
  WeeklyReportEmail,
  FamilyInviteEmail,
  BreachAlertEmail,
  SubscriptionCancelEmail,
  GrannyModeInviteEmail,
};
