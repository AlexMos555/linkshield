/**
 * What the app offers on each platform, pure — no React Native — so
 * mobile/scripts/test-platform-gating.mjs runs it under plain node.
 * docs/IOS.md, docs/MOBILE_AUTO_PROTECTION.md.
 *
 * Android protects through features that exist only there: the "Every app"
 * DNS shield (a local VPN), the keep-protection-on list (battery, the phone
 * maker's manager, Always-on VPN), link checking (Cleanway as the default
 * link handler), the call stop screen, the on-device message check, the
 * self-update banner of the site APK and Android's permission prompts. None
 * of them can exist on an iPhone, so none of them is shown there — not even
 * greyed out.
 *
 * The iPhone app protects through three iOS-native layers instead, built in
 * separate steps: a Safari Web Extension, an SMS filter
 * (ILMessageFilterExtension) and DNS protection (NEDNSSettingsManager with
 * encrypted DNS). Until a layer ships it is listed as "coming soon" — said
 * plainly, never as a placebo switch. Each later step reports its layer's
 * status through IosLayerAvailability; this file and the home card need no
 * other change.
 */

/** Android-only protection (shield, keep-alive, link guard, call guard, Private DNS, permission steps). */
export function androidProtectionShown(os: string): boolean {
  return os === "android";
}

/** Settings → "Link checking" (default link handler): Android only. */
export function linkGuardSettingShown(os: string): boolean {
  return os === "android";
}

/** The iPhone protection card on the home screen. */
export function iosProtectionShown(os: string): boolean {
  return os === "ios";
}

// ── The iPhone's protection layers ────────────────────────────────────

export type IosLayerId = "safari" | "sms_filter" | "dns";

/**
 *   coming — not in this build yet ("Coming soon");
 *   setup  — built, waiting for the person (the card offers "Set up");
 *   on     — set up and working, as far as iOS lets the app know.
 */
export type IosLayerStatus = "coming" | "setup" | "on";

/** What the later steps report; a layer they do not report is "coming". */
export type IosLayerAvailability = Partial<Record<IosLayerId, IosLayerStatus>>;

export interface IosLayer {
  id: IosLayerId;
  titleKey: string;
  lineKey: string;
  status: IosLayerStatus;
}

/** A layer as listed; `readyLineKey` replaces the line once the layer is no longer "coming". */
type IosLayerDef = Omit<IosLayer, "status"> & { readyLineKey?: string };

// Literal keys, so scripts/check-mobile-i18n.py can see every one. The order
// is the order on screen: the one people meet first (Safari) on top.
const IOS_LAYERS: ReadonlyArray<IosLayerDef> = [
  { id: "safari", titleKey: "mobile.ios.safari_title", lineKey: "mobile.ios.safari_line" },
  { id: "sms_filter", titleKey: "mobile.ios.sms_title", lineKey: "mobile.ios.sms_line", readyLineKey: "mobile.ios_sms.line_ready" },
  { id: "dns", titleKey: "mobile.ios.dns_title", lineKey: "mobile.ios.dns_line" },
];

const STATUSES: ReadonlySet<string> = new Set(["coming", "setup", "on"]);

export function iosProtectionLayers(availability: IosLayerAvailability = {}): IosLayer[] {
  return IOS_LAYERS.map(({ readyLineKey, ...layer }) => {
    const reported = availability[layer.id];
    const status: IosLayerStatus = reported && STATUSES.has(reported) ? reported : "coming";
    return { ...layer, lineKey: status !== "coming" && readyLineKey ? readyLineKey : layer.lineKey, status };
  });
}

// ── The scam-text filter (ILMessageFilterExtension) ───────────────────

/**
 * The filter's layer status: "setup" whenever this build carries the
 * extension, and never "on". Apple gives an app no way to know whether the
 * person turned the filter on (Settings → Apps → Messages → Unknown & Spam →
 * SMS Filtering), and a filter extension cannot write anything back; a row
 * that turned green on a guess would be the placebo this card exists to
 * avoid. "coming" on a build without the extension.
 */
export function smsFilterLayerStatus(installed: boolean): IosLayerStatus {
  return installed ? "setup" : "coming";
}

/**
 * Ask the server's version endpoint at all: always on Android (update nudge,
 * message-check switches); on an iPhone only when its build carries the
 * filter, which needs the same switches (the model's kill switch). The iPhone
 * never shows an update decision from it.
 */
export function remoteConfigFetched(os: string, smsFilterInstalled: boolean): boolean {
  return os === "android" || (os === "ios" && smsFilterInstalled);
}

/** The setup sheet, in order: where the switch is, then what it does and what it never does. */
export const SMS_FILTER_SETUP = {
  titleKey: "mobile.ios_sms.sheet_title",
  leadKey: "mobile.ios_sms.sheet_lead",
  stepKeys: [
    "mobile.ios_sms.step_settings",
    "mobile.ios_sms.step_messages",
    "mobile.ios_sms.step_filtering",
    "mobile.ios_sms.step_choose",
  ],
  olderKey: "mobile.ios_sms.older_ios",
  noteKeys: ["mobile.ios_sms.note_what", "mobile.ios_sms.note_privacy", "mobile.ios_sms.note_limits"],
  openSettingsKey: "mobile.ios_sms.open_settings",
  doneKey: "mobile.ios_sms.done",
} as const;

// ── Copy that differs by platform ─────────────────────────────────────

export interface OnboardingSlide {
  titleKey: string;
  descKey: string;
}

/**
 * The three first-launch slides. The third one is about automatic
 * protection, which differs entirely: Android sets up the "Every app"
 * shield; the iPhone gets its layers in updates.
 */
export function onboardingSlides(os: string): OnboardingSlide[] {
  return [
    { titleKey: "mobile.onboarding.s1_title", descKey: "mobile.onboarding.s1_desc" },
    { titleKey: "mobile.onboarding.s2_title", descKey: "mobile.onboarding.s2_desc" },
    os === "ios"
      ? { titleKey: "mobile.onboarding.s3_title_ios", descKey: "mobile.onboarding.s3_desc_ios" }
      : { titleKey: "mobile.onboarding.s3_title", descKey: "mobile.onboarding.s3_desc" },
  ];
}

/** "How to share": iOS names the share extension and where to switch it on. */
export function shareHowToKey(os: string): string {
  return os === "ios" ? "mobile.home.check.share_sheet_body_ios" : "mobile.home.check.share_sheet_body";
}

/** The privacy line at the bottom of home: the Android one talks about shields an iPhone does not have. */
export function homePrivacyKey(os: string): string {
  return os === "ios" ? "mobile.home.privacy_ios" : "mobile.home.privacy";
}

/**
 * The hero when this phone has no shield at all (the iPhone today): not
 * "let's set up your protection — 0 shields active", which asks for a setup
 * that does not exist, but what the app does now and where the rest is.
 * Null when the usual hero copy applies.
 */
export function heroWithoutShieldsKeys(os: string, shieldCount: number): { title: string; sub: string } | null {
  if (shieldCount > 0 || os !== "ios") return null;
  return { title: "mobile.home.hero.title_ios", sub: "mobile.home.hero.sub_ios" };
}
