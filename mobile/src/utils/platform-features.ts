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
 * separate steps: a Safari Web Extension (shipped: safariLayerState below), an SMS filter
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

// Literal keys, so scripts/check-mobile-i18n.py can see every one. The order
// is the order on screen: the one people meet first (Safari) on top.
const IOS_LAYERS: ReadonlyArray<Omit<IosLayer, "status">> = [
  { id: "safari", titleKey: "mobile.ios.safari_title", lineKey: "mobile.ios.safari_line" },
  { id: "sms_filter", titleKey: "mobile.ios.sms_title", lineKey: "mobile.ios.sms_line" },
  { id: "dns", titleKey: "mobile.ios.dns_title", lineKey: "mobile.ios.dns_line" },
];

const STATUSES: ReadonlySet<string> = new Set(["coming", "setup", "on"]);

/**
 * `lines` lets a layer say more than its default line once it is built
 * (e.g. the Safari layer: "turned off" vs "allow on all websites").
 */
export function iosProtectionLayers(
  availability: IosLayerAvailability = {},
  lines: Partial<Record<IosLayerId, string>> = {},
): IosLayer[] {
  return IOS_LAYERS.map((layer) => {
    const reported = availability[layer.id];
    const status: IosLayerStatus = reported && STATUSES.has(reported) ? reported : "coming";
    const line = status !== "coming" ? lines[layer.id] : undefined;
    return { ...layer, lineKey: line || layer.lineKey, status };
  });
}

// ── The Safari layer ──────────────────────────────────────────────────

/**
 * What the app can learn about its Safari Web Extension
 * (modules/cleanway-safari): whether it ships in this build, whether it is
 * switched on (iOS 26.2+ only — older iOS has no API), and when it last
 * ran on a real web page (the extension tells the app, which proves "Allow on
 * all websites" too — nothing else can).
 */
export interface SafariExtensionFacts {
  bundled: boolean;
  stateKnown: boolean;
  enabled: boolean;
  lastSeenMs: number | null;
}

export const NO_SAFARI_EXTENSION: SafariExtensionFacts = Object.freeze({
  bundled: false,
  stateKnown: false,
  enabled: false,
  lastSeenMs: null,
});

/** Validates what the native module returned; anything odd reads as "not known". */
export function parseSafariFacts(raw: unknown): SafariExtensionFacts {
  if (!raw || typeof raw !== "object") return NO_SAFARI_EXTENSION;
  const r = raw as Record<string, unknown>;
  const seen = r.lastSeenMs;
  const stateKnown = r.stateKnown === true;
  return {
    bundled: r.bundled === true,
    stateKnown,
    enabled: stateKnown && r.enabled === true,
    lastSeenMs: typeof seen === "number" && Number.isFinite(seen) && seen > 0 ? seen : null,
  };
}

/**
 * "Seen on a web page" counts for two weeks. The extension reports at most
 * every 6 hours while Safari is used, so a fortnight of silence means it was
 * switched off on an iOS that cannot say so, or Safari is not being used —
 * either way, the setup steps are the right thing to show.
 */
export const SAFARI_SEEN_FRESH_MS = 14 * 24 * 3600_000;

export function safariLayerState(facts: SafariExtensionFacts, nowMs: number): { status: IosLayerStatus; lineKey: string } {
  if (!facts.bundled) return { status: "coming", lineKey: "mobile.ios.safari_line" };
  if (facts.stateKnown && !facts.enabled) return { status: "setup", lineKey: "mobile.ios.safari_line_off" };
  const seen = facts.lastSeenMs;
  // A time from the future (clock changed) is not trusted beyond a day.
  const fresh = seen !== null && nowMs - seen < SAFARI_SEEN_FRESH_MS && seen - nowMs < 24 * 3600_000;
  if (fresh) return { status: "on", lineKey: "mobile.ios.safari_line_on" };
  if (facts.stateKnown && facts.enabled) return { status: "setup", lineKey: "mobile.ios.safari_line_allow" };
  return { status: "setup", lineKey: "mobile.ios.safari_line_setup" };
}

/**
 * The setup steps, in order. The Settings path is the iOS 18+ one
 * (Settings → Apps → Safari); step 1's text names the older path too.
 */
export const SAFARI_SETUP_STEP_KEYS: ReadonlyArray<string> = [
  "mobile.ios.safari_setup_step1",
  "mobile.ios.safari_setup_step2",
  "mobile.ios.safari_setup_step3",
  "mobile.ios.safari_setup_step4",
];

/**
 * The page "Test it in Safari" opens. cleanway.ai is never checked by the
 * extension, but its content script there tells the app it runs
 * (packages/extension-core/src/content/index.js → EXTENSION_SEEN).
 * `x-safari-https` makes iOS 17+ open it in Safari even when another browser
 * is the default — the extension lives only in Safari.
 */
export const SAFARI_TEST_URL = "x-safari-https://cleanway.ai/";
export const SAFARI_TEST_URL_FALLBACK = "https://cleanway.ai/";

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
