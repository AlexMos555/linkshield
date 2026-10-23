/**
 * The legal pages the app links to: from sign-in (app/auth.tsx, where the
 * email address is collected — GDPR Art. 13 wants the policy at that point),
 * the paywall (App Store Review 3.1.2) and Settings. One place, so the three
 * cannot drift apart.
 */
export const PRIVACY_POLICY_URL = "https://cleanway.ai/privacy-policy";
export const TERMS_URL = "https://cleanway.ai/terms";
/**
 * Settings → About → Data sources: the credit the open data asks for (the
 * popular-site ranking, the Android shield's veto list among its copies, is
 * adapted from the Majestic Million, CC BY 3.0, and the Chrome UX Report,
 * CC BY 4.0). The section's id is DATA_SOURCES_ANCHOR in
 * landing/lib/data-sources.ts.
 */
export const DATA_SOURCES_URL = "https://cleanway.ai/transparency/methodology#data-sources";
