/**
 * Left-to-right or right-to-left: what a language needs, and what a language
 * change has to do about it.
 *
 * React Native reads the direction once, when the JS starts
 * (`I18nManager.isRTL` is a constant), and `forceRTL` only writes a setting
 * for the NEXT start. On Android the shield keeps the process — and the JS in
 * it — alive after the app is swiped away, so "the next start" may be days
 * off. Judging a later change by that constant went wrong on a Galaxy
 * (2026-11-11): Arabic → Russian compared "Russian is LTR" with a constant
 * that still said LTR, wrote nothing, asked for no restart, and the screen
 * stayed mirrored until the shield was turned off and the app started twice.
 *
 * So the app keeps what it last ASKED for next to what the JS STARTED in,
 * and restarts the JS itself (src/i18n/index.ts) when they part.
 *
 * Pure — no React Native — so scripts/test-device-fixes.mjs runs it.
 */

export const RTL_LANGUAGES: readonly string[] = ["ar"];

export function isRtlLanguage(language: string): boolean {
  return RTL_LANGUAGES.includes(language);
}

export interface DirectionState {
  /** The direction this JS started in (I18nManager.isRTL): what it thinks is on screen. */
  startedRTL: boolean;
  /** The direction last written for the next start (forceRTL). */
  requestedRTL: boolean;
}

export interface DirectionChange {
  /** Write the new direction for the next start. */
  write: boolean;
  /** The JS must restart for the screen to be right. */
  reload: boolean;
}

/**
 * What switching to a language of direction [nextRTL] takes. A restart is due
 * when the language's direction is not the one this JS started in — and also
 * when an earlier flip is still waiting for its restart: the app's window may
 * have been rebuilt in the new direction since (swiped away, opened again),
 * so the JS no longer knows what is on screen.
 */
export function directionChange(state: DirectionState, nextRTL: boolean): DirectionChange {
  return {
    write: nextRTL !== state.requestedRTL,
    reload: nextRTL !== state.startedRTL || state.requestedRTL !== state.startedRTL,
  };
}

/**
 * At start, after the saved language is applied: restart by itself? Only when
 * the language's direction is not the one on screen, and only once per
 * direction — [triedFor] is the direction a restart was already spent on
 * ("rtl" / "ltr", stored), so a phone that does not take the setting cannot loop.
 */
export function startupReload(startedRTL: boolean, wantedRTL: boolean, triedFor: string | null): boolean {
  if (wantedRTL === startedRTL) return false;
  return triedFor !== directionName(wantedRTL);
}

export function directionName(rtl: boolean): "rtl" | "ltr" {
  return rtl ? "rtl" : "ltr";
}
