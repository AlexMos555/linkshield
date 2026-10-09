/**
 * The iPhone's DNS protection as the native side reports it
 * (ios/CleanwayVpnModule.swift, CleanwayDnsSettings.report). Pure — no React
 * Native — so mobile/scripts/test-ios-dns.mjs runs it under plain node.
 */

/** What went wrong, as far as the app can tell (NEDNSSettingsManagerError, else "failed"). */
export type IosDnsError = 'invalid' | 'disabled' | 'stale' | 'cannot_remove' | 'failed';

export type IosDnsReport = {
  /** A DNS configuration of this app is saved in iOS. */
  installed: boolean;
  /** …and it is ours, pointing at today's gateway. False for an old or foreign one. */
  current: boolean;
  /** The person picked it in Settings (iOS's isEnabled; the app cannot set it). */
  enabled: boolean;
  /** Null when the call succeeded. */
  error: IosDnsError | null;
  /** Raw "domain code: description" of the system error, for logs only — never shown. */
  message: string | null;
};

const ERRORS: ReadonlySet<string> = new Set(['invalid', 'disabled', 'stale', 'cannot_remove', 'failed']);

/**
 * Validates the native dictionary. Anything odd reads as "not there": a
 * missing or non-boolean `enabled` is false, never on — the screen must not
 * claim protection it cannot see. An unknown error code is "failed".
 */
export function parseIosDnsReport(raw: unknown): IosDnsReport {
  const r = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
  const installed = r.installed === true;
  const error = typeof r.error === 'string' ? (ERRORS.has(r.error) ? (r.error as IosDnsError) : 'failed') : null;
  return {
    installed,
    current: installed && r.current === true,
    enabled: installed && r.enabled === true,
    error: raw && typeof raw === 'object' ? error : 'failed',
    message: typeof r.message === 'string' ? r.message : null,
  };
}
