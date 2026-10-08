import type { KeepAliveStatus, OemFamily, RearmDecision } from './CleanwayVpn.types';

/**
 * Turns the native keepAliveStatus() map into a typed KeepAliveStatus.
 *
 * The JS bundle and the native build ship separately, so every field
 * degrades on its own: a missing or non-boolean value reads as null ("cannot
 * tell") and the row it feeds says nothing about it — never a guess either
 * way. An unknown phone maker reads as null: no steps rather than wrong steps.
 */

/** Must match KeepAlivePolicy.OemFamily.wire (KeepAlivePolicyTest pins the native side). */
export const OEM_FAMILIES: readonly OemFamily[] = ['samsung', 'xiaomi', 'huawei', 'oppo', 'vivo'];

const REARM_DECISIONS: readonly RearmDecision[] = [
  'start', 'running', 'not_wanted', 'taken_away', 'private_dns', 'other_vpn', 'budget', 'no_consent',
];

export const UNKNOWN_KEEP_ALIVE: KeepAliveStatus = { batteryUnrestricted: null, alwaysOn: null, oem: null };

export function parseKeepAliveStatus(raw: unknown): KeepAliveStatus {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return UNKNOWN_KEEP_ALIVE;
  const r = raw as Record<string, unknown>;
  const bool = (v: unknown): boolean | null => (typeof v === 'boolean' ? v : null);
  const oem =
    typeof r.oem === 'string' && (OEM_FAMILIES as readonly string[]).includes(r.oem) ? (r.oem as OemFamily) : null;
  return { batteryUnrestricted: bool(r.batteryUnrestricted), alwaysOn: bool(r.alwaysOn), oem };
}

/** The native decision, or null for anything this bundle does not know. */
export function parseRearmDecision(raw: unknown): RearmDecision | null {
  return typeof raw === 'string' && (REARM_DECISIONS as readonly string[]).includes(raw)
    ? (raw as RearmDecision)
    : null;
}
