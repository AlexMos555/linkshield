import type {
  MessageAnalysis,
  MessageLegitShape,
  MessageLink,
  MessageLinkStatus,
  MessageReason,
  MessageVerdict,
} from './CleanwayVpn.types';

/**
 * Turns the native analyzeMessage() map into a typed MessageAnalysis.
 *
 * The bridge is ours, but the JS bundle and the native build ship separately
 * (a JS reload on an older APK, a newer APK with this JS): a field that is
 * missing or unknown must degrade, never crash a screen or show a verdict
 * the UI cannot explain. An unknown verdict rejects the whole result — the
 * caller then says "could not check" instead of guessing.
 */

const VERDICTS: readonly MessageVerdict[] = ['dangerous', 'caution', 'no_signals'];

const LINK_STATUSES: readonly MessageLinkStatus[] = ['blocked', 'system', 'allowed_by_user', 'unknown'];

/** Must match MessageAnalyzer.ALL_REASONS (MessageAnalyzerTest pins the two against each other). */
export const MESSAGE_REASONS: readonly MessageReason[] = [
  'link_blocklisted',
  'claims_organisation',
  'threat_or_urgency',
  'asks_to_confirm_data',
  'reward_bait',
  'call_unknown_number',
  'link_not_official',
  'link_shortener',
  'link_messenger',
  'link_ip_address',
  'link_lookalike',
  'link_imitates_brand',
  'link_apk',
  'asks_for_code',
  'safe_account',
  'asks_for_payment',
  'relative_in_trouble',
  'install_app',
  'malware_lure',
  'sms_transfer_command',
  'disguised_letters',
  'sender_personal_number',
  'sender_mismatch',
];

const LEGIT_SHAPES: readonly MessageLegitShape[] = [
  'login_code',
  'payment_alert',
  'pickup_code',
  'public_alert',
  'safety_notice',
];

function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function parseLink(value: unknown): MessageLink | null {
  if (typeof value !== 'object' || value === null) return null;
  const o = value as Record<string, unknown>;
  if (typeof o.text !== 'string' || typeof o.host !== 'string' || !isOneOf(o.status, LINK_STATUSES)) {
    return null;
  }
  return {
    text: o.text,
    host: o.host,
    status: o.status,
    shortener: o.shortener === true,
    messenger: o.messenger === true,
  };
}

export function parseMessageAnalysis(raw: unknown): MessageAnalysis | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (!isOneOf(o.verdict, VERDICTS)) return null;
  const links = Array.isArray(o.links)
    ? o.links.map(parseLink).filter((l): l is MessageLink => l !== null)
    : [];
  return {
    verdict: o.verdict,
    // A code from a newer native build has no translation here yet: drop it, keep the verdict.
    reasons: strings(o.reasons).filter((r): r is MessageReason => isOneOf(r, MESSAGE_REASONS)),
    links,
    phones: strings(o.phones),
    legitShape: isOneOf(o.legitShape, LEGIT_SHAPES) ? o.legitShape : null,
    organisations: strings(o.organisations),
    truncated: o.truncated === true,
    listAvailable: o.listAvailable === true,
    listStale: o.listStale === true,
  };
}
