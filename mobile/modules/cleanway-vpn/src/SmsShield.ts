import type {
  MessageReason,
  SmsAlertEvent,
  SmsAlertVerdict,
  SmsPermissionState,
  SmsShieldStatus,
} from './CleanwayVpn.types';

/**
 * Turns the native smsShieldStatus() and recentSmsEvents() values into typed
 * ones.
 *
 * The JS bundle and the native build ship separately, and the events come
 * from a file another process wrote. Anything missing or odd degrades to the
 * claim that promises least: "not supported", "not requested", zero, "no
 * events" — never to "the check is on" or to a warning the screen cannot
 * explain. Only type imports: scripts/test-sms-shield.mjs loads the compiled
 * file as an ES module.
 */

/** What every non-Android platform, an older native build and any error report. */
export const SMS_SHIELD_UNSUPPORTED: SmsShieldStatus = {
  supported: false,
  permission: 'not_requested',
  canAskAgain: false,
  enabled: false,
  notificationsEnabled: false,
  backgroundRestricted: false,
  checkedCount: 0,
  flaggedCount: 0,
  lastCheckedAt: null,
  listAgeMs: null,
};

const PERMISSION_STATES: readonly SmsPermissionState[] = ['granted', 'denied', 'restricted_maybe', 'not_requested'];
const ALERT_VERDICTS: readonly SmsAlertVerdict[] = ['dangerous', 'caution'];
/** SmsEvents.eventId: 8 bytes of SHA-256 as hex. */
const EVENT_ID = /^[0-9a-f]{16}$/;
/** SmsEvents.MAX_HOSTS / MAX_REASONS; IncomingSmsParts.MAX_SENDER_CHARS code points + the ellipsis. */
const MAX_HOSTS = 5;
const MAX_REASONS = 12;
const MAX_SENDER_CODE_POINTS = 33;
const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | null {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value) ? (value as T) : null;
}

/** A count: a finite whole number ≥ 0, else 0. */
function count(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

/** A time or an age: a finite number ≥ 0, else null ("not known"). */
function moment(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

export function isSmsEventId(value: unknown): value is string {
  return typeof value === 'string' && EVENT_ID.test(value);
}

/**
 * smsShieldStatus() → SmsShieldStatus. Not an object, or `supported` not
 * exactly true: unsupported — the app must never offer a switch that cannot
 * work, nor call a check "on" that it cannot prove.
 */
export function parseSmsShieldStatus(raw: unknown): SmsShieldStatus {
  if (!isRecord(raw) || raw.supported !== true) return SMS_SHIELD_UNSUPPORTED;
  return {
    supported: true,
    permission: oneOf(raw.permission, PERMISSION_STATES) ?? 'not_requested',
    // Unknown reads as "will not ask": the screen then shows the way through
    // App info instead of a button whose dialog never comes.
    canAskAgain: raw.canAskAgain === true,
    enabled: raw.enabled === true,
    // Unknown reads as "cannot notify": the screen then asks, instead of
    // promising a warning that may never show.
    notificationsEnabled: raw.notificationsEnabled === true,
    backgroundRestricted: raw.backgroundRestricted === true,
    checkedCount: count(raw.checkedCount),
    flaggedCount: count(raw.flaggedCount),
    lastCheckedAt: moment(raw.lastCheckedAt),
    listAgeMs: moment(raw.listAgeMs),
  };
}

function parseEvent(raw: unknown, knownReasons: readonly MessageReason[]): SmsAlertEvent | null {
  if (!isRecord(raw) || !isSmsEventId(raw.id)) return null;
  const verdict = oneOf(raw.verdict, ALERT_VERDICTS);
  const ts = moment(raw.ts);
  if (verdict === null || ts === null) return null;
  // By code points, like the native cap: a UTF-16 slice could cut an emoji in half.
  const sender = typeof raw.sender === 'string' && raw.sender.trim() !== ''
    ? Array.from(raw.sender).slice(0, MAX_SENDER_CODE_POINTS).join('')
    : null;
  const reasons = Array.isArray(raw.reasons)
    ? raw.reasons.filter((r): r is MessageReason => oneOf(r, knownReasons) !== null).slice(0, MAX_REASONS)
    : [];
  const hosts = Array.isArray(raw.hosts)
    ? raw.hosts.filter((h): h is string => typeof h === 'string' && h.length <= 253 && HOSTNAME.test(h)).slice(0, MAX_HOSTS)
    : [];
  return { id: raw.id, ts, sender, verdict, reasons, hosts };
}

/**
 * recentSmsEvents() → the events this build can show, newest first as
 * stored. An event without a valid id, time or verdict is dropped whole; a
 * reason this build has no words for is dropped from its event (a newer
 * native build may add codes). Duplicate ids keep the first.
 */
export function parseSmsAlertEvents(raw: unknown, knownReasons: readonly MessageReason[]): SmsAlertEvent[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const events: SmsAlertEvent[] = [];
  for (const item of raw) {
    const event = parseEvent(item, knownReasons);
    if (event === null || seen.has(event.id)) continue;
    seen.add(event.id);
    events.push(event);
  }
  return events;
}
