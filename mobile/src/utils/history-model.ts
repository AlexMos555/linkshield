import type {
  MessageReason,
  MessageVerdict,
  SmsAlertEvent,
  SmsAlertVerdict,
} from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/**
 * What the History tab shows and which filter each row belongs to.
 *
 * Three stores feed it: the SQLite `checks` table (links and messages the
 * person checked), the native block log (what the shields did on their own,
 * app open or not) and, in the RuStore build, the SMS event log (messages the
 * automatic SMS check flagged as they arrived). The home activity card counts
 * all three, and each counter opens History with the matching filter — so
 * the filters here are defined by what those counters add up, row for row:
 *
 *   Checked → every SQLite row (getStats total_checks, links and SMS)
 *   Blocked → shield "blocked" + checked links "dangerous" (threats_blocked)
 *   Warned  → shield "warned"  + checked links "caution"   (threats_warned)
 *             + every SMS the automatic check flagged (its flaggedCount)
 *
 * A message check is listed under Checked and SMS only: nothing was blocked
 * or warned on its own — the person asked, and was told. An automatic SMS
 * warning is listed under Warned and SMS, whatever its verdict: Cleanway
 * warned as it arrived, but the phone showed the message anyway (only the
 * default SMS app can hold one back), so it was never blocked. The harmless
 * SMS the automatic check read leave no row, so they are in no counter here
 * (the SMS card shows their number on its own).
 *
 * Pure — no React Native — so scripts/test-history-model.mjs runs it under
 * plain node. Only type imports: the test loads the compiled file as an ES
 * module, where a runtime import without an extension would not resolve.
 */

export type HistoryFilter = "all" | "blocked" | "warned" | "checked" | "sms";

/** Chip order on screen. */
export const HISTORY_FILTERS: readonly HistoryFilter[] = ["all", "blocked", "warned", "checked", "sms"];

/** `source` of the SQLite rows written by the message check (database.ts re-exports it). */
export const MESSAGE_CHECK_SOURCE = "sms";

export type ShieldKind = "blocked" | "warned" | "allowed";
export type ShieldSource = "dns" | "link";
export type CheckLevel = "safe" | "caution" | "dangerous";

/** Something a shield did on its own. Opens the detail sheet. */
export type ShieldItem = {
  type: "shield";
  key: string;
  ts: number;
  domain: string;
  kind: ShieldKind;
  /** Which shield acted; null when unknown (allows, unknown values). */
  source: ShieldSource | null;
};

/** A link the person checked by hand. */
export type CheckItem = {
  type: "check";
  key: string;
  ts: number;
  domain: string;
  /** null for a level this build does not know — shown as "unknown", never as safe. */
  level: CheckLevel | null;
  score: number;
};

/** A message check. The text was never stored — only the verdict and link hosts. */
export type SmsItem = {
  type: "sms";
  key: string;
  ts: number;
  hosts: string[];
  verdict: MessageVerdict | null;
};

/**
 * An SMS the automatic check flagged as it arrived. Opens its detail sheet.
 * Never the text: it was never stored.
 */
export type SmsAlertItem = {
  type: "sms_alert";
  key: string;
  ts: number;
  /** The event id; the notification's deep link names it. */
  id: string;
  sender: string | null;
  verdict: SmsAlertVerdict;
  reasons: MessageReason[];
  hosts: string[];
};

export type HistoryItem = ShieldItem | CheckItem | SmsItem | SmsAlertItem;

/** A SQLite `checks` row as getRecentChecks returns it (unvalidated). */
export interface CheckRowInput {
  id?: unknown;
  domain?: unknown;
  score?: unknown;
  level?: unknown;
  source?: unknown;
  checked_at?: unknown;
}

/** A native block-log entry as the bridge returns it (unvalidated). */
export interface ShieldRowInput {
  domain?: unknown;
  ts?: unknown;
  kind?: unknown;
  source?: unknown;
}

const SHIELD_KINDS: readonly ShieldKind[] = ["blocked", "warned", "allowed"];
const SHIELD_SOURCES: readonly ShieldSource[] = ["dns", "link"];
const CHECK_LEVELS: readonly CheckLevel[] = ["safe", "caution", "dangerous"];
const MESSAGE_VERDICTS: readonly MessageVerdict[] = ["dangerous", "caution", "no_signals"];
const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const MAX_HOSTNAME = 253;
/** SmsEvents.eventId (same as isSmsEventId in the module; repeated to keep this file import-free). */
const SMS_EVENT_ID = /^[0-9a-f]{16}$/;

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | null {
  return typeof value === "string" && (allowed as readonly string[]).includes(value) ? (value as T) : null;
}

/**
 * SQLite used to store `datetime('now')` — "YYYY-MM-DD HH:MM:SS", UTC with no
 * timezone marker. Hermes reads that as local time (hours off) or as Invalid
 * Date, so it is normalised to ISO-UTC first. Newer rows are ISO already.
 */
export function parseCheckedAt(value: unknown): number {
  if (typeof value !== "string" || value === "") return NaN;
  const sqlite = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value);
  return new Date(sqlite ? `${value.replace(" ", "T")}Z` : value).getTime();
}

/** The link hosts of a message-check row: space-separated in `domain`. */
export function splitHosts(domain: unknown): string[] {
  return typeof domain === "string" ? domain.split(" ").filter(Boolean) : [];
}

function toShieldItem(row: ShieldRowInput): Omit<ShieldItem, "key"> | null {
  const kind = oneOf(row.kind, SHIELD_KINDS);
  if (!kind || typeof row.domain !== "string" || row.domain === "") return null;
  const ts = typeof row.ts === "number" && Number.isFinite(row.ts) ? row.ts : NaN;
  return { type: "shield", ts, domain: row.domain, kind, source: oneOf(row.source, SHIELD_SOURCES) };
}

function toCheckOrSms(row: CheckRowInput, index: number): HistoryItem {
  const ts = parseCheckedAt(row.checked_at);
  const key = `c:${typeof row.id === "number" || typeof row.id === "string" ? row.id : `i${index}`}`;
  if (row.source === MESSAGE_CHECK_SOURCE) {
    return { type: "sms", key, ts, hosts: splitHosts(row.domain), verdict: oneOf(row.level, MESSAGE_VERDICTS) };
  }
  const score = typeof row.score === "number" && Number.isFinite(row.score) ? row.score : 0;
  return {
    type: "check",
    key,
    ts,
    domain: typeof row.domain === "string" ? row.domain : "",
    level: oneOf(row.level, CHECK_LEVELS),
    score,
  };
}

/**
 * Stable keys: a list refresh prepends rows, so an index-based key would
 * re-render every row. Two entries with the same site, kind and millisecond
 * (never written, but not impossible) get a suffix instead of a collision.
 */
function keyShieldItems(items: readonly Omit<ShieldItem, "key">[]): ShieldItem[] {
  const seen = new Map<string, number>();
  return items.map((item) => {
    const base = `s:${item.kind}:${item.source ?? "-"}:${item.domain}:${item.ts}`;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    return { ...item, key: n === 0 ? base : `${base}#${n}` };
  });
}

/** Validated by the module (parseSmsAlertEvents): ids are unique, so the id is the key. */
function toSmsAlertItem(event: SmsAlertEvent): SmsAlertItem {
  return {
    type: "sms_alert",
    key: `a:${event.id}`,
    ts: event.ts,
    id: event.id,
    sender: event.sender,
    verdict: event.verdict,
    reasons: [...event.reasons],
    hosts: [...event.hosts],
  };
}

/** Every store as one list, newest first. Rows with no readable time sink to the end. */
export function mergeHistory(
  checks: readonly CheckRowInput[],
  shield: readonly ShieldRowInput[],
  smsAlerts: readonly SmsAlertEvent[] = [],
): HistoryItem[] {
  const shieldItems = keyShieldItems(
    shield.map(toShieldItem).filter((x): x is Omit<ShieldItem, "key"> => x !== null),
  );
  const checkItems = checks.map(toCheckOrSms);
  const alertItems = smsAlerts.map(toSmsAlertItem);
  const time = (item: HistoryItem) => (Number.isFinite(item.ts) ? item.ts : -Infinity);
  return [...checkItems, ...shieldItems, ...alertItems].sort((a, b) => time(b) - time(a));
}

/** Does this row belong under this chip? Mirrors the home counters (see top). */
export function matchesFilter(item: HistoryItem, filter: HistoryFilter): boolean {
  switch (filter) {
    case "all":
      return true;
    case "blocked":
      return item.type === "shield" ? item.kind === "blocked" : item.type === "check" && item.level === "dangerous";
    case "warned":
      return item.type === "shield" ? item.kind === "warned"
        : item.type === "check" ? item.level === "caution"
        : item.type === "sms_alert";
    case "checked":
      return item.type === "check" || item.type === "sms";
    case "sms":
      return item.type === "sms" || item.type === "sms_alert";
  }
}

export function filterHistory(items: readonly HistoryItem[], filter: HistoryFilter): HistoryItem[] {
  return filter === "all" ? [...items] : items.filter((item) => matchesFilter(item, filter));
}

/** What each store could not list: a full page of checks, or shield events past the log. */
export type HistoryGaps = {
  /** getRecentChecks returned a full page: older checks exist. */
  checksFull: boolean;
  /** The lifetime counter of a kind is above the events the log still holds. */
  shieldBlocked: boolean;
  shieldWarned: boolean;
  /** More SMS were flagged than the SMS event log still lists (it keeps 200, for 90 days). */
  smsAlerts: boolean;
};

/**
 * Which shield kinds have events the log no longer lists. The lifetime
 * counters behind the home numbers keep counting after the 200-event log
 * rotates — and on an install from before events were coalesced they were
 * counted per DNS query — so "Blocked 3400" can open a list of 15 rows.
 */
export function shieldGaps(
  shield: readonly ShieldRowInput[],
  totals: { blocked: number; warned: number },
): Pick<HistoryGaps, "shieldBlocked" | "shieldWarned"> {
  const listed = (kind: ShieldKind) => shield.filter((row) => row.kind === kind).length;
  return { shieldBlocked: totals.blocked > listed("blocked"), shieldWarned: totals.warned > listed("warned") };
}

/** Flagged SMS the event log no longer lists: the lifetime count is above what it holds. */
export function smsAlertGap(listed: number, flaggedTotal: number): boolean {
  return flaggedTotal > listed;
}

/** Should this filter say "only the latest events are shown"? */
export function isTruncated(filter: HistoryFilter, gaps: HistoryGaps): boolean {
  switch (filter) {
    case "all":
      return gaps.checksFull || gaps.shieldBlocked || gaps.shieldWarned || gaps.smsAlerts;
    case "blocked":
      return gaps.checksFull || gaps.shieldBlocked;
    case "warned":
      return gaps.checksFull || gaps.shieldWarned || gaps.smsAlerts;
    case "checked":
      return gaps.checksFull;
    case "sms":
      return gaps.checksFull || gaps.smsAlerts;
  }
}

/** The `filter` route param → a known filter; anything else shows everything. */
export function parseHistoryFilter(raw: unknown): HistoryFilter {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return oneOf(value, HISTORY_FILTERS) ?? "all";
}

/**
 * The `domain` route param → a DNS-form host name, or null. The deep link is
 * reachable by any app (the cleanway:// scheme is public), so anything that
 * is not a plain host name is ignored.
 */
export function parseDeepLinkDomain(raw: unknown): string | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") return null;
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  return host.length <= MAX_HOSTNAME && HOSTNAME.test(host) ? host : null;
}

/**
 * The block-log entry a notification points at: the newest one for this
 * site, preferring the kind the notification was about. Null when the site is
 * not in the log — then nothing opens, so a crafted link from another app
 * cannot put a made-up site and its "allow" button in front of the person.
 */
export function findShieldEvent(
  items: readonly HistoryItem[],
  domain: string,
  filter: HistoryFilter,
): ShieldItem | null {
  const forSite = items.filter((i): i is ShieldItem => i.type === "shield" && i.domain === domain);
  const wanted = filter === "blocked" || filter === "warned" ? filter : null;
  return forSite.find((i) => i.kind === wanted) ?? forSite[0] ?? null;
}

/**
 * The `sms` route param → an SMS event id, or null. Set by the SMS warning's
 * notification (cleanway:///history?filter=sms&sms=<id>); any app can craft
 * that link, so anything but a stored id's shape is ignored.
 */
export function parseDeepLinkSmsId(raw: unknown): string | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === "string" && SMS_EVENT_ID.test(value) ? value : null;
}

/**
 * The flagged SMS a notification points at, or null when the event log does
 * not hold that id — then nothing opens, so a crafted link cannot put a
 * made-up warning, sender or site in front of the person.
 */
export function findSmsAlert(items: readonly HistoryItem[], id: string): SmsAlertItem | null {
  return items.find((i): i is SmsAlertItem => i.type === "sms_alert" && i.id === id) ?? null;
}
