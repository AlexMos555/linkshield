import type { MessageVerdict } from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/**
 * What the History tab shows and which filter each row belongs to.
 *
 * Two stores feed it: the SQLite `checks` table (links and messages the
 * person checked) and the native block log (what the shields did on their
 * own, app open or not). The home activity card counts the same two stores,
 * and each counter opens History with the matching filter — so the filters
 * here are defined by what those counters add up, row for row:
 *
 *   Checked → every SQLite row (getStats total_checks, links and SMS)
 *   Blocked → shield "blocked" + checked links "dangerous" (threats_blocked)
 *   Warned  → shield "warned"  + checked links "caution"   (threats_warned)
 *
 * A message check is listed under Checked and SMS only: nothing was blocked
 * or warned on its own — the person asked, and was told.
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

export type HistoryItem = ShieldItem | CheckItem | SmsItem;

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

/** Both stores as one list, newest first. Rows with no readable time sink to the end. */
export function mergeHistory(checks: readonly CheckRowInput[], shield: readonly ShieldRowInput[]): HistoryItem[] {
  const shieldItems = keyShieldItems(
    shield.map(toShieldItem).filter((x): x is Omit<ShieldItem, "key"> => x !== null),
  );
  const checkItems = checks.map(toCheckOrSms);
  const time = (item: HistoryItem) => (Number.isFinite(item.ts) ? item.ts : -Infinity);
  return [...checkItems, ...shieldItems].sort((a, b) => time(b) - time(a));
}

/** Does this row belong under this chip? Mirrors the home counters (see top). */
export function matchesFilter(item: HistoryItem, filter: HistoryFilter): boolean {
  switch (filter) {
    case "all":
      return true;
    case "blocked":
      return item.type === "shield" ? item.kind === "blocked" : item.type === "check" && item.level === "dangerous";
    case "warned":
      return item.type === "shield" ? item.kind === "warned" : item.type === "check" && item.level === "caution";
    case "checked":
      return item.type !== "shield";
    case "sms":
      return item.type === "sms";
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

/** Should this filter say "only the latest events are shown"? */
export function isTruncated(filter: HistoryFilter, gaps: HistoryGaps): boolean {
  switch (filter) {
    case "all":
      return gaps.checksFull || gaps.shieldBlocked || gaps.shieldWarned;
    case "blocked":
      return gaps.checksFull || gaps.shieldBlocked;
    case "warned":
      return gaps.checksFull || gaps.shieldWarned;
    case "checked":
    case "sms":
      return gaps.checksFull;
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
