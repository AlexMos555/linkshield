import type {
  MessageAnalysis,
  MessageLink,
  MessageReason,
  MessageVerdict,
} from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/**
 * The JS half of the message check (app/message.tsx): which link hosts go to
 * the server, how the answers fold into the on-device verdict, what to advise,
 * and what the history keeps.
 *
 * Pure — no React Native — so scripts/test-message-verdict.mjs runs it under
 * plain node.
 *
 * Privacy: nothing here ever sees the message text. It works on the native
 * analysis, whose links carry the link as written (path and query included)
 * and its host. Only a host may leave the phone, and only the hosts
 * planServerChecks() picks.
 */

/**
 * At most this many distinct hosts per message go to GET /public/check. The
 * endpoint allows about 60 requests an hour per IP, and Tele2 CGNAT puts many
 * phones behind one IP.
 */
export const MAX_SERVER_CHECKS = 3;

/** Reasons shown on the result screen; the rest stay in the history row. */
export const MAX_SHOWN_REASONS = 4;

const MAX_ADVICE = 4;
const MAX_HISTORY_HOSTS = 5;

export type ServerLevel = "safe" | "caution" | "dangerous";

/** What the domain-only server check said about one host. */
export type LinkCheck =
  | { kind: "pending" }
  | { kind: "checked"; level: ServerLevel }
  | { kind: "failed"; why: "rate_limited" | "offline" | "timeout" | "error" }
  /** Never sent: over the per-message cap, or an IP address rather than a domain. */
  | { kind: "not_sent" };

/** Native reason codes plus the two the server check adds. */
export type MessageCheckReason = MessageReason | "link_checked_dangerous" | "link_checked_caution";

/** One line of the "what to do" block. */
export type AdviceKey =
  | "no_link"
  | "no_reply"
  | "no_code"
  | "no_money"
  | "no_install"
  | "call_yourself"
  | "call_relative"
  | "delete";

/** What one link row says, combining the on-device list and the server check. */
export type LinkVerdict =
  | "blocked"
  | "allowed"
  | "system"
  | "shortener"
  | "messenger"
  | "checking"
  | "dangerous"
  | "caution"
  | "clean"
  | "not_checked"
  | "rate_limited"
  | "offline"
  | "timeout"
  | "failed";

export type MergedVerdict = { verdict: MessageVerdict; reasons: MessageCheckReason[] };

/**
 * What the links of a message add up to: none at all, some still being
 * checked, some we could not check (offline, rate limit, a short link, a
 * shared Google host…), or all checked.
 */
export type LinksState = "none" | "checking" | "unchecked" | "checked";

/** What a history row keeps of a message check: never the text, never a link's path. */
export type MessageHistoryEntry = {
  hosts: string[];
  level: MessageVerdict;
  reasons: MessageCheckReason[];
};

const RANK: Record<MessageVerdict, number> = { no_signals: 0, caution: 1, dangerous: 2 };

const IP_HOST = /^(\d{1,3}\.){3}\d{1,3}$|^\[/;

/**
 * Is shared text a MESSAGE — words around a link, several links, or plain
 * words — rather than one bare link? A bare link keeps the link flow
 * (/shared); anything more goes to the on-device message check, which reads
 * the wording as well as the links.
 */
export function isMessageText(text: string): boolean {
  return (text || "").trim().split(/\s+/).filter(Boolean).length > 1;
}

/**
 * The hosts worth asking the server about, keyed by host. Only links the
 * on-device list knows nothing about: a listed link is already answered, an
 * allowed one was vouched for. A shortener, messenger or system host is not
 * sent either — "clck.ru", "t.me" or "docs.google.com" would come back as a
 * popular, clean site and say nothing about the page the link leads to.
 */
export function planServerChecks(links: readonly MessageLink[]): Readonly<Record<string, LinkCheck>> {
  const hosts = [...new Set(
    links
      .filter((l) => l.status === "unknown" && !l.shortener && !l.messenger)
      .map((l) => l.host),
  )];
  const domains = hosts.filter((h) => !IP_HOST.test(h));
  const sent = new Set(domains.slice(0, MAX_SERVER_CHECKS));
  return Object.fromEntries(
    hosts.map((h): [string, LinkCheck] => [h, sent.has(h) ? { kind: "pending" } : { kind: "not_sent" }]),
  );
}

/** Hosts from a plan that are waiting for the server. */
export function pendingHosts(checks: Readonly<Record<string, LinkCheck>>): string[] {
  return Object.keys(checks).filter((h) => checks[h].kind === "pending");
}

/** One link row, most decisive fact first. */
export function linkVerdict(link: MessageLink, checks: Readonly<Record<string, LinkCheck>>): LinkVerdict {
  if (link.status === "blocked") return "blocked";
  if (link.status === "allowed_by_user") return "allowed";
  if (link.status === "system") return "system";
  if (link.shortener) return "shortener";
  if (link.messenger) return "messenger";
  const check = checks[link.host];
  if (!check || check.kind === "not_sent") return "not_checked";
  if (check.kind === "pending") return "checking";
  if (check.kind === "checked") return check.level === "safe" ? "clean" : check.level;
  return check.why === "error" ? "failed" : check.why;
}

/** Link rows that say nothing about the site's safety: the verdict could not take the link into account. */
const UNCHECKED: ReadonlySet<LinkVerdict> = new Set<LinkVerdict>([
  "not_checked", "rate_limited", "offline", "timeout", "failed", "shortener", "messenger", "system",
]);

/**
 * A calm verdict must not read as "the link is fine" while the link is still
 * being checked, or was never checked: the result screen says which.
 */
export function linksState(links: readonly MessageLink[], checks: Readonly<Record<string, LinkCheck>>): LinksState {
  if (links.length === 0) return "none";
  const rows = links.map((l) => linkVerdict(l, checks));
  if (rows.includes("checking")) return "checking";
  return rows.some((v) => UNCHECKED.has(v)) ? "unchecked" : "checked";
}

/**
 * Folds the server's answers into the on-device verdict. A server answer can
 * only raise it — a "safe" site does not clear a message that asks for a code
 * — and a dangerous site makes the whole message dangerous.
 */
export function mergeVerdict(
  analysis: Pick<MessageAnalysis, "verdict" | "reasons">,
  checks: Readonly<Record<string, LinkCheck>>,
): MergedVerdict {
  const levels = Object.values(checks).flatMap((c) => (c.kind === "checked" ? [c.level] : []));
  const server: MessageVerdict =
    levels.includes("dangerous") ? "dangerous"
    : levels.includes("caution") ? "caution"
    : "no_signals";
  const verdict = RANK[server] > RANK[analysis.verdict] ? server : analysis.verdict;
  const reasons: MessageCheckReason[] = [...analysis.reasons];
  if (server === "dangerous") {
    // A listed link already says it; a second "the site is dangerous" line adds nothing.
    return reasons.includes("link_blocklisted")
      ? { verdict, reasons }
      : { verdict, reasons: ["link_checked_dangerous", ...reasons] };
  }
  if (server === "caution") return { verdict, reasons: [...reasons, "link_checked_caution"] };
  return { verdict, reasons };
}

/** Did the verdict get worse? The screen buzzes again only then. */
export function isEscalation(from: MessageVerdict, to: MessageVerdict): boolean {
  return RANK[to] > RANK[from];
}

/**
 * The "what to do" lines: the ones this message calls for, costliest mistake
 * first (a code, money, an app, then the link and the callback), then the step
 * that always applies — call the organisation (or the relative) yourself —
 * and, for a dangerous message, delete it.
 */
export function adviceFor(input: {
  verdict: MessageVerdict;
  reasons: readonly MessageCheckReason[];
  hasLinks: boolean;
  hasPhones: boolean;
  /** A link is still being checked or could not be checked (see linksState). */
  linksUnchecked?: boolean;
}): AdviceKey[] {
  const { verdict, reasons, hasLinks, hasPhones, linksUnchecked = false } = input;
  if (verdict === "no_signals") return linksUnchecked ? ["no_link", "no_code", "call_yourself"] : ["no_code", "call_yourself"];
  const has = (...codes: MessageCheckReason[]) => codes.some((c) => reasons.includes(c));
  const specific: AdviceKey[] = [
    ...(has("asks_for_code") ? (["no_code"] as const) : []),
    ...(has("safe_account", "asks_for_payment", "sms_transfer_command", "relative_in_trouble") ? (["no_money"] as const) : []),
    ...(has("install_app", "link_apk", "malware_lure") ? (["no_install"] as const) : []),
    ...(hasLinks ? (["no_link"] as const) : []),
    ...(hasPhones || has("call_unknown_number") ? (["no_reply"] as const) : []),
  ];
  const tail: AdviceKey[] = [
    has("relative_in_trouble") ? "call_relative" : "call_yourself",
    ...(verdict === "dangerous" ? (["delete"] as const) : []),
  ];
  return [...specific.slice(0, MAX_ADVICE - tail.length), ...tail];
}

/** The history row of a finished check: verdict, reason codes and link hosts — nothing else. */
export function historyEntry(links: readonly MessageLink[], merged: MergedVerdict): MessageHistoryEntry {
  return {
    hosts: [...new Set(links.map((l) => l.host))].slice(0, MAX_HISTORY_HOSTS),
    level: merged.verdict,
    reasons: [...merged.reasons],
  };
}

/** Narrowing for values read back from storage. */
export function isMessageVerdict(value: unknown): value is MessageVerdict {
  return value === "dangerous" || value === "caution" || value === "no_signals";
}
