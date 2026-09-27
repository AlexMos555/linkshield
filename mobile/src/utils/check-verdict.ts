/**
 * What the link-check screens (app/shared.tsx, app/result.tsx) show, from two
 * sources: the on-device list of scam sites (matchBlocklist) and the server's
 * domain check.
 *
 * The list answers in milliseconds and the server can take ten seconds, so a
 * listed site is called dangerous at once and the server's reasons arrive
 * afterwards. A server answer can never downgrade it: on 2026-09-25 a link
 * the phone had already refused to open got "we could not finish the check"
 * on its first tap and "dangerous 95" on its second (report #4).
 *
 * Pure — no React Native — so scripts/test-check-verdict.mjs runs it under
 * plain node. Types are structural on purpose: the server answer is read the
 * way @cleanway/api-client's PublicCheckResult spells it.
 */

export type CheckLevel = "safe" | "caution" | "dangerous";

/** The parts of a server answer this file reads (structurally a PublicCheckResult). */
export interface ServerAnswer {
  domain: string;
  score: number;
  level: string;
  exists?: boolean;
  confidence?: string;
  reasons: ReadonlyArray<{ detail: string; code?: string }>;
}

/** Reason code the phone adds when its own list knows the site. */
export const ON_DEVICE_LIST_CODE = "on_device_list";
/** Reason code a newer server sends for a name that does not exist. */
export const NOT_FOUND_CODE = "domain_not_found";
/**
 * `source` of a History row decided by the on-device list. Same value as
 * history-model.ts's LIST_CHECK_SOURCE (each file compiles alone in its test,
 * so the string is repeated rather than imported).
 */
export const LIST_CHECK_SOURCE = "list";

/** The server's level, read the way the screens always have: anything unknown is caution, never safe. */
export function serverLevel(answer: ServerAnswer): CheckLevel {
  return answer.level === "safe" || answer.level === "dangerous" ? answer.level : "caution";
}

/**
 * The name does not exist at all. Newer servers say so (`exists: false`, or
 * the domain_not_found reason); older ones called such a name "dangerous" for
 * having no HTTPS and no mail server — a typo in "sberbank.ru" read as a scam.
 */
export function isNotFound(answer: ServerAnswer | null): boolean {
  if (!answer) return false;
  return answer.exists === false || answer.reasons.some((r) => r.code === NOT_FOUND_CODE);
}

/**
 * The verdict on screen, or null while there is none yet. The list outranks
 * the server: listed means dangerous, whatever the server says or whenever
 * it answers.
 */
export function shownLevel(listed: string | null, answer: ServerAnswer | null): CheckLevel | null {
  if (listed) return "dangerous";
  return answer ? serverLevel(answer) : null;
}

/** Show the server's score ring? Only when the number agrees with the verdict shown. */
export function showScore(listed: string | null, answer: ServerAnswer | null): boolean {
  if (!answer || isNotFound(answer)) return false;
  return !listed || serverLevel(answer) === "dangerous";
}

/**
 * The server's reasons to list. Under a listed verdict a "safe" server answer
 * carries only reassurance ("well-known site") — shown as a red "why" it would
 * contradict the headline, so it is left out.
 */
export function reasonsToShow(listed: string | null, answer: ServerAnswer | null): ReadonlyArray<{ detail: string; code?: string }> {
  if (!answer) return [];
  if (listed && serverLevel(answer) === "safe") return [];
  return answer.reasons;
}

/** One History row, the shape src/services/database.ts saves. */
export interface HistoryRow {
  domain: string;
  score: number;
  level: CheckLevel;
  reasons: Array<{ detail: string; code?: string }>;
  confidence?: string;
  source?: string;
}

/** The History row a finished check becomes, or null when there is nothing to keep. */
export function historyRecord(
  domain: string,
  listed: string | null,
  answer: ServerAnswer | null,
): HistoryRow | null {
  if (listed) return listedRecord(domain, listed, answer);
  // A name that does not exist is not a site to remember a verdict for.
  if (!answer || isNotFound(answer)) return null;
  return {
    domain: answer.domain,
    score: answer.score,
    level: serverLevel(answer),
    reasons: [...answer.reasons],
    ...(answer.confidence ? { confidence: answer.confidence } : {}),
  };
}

/** The row of a site the on-device list knows: dangerous, with the server's details when it has them. */
function listedRecord(domain: string, listed: string, answer: ServerAnswer | null): HistoryRow {
  return {
    domain,
    score: answer && serverLevel(answer) === "dangerous" ? answer.score : 0,
    level: "dangerous",
    reasons: [{ code: ON_DEVICE_LIST_CODE, detail: "On the list of scam sites on this phone" }, ...reasonsToShow(listed, answer)],
    source: LIST_CHECK_SOURCE,
  };
}

/** How far one site's History row has got: none yet, the list's row alone, or complete. */
export type HistorySaved = "nothing" | "list" | "final";

/** What to write to History now, and how far the row has got once it is written. */
export type HistoryStep =
  | { write: "none" }
  | { write: "insert" | "update"; row: HistoryRow; saved: HistorySaved };

/**
 * The History write one site needs now. `listed` is undefined while the list
 * is being read; `answer` is undefined while the server has not answered and
 * null when it failed.
 *
 * A listed site is saved the moment the list answers: its verdict is on
 * screen at once, and people close it long before a slow server check ends —
 * a row that waited for the server was lost with the screen. The row is then
 * filled in with the server's score and reasons if they come. Any other site
 * is saved once the server answers.
 */
export function historyStep(
  domain: string,
  listed: string | null | undefined,
  answer: ServerAnswer | null | undefined,
  saved: HistorySaved,
): HistoryStep {
  if (saved === "final" || listed === undefined) return { write: "none" };
  if (listed) {
    if (saved === "nothing") {
      return { write: "insert", row: listedRecord(domain, listed, answer ?? null), saved: answer ? "final" : "list" };
    }
    return answer ? { write: "update", row: listedRecord(domain, listed, answer), saved: "final" } : { write: "none" };
  }
  const row = answer ? historyRecord(domain, null, answer) : null;
  return row ? { write: "insert", row, saved: "final" } : { write: "none" };
}

/**
 * One automatic retry, on a timeout only. A site's first check can take the
 * server ten seconds; by the time the phone gives up, the answer is usually
 * cached and the second request returns in milliseconds. Any other failure is
 * final — retrying a rate limit only digs deeper.
 */
export async function retryOnceOnTimeout<T extends { error: { kind: string } | null }>(
  attempt: () => Promise<T>,
): Promise<T> {
  const first = await attempt();
  return first.error?.kind === "timeout" ? attempt() : first;
}
