/**
 * How the app reads its on-device SQLite store (src/services/database.ts),
 * and what a failed read means. Pure: no react-native, no expo-sqlite, so
 * mobile/scripts/test-local-store.mjs runs it under plain node.
 *
 * Why this exists (Galaxy A16, release 1.0.4, process alive for days under
 * the VPN service): every query started failing with
 *   "NativeDatabase.prepareAsync has been rejected … NullPointerException",
 * Home read "Checked: 0" and the intro tour came back mid-session.
 *
 * The old getDB() set its cached handle only AFTER openDatabaseAsync resolved,
 * so the screens that read storage on start (onboarding gate, home counters,
 * billing, freemium) each opened "cleanway.db" again. expo-sqlite gives every
 * open of the same file the SAME native connection, but on Android each JS
 * wrapper owns it: when Hermes garbage-collects one of the discarded wrappers,
 * NativeDatabase.sharedObjectDidRelease() closes the connection under the one
 * still in use, and the next JNI call throws the NPE. The dead connection also
 * stays in expo-sqlite's cache, so opening by name again returns it again.
 */

/**
 * The rejection means the native connection is gone (closed under us or
 * released), not that the SQL was wrong: reopening can fix it.
 */
export function isDeadHandleError(e: unknown): boolean {
  if (!e) return false;
  const message = String((e as { message?: unknown }).message ?? e);
  return /NullPointerException|closed resource|already released|doesn't contain valid id|ContextLost|context.*lost/i.test(
    message,
  );
}

export interface SharedHandle<DB> {
  /**
   * Runs `fn` on the one shared connection. If it fails because the
   * connection died, opens a new one and runs `fn` once more; a second
   * failure rejects. Ordinary errors reject at once and keep the connection.
   */
  use<T>(fn: (db: DB) => Promise<T>): Promise<T>;
}

/**
 * One lazily opened connection for the whole process. The open is memoised
 * as a promise, so callers that race on start share it instead of opening the
 * file again. A failed open is forgotten — the next call tries again.
 */
export function sharedHandle<DB>(open: () => Promise<DB>): SharedHandle<DB> {
  let current: Promise<DB> | null = null;

  function get(): Promise<DB> {
    if (!current) {
      const opening = open();
      current = opening;
      opening.catch(() => {
        if (current === opening) current = null;
      });
    }
    return current;
  }

  return {
    async use<T>(fn: (db: DB) => Promise<T>): Promise<T> {
      const used = get();
      const db = await used;
      try {
        return await fn(db);
      } catch (e) {
        if (!isDeadHandleError(e)) throw e;
        // Drop it only if nobody replaced it yet: of several callers failing
        // on the same dead connection, the first reopens and the rest reuse.
        if (current === used) current = null;
        return fn(await get());
      }
    },
  };
}

// ── What a failed read means ──

export const ONBOARDING_DONE_KEY = "onboarding_done";

/**
 * The intro tour is for a first run, and only a store that answered can say
 * this is one. A read that fails is NOT "never seen": it brought the tour
 * back mid-session for someone who finished it long ago.
 */
export async function onboardingNeeded(read: (key: string) => Promise<string | null>): Promise<boolean> {
  try {
    return (await read(ONBOARDING_DONE_KEY)) !== "true";
  } catch {
    return false;
  }
}

export type ActivityStats = {
  total_checks: number;
  threats_blocked: number;
  threats_warned: number;
};

/**
 * The home counters when SQLite cannot be read: the counts it last gave,
 * plus the checks that could only be kept in memory (their writes failed,
 * so SQLite never had them). Never 0 over numbers the person already saw.
 */
export function statsWhenUnreadable(lastRead: ActivityStats | null, inMemory: ActivityStats): ActivityStats {
  if (!lastRead) return inMemory;
  return {
    total_checks: lastRead.total_checks + inMemory.total_checks,
    threats_blocked: lastRead.threats_blocked + inMemory.threats_blocked,
    threats_warned: lastRead.threats_warned + inMemory.threats_warned,
  };
}
