/**
 * useDomainCheck — one site, checked two ways at once, for the link-check
 * screens (app/shared.tsx, app/result.tsx).
 *
 *  1. The on-device list (matchBlocklist): milliseconds, no network. A listed
 *     site is dangerous from the first frame — the screen does not wait for
 *     the server, and nothing the server says later can downgrade it.
 *  2. The server's domain check (checkDomain): up to ~12 s on a first check,
 *     retried once on a timeout. Its score and reasons fill in as they come.
 *
 * Folding the two is pure (src/utils/check-verdict.ts). Here: the requests,
 * one History row per check when [record] is set, and one buzz per site.
 *
 * The same screen can be handed a second site: Expo Router reuses an open
 * /shared for the next shared link and only changes its params
 * (scripts/test-domain-check-hook.mjs). So every answer is tagged with the
 * site it is about. The screen never shows one site's verdict under another's
 * name, and History files each answer under its own site — including one
 * that arrives after the screen moved on or closed.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import * as Haptics from "expo-haptics";

import { checkDomain, type ApiError, type PublicCheckResult } from "../services/api";
import { saveCheck, updateCheck } from "../services/database";
import { matchBlocklist } from "../../modules/cleanway-vpn";
import { historyStep, isNotFound, shownLevel, type HistorySaved } from "../utils/check-verdict";

export interface DomainCheck {
  /** The listed suffix; null when the list does not have the site; undefined while it is being read. */
  listed: string | null | undefined;
  /** The server's answer, once it came. */
  result: PublicCheckResult | null;
  /** Why the server check failed, when it did. */
  error: ApiError["kind"] | null;
  /** The server check is in flight. */
  pending: boolean;
  /** Ask the server again (after a failure). */
  retry: () => void;
}

/** What the screen knows about one site; `domain` says which. */
interface SiteState {
  domain: string | null;
  listed: string | null | undefined;
  result: PublicCheckResult | null;
  error: ApiError["kind"] | null;
  pending: boolean;
}

/** Nothing known yet about [domain]: the list is being read, the server asked. */
function freshState(domain: string | null): SiteState {
  return { domain, listed: domain ? undefined : null, result: null, error: null, pending: domain !== null };
}

/** History bookkeeping for one site, independent of which site the screen shows now. */
interface SiteRecorder {
  domain: string;
  record: boolean;
  listed(hit: string | null): void;
  answered(result: PublicCheckResult | null): void;
}

function siteRecorder(domain: string, record: boolean): SiteRecorder {
  let listed: string | null | undefined;
  let answer: PublicCheckResult | null | undefined;
  let saved: HistorySaved = "nothing";
  let rowId: Promise<number | null> = Promise.resolve(null);

  const advance = () => {
    if (!record) return;
    const step = historyStep(domain, listed, answer, saved);
    if (step.write === "none") return;
    saved = step.saved;
    const { row } = step;
    // Best-effort: the verdict on screen is what matters. Writes for one site
    // run in order, so the server's details never land before the list's row.
    rowId = step.write === "insert"
      ? rowId.then(() => saveCheck(row))
      : rowId.then(async (id) => {
        if (id === null) return saveCheck(row);
        await updateCheck(id, row);
        return id;
      });
    rowId = rowId.catch(() => null);
  };

  return {
    domain,
    record,
    listed(hit) {
      listed = hit;
      advance();
    },
    answered(result) {
      answer = result;
      advance();
    },
  };
}

export function useDomainCheck(domain: string | null, record: boolean): DomainCheck {
  const [site, setSite] = useState<SiteState>(() => freshState(domain));
  const [attempt, setAttempt] = useState(0);
  const recorder = useRef<SiteRecorder | null>(null);
  const buzzedFor = useRef<string | null>(null);

  const retry = useCallback(() => setAttempt((a) => a + 1), []);

  // In the render where the screen is handed a new site, the state still
  // holds the previous one's answers: show the new site as "checking", never
  // the old verdict under the new name.
  const shown = site.domain === domain ? site : freshState(domain);

  /** Apply [patch] only while the state is still about [forDomain]. */
  const update = useCallback((forDomain: string, patch: Partial<SiteState>) => {
    setSite((s) => (s.domain === forDomain ? { ...s, ...patch } : s));
  }, []);

  useEffect(() => {
    setSite((s) => (s.domain === domain ? s : freshState(domain)));
    if (!domain) {
      recorder.current = null;
      return;
    }
    // Re-run for the same site (a remount in development): keep its
    // bookkeeping, or the same check would be saved twice.
    const prev = recorder.current;
    const rec = prev && prev.domain === domain && prev.record === record ? prev : siteRecorder(domain, record);
    recorder.current = rec;
    let alive = true;
    void matchBlocklist(domain).then((hit) => {
      // History does not wait for the screen: it may be closed by now.
      rec.listed(hit);
      if (alive) update(domain, { listed: hit });
    });
    return () => {
      alive = false;
    };
  }, [domain, record, update]);

  useEffect(() => {
    if (!domain) return;
    const rec = recorder.current?.domain === domain ? recorder.current : null;
    let alive = true;
    update(domain, { pending: true, error: null, result: null });
    void (async () => {
      let data: PublicCheckResult | null = null;
      let failure: ApiError["kind"] | null = null;
      try {
        // Result-based call so the error KIND survives: a rate limit, a slow
        // server and no connection each get their own honest sentence.
        const { data: answer, error: apiError } = await checkDomain(domain);
        data = answer ?? null;
        if (!data) failure = apiError?.kind ?? "network";
      } catch {
        failure = "network";
      }
      rec?.answered(data);
      if (alive) update(domain, { result: data, error: failure, pending: false });
    })();
    return () => {
      alive = false;
    };
  }, [domain, attempt, record, update]);

  // One buzz per site, at the first verdict — for a listed site that is the
  // list's, before the server has said anything.
  useEffect(() => {
    if (!domain || shown.listed === undefined || buzzedFor.current === domain) return;
    const level = shownLevel(shown.listed, shown.result);
    if (!level) return;
    buzzedFor.current = domain;
    if (!shown.listed && isNotFound(shown.result)) {
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      return;
    }
    void Haptics.notificationAsync(
      level === "dangerous" ? Haptics.NotificationFeedbackType.Error
      : level === "caution" ? Haptics.NotificationFeedbackType.Warning
      : Haptics.NotificationFeedbackType.Success,
    );
  }, [domain, shown.listed, shown.result]);

  return { listed: shown.listed, result: shown.result, error: shown.error, pending: shown.pending, retry };
}
