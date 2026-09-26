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
 */
import { useCallback, useEffect, useRef, useState } from "react";
import * as Haptics from "expo-haptics";

import { checkDomain, type ApiError, type PublicCheckResult } from "../services/api";
import { saveCheck } from "../services/database";
import { matchBlocklist } from "../../modules/cleanway-vpn";
import { historyRecord, isNotFound, shownLevel } from "../utils/check-verdict";

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

export function useDomainCheck(domain: string | null, record: boolean): DomainCheck {
  const [listed, setListed] = useState<string | null | undefined>(undefined);
  const [result, setResult] = useState<PublicCheckResult | null>(null);
  const [error, setError] = useState<ApiError["kind"] | null>(null);
  const [pending, setPending] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const savedFor = useRef<string | null>(null);
  const buzzedFor = useRef<string | null>(null);

  const retry = useCallback(() => setAttempt((a) => a + 1), []);

  useEffect(() => {
    let alive = true;
    setListed(undefined);
    if (!domain) {
      setListed(null);
      return;
    }
    void matchBlocklist(domain).then((hit) => {
      if (alive) setListed(hit);
    });
    return () => {
      alive = false;
    };
  }, [domain]);

  useEffect(() => {
    if (!domain) {
      setPending(false);
      return;
    }
    let alive = true;
    setPending(true);
    setError(null);
    setResult(null);
    void (async () => {
      try {
        // Result-based call so the error KIND survives: a rate limit, a slow
        // server and no connection each get their own honest sentence.
        const { data, error: apiError } = await checkDomain(domain);
        if (!alive) return;
        if (data) setResult(data);
        else setError(apiError?.kind ?? "network");
      } catch {
        if (alive) setError("network");
      } finally {
        if (alive) setPending(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [domain, attempt]);

  // One History row per site, once both answers are in (a failed server
  // check of a listed site is still a check: the list answered it).
  useEffect(() => {
    if (!record || !domain || listed === undefined || pending || savedFor.current === domain) return;
    const row = historyRecord(domain, listed, result);
    if (!row) return;
    savedFor.current = domain;
    // Best-effort: the verdict on screen is what matters.
    void saveCheck(row).catch(() => undefined);
  }, [record, domain, listed, pending, result]);

  // One buzz per site, at the first verdict — for a listed site that is the
  // list's, before the server has said anything.
  useEffect(() => {
    if (!domain || listed === undefined || buzzedFor.current === domain) return;
    const level = shownLevel(listed, result);
    if (!level) return;
    buzzedFor.current = domain;
    if (!listed && isNotFound(result)) {
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      return;
    }
    void Haptics.notificationAsync(
      level === "dangerous" ? Haptics.NotificationFeedbackType.Error
      : level === "caution" ? Haptics.NotificationFeedbackType.Warning
      : Haptics.NotificationFeedbackType.Success,
    );
  }, [domain, listed, result]);

  return { listed, result, error, pending, retry };
}
