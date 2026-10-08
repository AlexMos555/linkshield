/**
 * useMessageCheck — check one pasted or shared message.
 *
 * 1. The text goes to the native analyzer (analyzeMessage), which reads it on
 *    the phone and drops it: links against the on-device blocklist, wording
 *    against the known scam shapes. Its verdict shows at once.
 * 2. Up to MAX_SERVER_CHECKS link hosts the list knows nothing about go, in
 *    parallel, to the domain-only server check — the host alone, never the
 *    text and never the link's path. Each answer can only raise the verdict.
 * 3. When those settle, one history row is saved: verdict, reason codes and
 *    link hosts. No text. "Check the links again" asks only about the hosts
 *    that failed, and rewrites that same row.
 *
 * The text is an argument here and nowhere else: not in state, not logged.
 */
import { useCallback, useRef, useState } from "react";
import * as Haptics from "expo-haptics";

import {
  analyzeMessage,
  noteCallEvent,
  type MessageAnalysis,
  type MessageVerdict,
} from "../../modules/cleanway-vpn";
import { saveMessageCheck, updateMessageCheck } from "../services/database";
import { checkMessageHost } from "../services/message-link-check";
import {
  historyEntry,
  isEscalation,
  listOnlyVerdict,
  mergeVerdict,
  pendingHosts,
  planServerChecks,
  type LinkCheck,
  type MergedVerdict,
  type MessageCheckReason,
} from "../utils/message-verdict";

type LinkChecks = Readonly<Record<string, LinkCheck>>;

/** The finished check, kept for a retry of its links. Never the text. */
type Finished = { analysis: MessageAnalysis; linkChecks: LinkChecks; row: Promise<number | null> };

export type MessageCheckState =
  | { phase: "idle" }
  | { phase: "checking" }
  /** "unsupported": no analyzer in this build. "failed": it threw. Never read either as "fine". */
  | { phase: "unavailable"; reason: "unsupported" | "failed" }
  | {
      phase: "done";
      analysis: MessageAnalysis;
      /** Server answers by host, for the links planServerChecks() picked. */
      linkChecks: Readonly<Record<string, LinkCheck>>;
      verdict: MessageVerdict;
      reasons: MessageCheckReason[];
      /** The free plan's daily limit: the scam list's verdict only (listOnlyVerdict), no detailed analysis. */
      locked?: boolean;
    };

/**
 * Asks the server about [hosts] in parallel. Each answer can only raise the
 * verdict; [onAnswer] sees every step so the screen updates as they arrive.
 */
async function askServer(
  analysis: MessageAnalysis,
  start: LinkChecks,
  hosts: readonly string[],
  onAnswer: (linkChecks: LinkChecks, merged: MergedVerdict, before: MessageVerdict) => void,
): Promise<{ linkChecks: LinkChecks; merged: MergedVerdict }> {
  let linkChecks = start;
  let merged = mergeVerdict(analysis, linkChecks);
  await Promise.all(hosts.map(async (host) => {
    const answer = await checkMessageHost(host);
    const before = merged.verdict;
    linkChecks = { ...linkChecks, [host]: answer };
    merged = mergeVerdict(analysis, linkChecks);
    onAnswer(linkChecks, merged, before);
  }));
  return { linkChecks, merged };
}

/** Best-effort, like the link check: the verdict on screen is what matters. */
function saveRow(analysis: MessageAnalysis, merged: MergedVerdict): Promise<number | null> {
  return saveMessageCheck(historyEntry(analysis.links, merged)).catch(() => null);
}

/**
 * A message that turned dangerous only through the server's answer about a
 * link: the native analyzer told the after-call notice (CallGuard.kt) about
 * its own dangerous verdicts already; this covers the rest. Only the fact —
 * never the text, never a host — crosses the bridge.
 */
function noteIfServerMadeItDangerous(onDevice: MessageVerdict, merged: MessageVerdict): void {
  if (onDevice !== "dangerous" && merged === "dangerous") noteCallEvent("message_dangerous");
}

/** Same feel as the link check (shared.tsx) — except that no signals is not "safe", so no success buzz. */
function buzz(verdict: MessageVerdict): void {
  if (verdict === "dangerous") void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
  else if (verdict === "caution") void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
  else void Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
}

export function useMessageCheck() {
  const [state, setState] = useState<MessageCheckState>({ phase: "idle" });
  // Each check gets a number; answers from an older one never touch the screen.
  const run = useRef(0);
  const last = useRef<Finished | null>(null);

  /** [detailed] false: the free plan's daily limit is spent — the scam list's verdict only. */
  const check = useCallback(async (text: string, detailed: boolean = true) => {
    const id = ++run.current;
    const current = () => id === run.current;
    last.current = null;
    setState({ phase: "checking" });

    const result = await analyzeMessage(text);
    if (!result.available) {
      if (current()) {
        setState({ phase: "unavailable", reason: result.reason });
        void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
      }
      return;
    }
    const { available: _available, ...analysis } = result;

    if (!detailed) {
      // No wording reasons, no legit shape, no server check: what the list
      // says about the links is all that shows. A listed link is still
      // "dangerous", buzzes and reaches History, as it does on a paid plan.
      const listOnly = listOnlyVerdict(analysis.links);
      const shown: MessageAnalysis = {
        ...analysis,
        verdict: listOnly.verdict,
        reasons: listOnly.verdict === "dangerous" ? ["link_blocklisted"] : [],
        legitShape: null,
      };
      if (current()) {
        setState({ phase: "done", analysis: shown, linkChecks: {}, ...listOnly, locked: true });
        buzz(listOnly.verdict);
      }
      if (listOnly.verdict === "dangerous") await saveRow(shown, listOnly);
      return;
    }

    const plan = planServerChecks(analysis.links);
    const first = mergeVerdict(analysis, plan);
    if (current()) {
      setState({ phase: "done", analysis, linkChecks: plan, ...first });
      buzz(first.verdict);
    }

    const { linkChecks, merged } = await askServer(analysis, plan, pendingHosts(plan), (checks, next, before) => {
      if (!current()) return;
      setState({ phase: "done", analysis, linkChecks: checks, ...next });
      if (isEscalation(before, next.verdict)) buzz(next.verdict);
    });
    noteIfServerMadeItDangerous(analysis.verdict, merged.verdict);

    // Saved even if the person already moved on: the check did happen.
    const row = saveRow(analysis, merged);
    if (current()) last.current = { analysis, linkChecks, row };
    await row;
  }, []);

  /** Ask again about the links whose check failed (offline, rate limit…), and update the same history row. */
  const retryLinks = useCallback(async () => {
    const prev = last.current;
    if (!prev) return;
    const id = ++run.current;
    const current = () => id === run.current;
    const failed = Object.keys(prev.linkChecks).filter((h) => prev.linkChecks[h].kind === "failed");
    const start: LinkChecks = {
      ...prev.linkChecks,
      ...Object.fromEntries(failed.map((h): [string, LinkCheck] => [h, { kind: "pending" }])),
    };
    setState({ phase: "done", analysis: prev.analysis, linkChecks: start, ...mergeVerdict(prev.analysis, start) });

    const { linkChecks, merged } = await askServer(prev.analysis, start, failed, (checks, next, before) => {
      if (!current()) return;
      setState({ phase: "done", analysis: prev.analysis, linkChecks: checks, ...next });
      if (isEscalation(before, next.verdict)) buzz(next.verdict);
    });
    noteIfServerMadeItDangerous(mergeVerdict(prev.analysis, prev.linkChecks).verdict, merged.verdict);

    const rowId = await prev.row;
    const row = rowId === null
      ? saveRow(prev.analysis, merged)
      : updateMessageCheck(rowId, historyEntry(prev.analysis.links, merged)).then(() => rowId, () => rowId);
    if (current()) last.current = { analysis: prev.analysis, linkChecks, row };
    await row;
  }, []);

  const reset = useCallback(() => {
    run.current += 1;
    last.current = null;
    setState({ phase: "idle" });
  }, []);

  return { state, check, retryLinks, reset };
}
