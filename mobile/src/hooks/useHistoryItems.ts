import { useCallback, useEffect, useRef, useState } from "react";
import { AppState, Platform } from "react-native";
import { useFocusEffect } from "expo-router";

import { getRecentChecks } from "../services/database";
import { recentShieldBlocks } from "../services/shield-log";
import {
  mergeHistory, shieldGaps, smsAlertGap, type HistoryGaps, type HistoryItem,
} from "../utils/history-model";
import type { SmsAlertEvent, SmsShieldStatus } from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/** SQLite rows read per load. */
const CHECK_LIMIT = 200;
/** The whole block log: it keeps at most 200 events (BlockLog.DEFAULT_CAP). */
const SHIELD_LIMIT = 200;
/** The whole SMS event log: it keeps at most 200 events (SmsEvents.DEFAULT_CAP). */
const SMS_ALERT_LIMIT = 200;

interface BlockEventsModule {
  addDomainBlockedListener?(cb: () => void): { remove(): void };
  shieldBlockTotals?(): { blocked: number; warned: number };
  recentSmsEvents?(limit?: number): SmsAlertEvent[];
  smsShieldStatus?(): SmsShieldStatus;
}

const NO_GAPS: HistoryGaps = { checksFull: false, shieldBlocked: false, shieldWarned: false, smsAlerts: false };

/** The lifetime counters behind the home numbers; zeros on an older native build. */
function readTotals(mod: BlockEventsModule | null): { blocked: number; warned: number } {
  try {
    return mod?.shieldBlockTotals?.() ?? { blocked: 0, warned: 0 };
  } catch {
    return { blocked: 0, warned: 0 };
  }
}

/**
 * What the automatic SMS check flagged (RuStore build), read fresh every time:
 * the ":sms" process writes it, and nothing tells this one when. Empty in
 * every other build and on error.
 */
function readSmsAlerts(mod: BlockEventsModule | null): SmsAlertEvent[] {
  try {
    return mod?.recentSmsEvents?.(SMS_ALERT_LIMIT) ?? [];
  } catch {
    return [];
  }
}

/** Is the SMS event log listing fewer flagged SMS than were ever flagged? Only asked when it lists any. */
function readSmsAlertGap(mod: BlockEventsModule | null, listed: number): boolean {
  if (listed === 0) return false;
  try {
    return smsAlertGap(listed, mod?.smsShieldStatus?.().flaggedCount ?? 0);
  } catch {
    return false;
  }
}

function loadModule(): BlockEventsModule | null {
  if (Platform.OS !== "android") return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../modules/cleanway-vpn") as BlockEventsModule;
  } catch {
    return null;
  }
}

export interface HistoryItems {
  items: HistoryItem[];
  loading: boolean;
  refreshing: boolean;
  /** What the stores could not list — older checks, or shield events past the log (isTruncated). */
  gaps: HistoryGaps;
  /** Pull-to-refresh. */
  refresh: () => void;
  /** Re-read every store; resolves with the fresh list (a deep link looks its site or SMS up in it). */
  reload: () => Promise<HistoryItem[]>;
}

/**
 * Everything History lists: checks from SQLite, the shields' block log and
 * the automatic SMS check's warnings, merged newest first (see
 * history-model.ts).
 *
 * Re-read whenever the tab comes into view, when the app returns to the
 * foreground, and on every new block event. The tab stays mounted once
 * opened, and the first version read only on mount — so a site blocked
 * after that first visit never appeared until a pull-to-refresh, and History
 * looked like it recorded nothing.
 */
export function useHistoryItems(): HistoryItems {
  const [mod] = useState<BlockEventsModule | null>(loadModule);
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [gaps, setGaps] = useState<HistoryGaps>(NO_GAPS);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const reload = useCallback(async () => {
    const checks = await getRecentChecks(CHECK_LIMIT).catch(() => []);
    const shield = recentShieldBlocks(SHIELD_LIMIT);
    const alerts = readSmsAlerts(mod);
    const next = mergeHistory(checks, shield, alerts);
    if (mounted.current) {
      setItems(next);
      setGaps({
        checksFull: checks.length >= CHECK_LIMIT,
        ...shieldGaps(shield, readTotals(mod)),
        smsAlerts: readSmsAlertGap(mod, alerts.length),
      });
      setLoading(false);
      setRefreshing(false);
    }
    return next;
  }, [mod]);

  const refresh = useCallback(() => {
    setRefreshing(true);
    void reload();
  }, [reload]);

  useFocusEffect(useCallback(() => {
    void reload();
  }, [reload]));

  useEffect(() => {
    const appSub = AppState.addEventListener("change", (state) => {
      if (state === "active") void reload();
    });
    const blockSub = mod?.addDomainBlockedListener?.(() => void reload());
    return () => {
      appSub.remove();
      blockSub?.remove();
    };
  }, [mod, reload]);

  return { items, loading, refreshing, gaps, refresh, reload };
}
