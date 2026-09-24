import { useCallback, useEffect, useRef, useState } from "react";
import { AppState, Platform } from "react-native";
import { useFocusEffect } from "expo-router";

import { getRecentChecks } from "../services/database";
import { recentShieldBlocks } from "../services/shield-log";
import { mergeHistory, shieldGaps, type HistoryGaps, type HistoryItem } from "../utils/history-model";

/** SQLite rows read per load. */
const CHECK_LIMIT = 200;
/** The whole block log: it keeps at most 200 events (BlockLog.DEFAULT_CAP). */
const SHIELD_LIMIT = 200;

interface BlockEventsModule {
  addDomainBlockedListener?(cb: () => void): { remove(): void };
  shieldBlockTotals?(): { blocked: number; warned: number };
}

const NO_GAPS: HistoryGaps = { checksFull: false, shieldBlocked: false, shieldWarned: false };

/** The lifetime counters behind the home numbers; zeros on an older native build. */
function readTotals(mod: BlockEventsModule | null): { blocked: number; warned: number } {
  try {
    return mod?.shieldBlockTotals?.() ?? { blocked: 0, warned: 0 };
  } catch {
    return { blocked: 0, warned: 0 };
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
  /** Re-read both stores; resolves with the fresh list (the deep link looks its site up in it). */
  reload: () => Promise<HistoryItem[]>;
}

/**
 * Everything History lists: checks from SQLite and the shields' block log,
 * merged newest first (see history-model.ts).
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
    const next = mergeHistory(checks, shield);
    if (mounted.current) {
      setItems(next);
      setGaps({ checksFull: checks.length >= CHECK_LIMIT, ...shieldGaps(shield, readTotals(mod)) });
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
