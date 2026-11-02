import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";

/** The module itself, so a name it does not export cannot type-check here (test-no-vpn-names.mjs). */
type ShieldLogModule = typeof import("../../modules/cleanway-vpn");

/**
 * Outside any try block on purpose: Metro keeps the path of a require()
 * written in one, even in a release bundle (test-no-vpn-names.mjs).
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const requireShieldModule = () => require("../../modules/cleanway-vpn") as ShieldLogModule;

function loadModule(): ShieldLogModule | null {
  if (Platform.OS !== "android") return null;
  try {
    return requireShieldModule();
  } catch {
    return null;
  }
}

/**
 * Totals from the shields' persisted block log — "blocked" (site never
 * opened: DNS refused it, or the link guard stopped the tapped link) and
 * "warned" (the link guard let a link open; its site was flagged after).
 * One per event, not per DNS query (BlockLog coalesces repeats). Refreshes on
 * foreground and live on each new block event, so the number a person sees
 * is what the shields actually did, app open or not.
 */
export function useShieldBlockTotals(): { blocked: number; warned: number } {
  const [mod] = useState<ShieldLogModule | null>(loadModule);
  const [totals, setTotals] = useState({ blocked: 0, warned: 0 });

  const refresh = useCallback(() => {
    if (!mod) return;
    try {
      setTotals(mod.shieldBlockTotals());
    } catch {
      /* older native build: keep zeros */
    }
  }, [mod]);

  useEffect(() => {
    refresh();
    const appSub = AppState.addEventListener("change", (s) => {
      if (s === "active") refresh();
    });
    const blockSub = mod?.addDomainBlockedListener?.(refresh);
    return () => {
      appSub.remove();
      blockSub?.remove();
    };
  }, [mod, refresh]);

  return totals;
}
