import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";

interface ShieldLogModule {
  shieldBlockTotals(sinceMs?: number): { blocked: number; warned: number };
  addDomainBlockedListener?(cb: () => void): { remove(): void };
}

function loadModule(): ShieldLogModule | null {
  if (Platform.OS !== "android") return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../modules/cleanway-vpn") as ShieldLogModule;
  } catch {
    return null;
  }
}

/**
 * Totals from the DNS shield's persisted block log — "blocked" (site never
 * opened) and "warned" (verdict came after the first lookup; future ones
 * blocked). Refreshes on foreground and live on each block event, so the
 * number a person sees is what the service actually did, app open or not.
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
