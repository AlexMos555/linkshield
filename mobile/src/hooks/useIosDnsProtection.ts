import { useCallback, useEffect, useRef, useState } from "react";
import { AppState } from "react-native";

import {
  addIosDnsChangedListener, installIosDns, iosDnsStatus, isIosDnsSupported, removeIosDns,
} from "../../modules/cleanway-vpn";
import type { IosDnsReport } from "../../modules/cleanway-vpn";
import {
  INITIAL_IOS_DNS, iosDnsFinished, iosDnsLayerStatus, iosDnsPhase, iosDnsStarted,
  type IosDnsAction, type IosDnsPhase, type IosDnsState,
} from "../utils/ios-dns";
import type { IosLayerStatus } from "../utils/platform-features";

// The last answer survives a remount (tab switch), so the card does not
// flash "Set up" over a layer that is on while iOS is asked again.
let lastKnown: IosDnsState | null = null;

export interface IosDnsProtection {
  state: IosDnsState;
  phase: IosDnsPhase;
  /** For iosProtectionLayers({ dns }). */
  layer: IosLayerStatus;
  install: () => Promise<void>;
  remove: () => Promise<void>;
  refresh: () => Promise<void>;
}

/**
 * The iPhone's DNS protection, live: read from iOS on mount, on every return
 * to the foreground (the person comes back from Settings) and when iOS posts
 * that the configuration changed. Inert on Android and on builds without it.
 */
export function useIosDnsProtection(): IosDnsProtection {
  const [state, setState] = useState<IosDnsState>(
    () => lastKnown ?? { ...INITIAL_IOS_DNS, supported: isIosDnsSupported() },
  );
  const mounted = useRef(true);

  const run = useCallback(async (action: IosDnsAction, call: () => Promise<IosDnsReport | null>) => {
    setState((s) => iosDnsStarted(s, action));
    const report = await call();
    if (!mounted.current) return;
    setState((s) => {
      const next = iosDnsFinished(s, action, report);
      lastKnown = next;
      return next;
    });
  }, []);

  const refresh = useCallback(() => run("status", iosDnsStatus), [run]);
  const install = useCallback(() => run("install", installIosDns), [run]);
  const remove = useCallback(() => run("remove", removeIosDns), [run]);

  useEffect(() => {
    mounted.current = true;
    if (!isIosDnsSupported()) return () => { mounted.current = false; };
    void refresh();
    const app = AppState.addEventListener("change", (s) => {
      if (s === "active") void refresh();
    });
    const changed = addIosDnsChangedListener(() => void refresh());
    return () => {
      mounted.current = false;
      app.remove();
      changed.remove();
    };
  }, [refresh]);

  const phase = iosDnsPhase(state);
  return { state, phase, layer: iosDnsLayerStatus(phase), install, remove, refresh };
}
