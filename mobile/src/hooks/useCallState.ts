/**
 * useCallState — is the person on the phone, or was she a moment ago?
 *
 * Reads the native snapshot (CallState.kt: the audio mode, no permission),
 * follows the module's call events while the screen is open, re-reads on
 * every foreground, and wakes itself when the 30-minute window after a call
 * closes. Where this build cannot see calls (iOS, an older native build) the
 * snapshot is null and `reason` is null: no stop screen is ever shown for a
 * call the app cannot see.
 */
import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";

import {
  applyCallEvent, guardReason, windowEndsAt, type CallSnapshot, type GuardReason,
} from "../utils/call-guard";

interface CallModule {
  callState(): CallSnapshot | null;
  addCallStateChangedListener?(cb: (p: Partial<CallSnapshot>) => void): { remove(): void };
}

function loadModule(): CallModule | null {
  if (Platform.OS !== "android") return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../modules/cleanway-vpn") as CallModule;
  } catch {
    return null;
  }
}

export interface CallStateView {
  /** Null where calls cannot be seen. */
  snapshot: CallSnapshot | null;
  /** Why the stop screen applies right now, or null. */
  reason: GuardReason | null;
  /** Re-read the native snapshot (the stop screen does this the moment it is asked to open). */
  refresh: () => GuardReason | null;
}

export function useCallState(): CallStateView {
  const [mod] = useState<CallModule | null>(loadModule);
  const [snapshot, setSnapshot] = useState<CallSnapshot | null>(() => readSnapshot(mod));
  // Bumped when the after-call window closes, so `reason` is recomputed.
  const [, setTick] = useState(0);

  const refresh = useCallback((): GuardReason | null => {
    const next = readSnapshot(mod);
    setSnapshot(next);
    return guardReason(next);
  }, [mod]);

  useEffect(() => {
    const appSub = AppState.addEventListener("change", (s) => {
      if (s === "active") refresh();
    });
    const callSub = mod?.addCallStateChangedListener?.((event) => {
      setSnapshot((prev) => applyCallEvent(prev, event));
    });
    return () => {
      appSub.remove();
      callSub?.remove();
    };
  }, [mod, refresh]);

  // The window closes by itself; recompute then, not on the next foreground.
  const endsAt = windowEndsAt(snapshot);
  useEffect(() => {
    if (endsAt <= 0) return;
    const wait = endsAt - Date.now() + 500;
    if (wait <= 0) return;
    const timer = setTimeout(() => setTick((n) => n + 1), wait);
    return () => clearTimeout(timer);
  }, [endsAt]);

  return { snapshot, reason: guardReason(snapshot), refresh };
}

function readSnapshot(mod: CallModule | null): CallSnapshot | null {
  if (!mod) return null;
  try {
    return mod.callState();
  } catch {
    return null;
  }
}
