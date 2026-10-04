import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { Modal } from "react-native";
import { noteCallEvent } from "../../../modules/cleanway-vpn";
import { useCallState } from "../../hooks/useCallState";
import type { GuardReason, GuardedActionKind } from "../../utils/call-guard";
import { CallGuardScreen } from "./CallGuardScreen";

interface CallGuardApi {
  /**
   * Run [action] — unless the person is on the phone or was within the last
   * 30 minutes: then the stop screen comes first, and [action] runs only if
   * she takes the slow path through it. Where calls cannot be seen (iOS, an
   * older native build) the action simply runs.
   *
   * [kind] names what is being guarded; it is the hook for the VPN
   * exclusion picker (#60): `guard("exclude_app", openPicker)`.
   */
  guard: (kind: GuardedActionKind, action: () => void) => void;
  /** Why the stop screen would apply right now, or null. */
  reason: GuardReason | null;
}

const CallGuardContext = createContext<CallGuardApi>({ guard: (_kind, action) => action(), reason: null });

/**
 * One stop screen for the whole app, above every route (a Modal), so each
 * guarded action asks the same question the same way. Hosts the call-state
 * subscription while the app is open.
 */
export function CallGuardProvider({ children }: { children: ReactNode }) {
  const { reason, refresh } = useCallState();
  const [shown, setShown] = useState<GuardReason | null>(null);
  const pending = useRef<(() => void) | null>(null);

  const guard = useCallback((_kind: GuardedActionKind, action: () => void) => {
    // Re-read the snapshot now: the call may have started after the last event.
    const now = refresh();
    if (!now) {
      action();
      return;
    }
    pending.current = action;
    setShown(now);
    // Whatever was asked for — a pause, an allow, "open anyway", an app out
    // of the shield — the after-call notice names it the same way: "you
    // tried to switch protection off".
    noteCallEvent("protection_off_asked");
  }, [refresh]);

  const keep = useCallback(() => {
    pending.current = null;
    setShown(null);
  }, []);

  const proceed = useCallback(() => {
    const action = pending.current;
    pending.current = null;
    setShown(null);
    action?.();
  }, []);

  const api = useMemo<CallGuardApi>(() => ({ guard, reason }), [guard, reason]);

  return (
    <CallGuardContext.Provider value={api}>
      {children}
      <Modal visible={shown !== null} animationType="slide" onRequestClose={keep}>
        {shown !== null && <CallGuardScreen mode="intercept" reason={shown} onKeep={keep} onProceed={proceed} />}
      </Modal>
    </CallGuardContext.Provider>
  );
}

export function useCallGuard(): CallGuardApi {
  return useContext(CallGuardContext);
}
