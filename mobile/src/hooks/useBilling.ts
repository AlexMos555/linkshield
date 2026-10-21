import { useCallback, useSyncExternalStore } from "react";
import { useFocusEffect } from "expo-router";

import { type BillingState, billing } from "../services/billing";

/**
 * The subscription store for a screen: the current state, re-derived at each
 * focus so "осталось N дней" is counted from now, not from when the screen
 * first opened. Actions live on `billing` itself.
 */
export function useBilling(): BillingState {
  const state = useSyncExternalStore(billing.subscribe, billing.getState, billing.getState);
  useFocusEffect(useCallback(() => {
    billing.recompute();
  }, []));
  return state;
}
