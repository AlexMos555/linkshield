import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";

import type { ShieldState } from "../components/shield/ShieldCard";

/**
 * Network shield state for the home screen.
 *
 * The native VPN module only exists on Android (and only in a dev/prod build,
 * not in Expo Go), so it is required lazily — an import failure must degrade to
 * "not available on this platform", never crash the home screen.
 *
 * Honesty contract (docs/MOBILE_AUTO_PROTECTION.md §2.2): the shield reports ON
 * only when the tunnel is running AND the canary probe confirms filtering is
 * live. `isRunning` alone is not verification.
 */

interface VpnSubscription {
  remove(): void;
}

interface VpnModule {
  startVpn(): Promise<boolean>;
  stopVpn(): Promise<void>;
  isVpnRunning(): boolean;
  verifyFiltering(): Promise<boolean>;
  addVpnStoppedListener?(cb: () => void): VpnSubscription;
}

function loadVpn(): VpnModule | null {
  if (Platform.OS !== "android") return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../modules/cleanway-vpn") as VpnModule;
  } catch {
    return null;
  }
}

export interface NetworkShield {
  /** True when this platform has a shipped, controllable network shield. */
  available: boolean;
  state: ShieldState;
  /** Counts toward the hero only when the canary confirmed filtering. */
  verified: boolean;
  turnOn: () => Promise<void>;
  turnOff: () => Promise<void>;
}

export function useNetworkShield(): NetworkShield {
  const [vpn] = useState<VpnModule | null>(loadVpn);
  const [running, setRunning] = useState(false);
  const [verified, setVerified] = useState(false);

  const sync = useCallback(async () => {
    if (!vpn) return;
    const isUp = vpn.isVpnRunning();
    setRunning(isUp);
    setVerified(isUp ? await vpn.verifyFiltering() : false);
  }, [vpn]);

  useEffect(() => {
    void sync();
    const appSub = AppState.addEventListener("change", (s) => {
      // The OS or another VPN can tear our tunnel down while backgrounded —
      // re-verify on every foreground rather than trusting stale state.
      if (s === "active") void sync();
    });
    // A foreground transition is not enough: another VPN app can displace our
    // tunnel while the user is looking at this screen, and without this the
    // shield would keep showing green over a dead tunnel until they navigate
    // away and back.
    const stopSub = vpn?.addVpnStoppedListener?.(() => {
      setRunning(false);
      setVerified(false);
    });
    return () => {
      appSub.remove();
      stopSub?.remove();
    };
  }, [sync, vpn]);

  const turnOn = useCallback(async () => {
    if (!vpn) return;
    const ok = await vpn.startVpn();
    setRunning(ok);
    setVerified(ok ? await vpn.verifyFiltering() : false);
  }, [vpn]);

  const turnOff = useCallback(async () => {
    if (!vpn) return;
    await vpn.stopVpn();
    setRunning(false);
    setVerified(false);
  }, [vpn]);

  const state: ShieldState =
    !running ? "setup"
    : verified ? "on"
    // Running but the canary still resolves: something else (another VPN,
    // private DNS) is answering. Say so instead of claiming protection.
    : "conflict";

  return { available: vpn !== null, state, verified, turnOn, turnOff };
}
