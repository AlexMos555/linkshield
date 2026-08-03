import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';

/** Must match CleanwayVpnService.CANARY_DOMAIN. */
export const CANARY_DOMAIN = 'block-canary.cleanway.ai';

/**
 * Control domain for the canary probe. Must resolve on any working network and
 * must NOT be in the blocklist — it separates "the filter blocked the canary"
 * from "this device has no working DNS at all".
 */
export const CONTROL_URL = 'https://api.cleanway.ai/api/v1/health';
import type { DomainBlockedPayload, VpnStoppedPayload } from './src/CleanwayVpn.types';

export type { DomainBlockedPayload, VpnStoppedPayload };

export async function startVpn(): Promise<boolean> {
  return CleanwayVpn.startVpn();
}

export async function stopVpn(): Promise<void> {
  return CleanwayVpn.stopVpn();
}

/**
 * Canary probe — the truth source for the shield's ON state.
 *
 * The service answers NXDOMAIN for this domain, so a successful resolution
 * means the tunnel is NOT filtering (or another VPN took over). The domain
 * also exists in public DNS, so "does not resolve" cannot be faked by a dead
 * network. Never claim protected on `isRunning` alone (spec §2.2).
 */
export async function verifyFiltering(): Promise<boolean> {
  // Two conditions, both required. A canary failure ALONE proves nothing: on a
  // device with no working DNS (airplane mode, captive portal, a broken
  // resolver) every lookup fails and a one-sided probe would report the shield
  // as ON while nothing is being filtered. That is the exact placebo this
  // project exists to avoid, so the control request must succeed first.
  try {
    const control = await fetch(CONTROL_URL, { method: 'GET' });
    if (!control.ok) return false; // network unusable — cannot conclude anything
  } catch {
    return false;
  }

  try {
    await fetch(`https://${CANARY_DOMAIN}/`, { method: 'HEAD' });
    // Resolved and reachable => our NXDOMAIN never happened => not filtering.
    return false;
  } catch {
    // Control worked but the canary did not: the filter is live.
    return true;
  }
}

/**
 * Subscribe to the tunnel being torn down without the user asking (revoked in
 * Settings, or another VPN app took over). Lets the UI drop its protected
 * state at the moment it stops being true.
 */
export function addVpnStoppedListener(cb: (p: VpnStoppedPayload) => void) {
  return CleanwayVpn.addListener('onVpnStopped', cb);
}

/**
 * Open the system VPN settings so the user can enable "Always-on VPN".
 * Returns false when no such screen exists on this device.
 */
export function openVpnSettings(): boolean {
  try {
    return CleanwayVpn.openVpnSettings();
  } catch {
    return false;
  }
}

export function isVpnRunning(): boolean {
  try {
    return CleanwayVpn.isRunning();
  } catch {
    return false;
  }
}

/**
 * React hook for the protection toggle. Tracks running state + the most recent
 * blocked domain (from the native onDomainBlocked event).
 */
export function useVpn() {
  const [running, setRunning] = useState<boolean>(isVpnRunning);
  const [verified, setVerified] = useState<boolean>(false);
  const [lastBlocked, setLastBlocked] = useState<DomainBlockedPayload | null>(null);

  useEffect(() => {
    const sub = CleanwayVpn.addListener('onDomainBlocked', (p) => setLastBlocked(p));
    return () => sub.remove();
  }, []);

  // Re-sync on foreground so the toggle reflects an external teardown (user revoked the
  // VPN in Settings, always-on takeover, or the OS killed the service).
  useEffect(() => {
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'active') {
        const r = isVpnRunning();
        setRunning(r);
        if (r) void verifyFiltering().then(setVerified);
        else setVerified(false);
      }
    });
    return () => sub.remove();
  }, []);

  const start = useCallback(async () => {
    const ok = await CleanwayVpn.startVpn();
    // Trust the resolved boolean: the native service's isRunning flag is set asynchronously
    // and is not yet true at the moment startVpn() resolves.
    setRunning(ok);
    if (ok) setVerified(await verifyFiltering());
    return ok;
  }, []);

  const stop = useCallback(async () => {
    await CleanwayVpn.stopVpn();
    setRunning(false);
    setVerified(false);
  }, []);

  return { running, verified, lastBlocked, start, stop };
}
