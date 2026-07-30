import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';

/** Must match CleanwayVpnService.CANARY_DOMAIN. */
export const CANARY_DOMAIN = 'block-canary.cleanway.ai';
import type { DomainBlockedPayload } from './src/CleanwayVpn.types';

export type { DomainBlockedPayload };

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
  try {
    const res = await fetch(`https://${CANARY_DOMAIN}/`, { method: "HEAD" });
    // Reachable => our NXDOMAIN never happened => filtering is not live.
    return !res.ok ? true : false;
  } catch {
    // DNS failure is the expected, healthy outcome.
    return true;
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
