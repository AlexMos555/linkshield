import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';
import type { DomainBlockedPayload } from './src/CleanwayVpn.types';

export type { DomainBlockedPayload };

export async function startVpn(): Promise<boolean> {
  return CleanwayVpn.startVpn();
}

export async function stopVpn(): Promise<void> {
  return CleanwayVpn.stopVpn();
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
  const [lastBlocked, setLastBlocked] = useState<DomainBlockedPayload | null>(null);

  useEffect(() => {
    const sub = CleanwayVpn.addListener('onDomainBlocked', (p) => setLastBlocked(p));
    return () => sub.remove();
  }, []);

  // Re-sync on foreground so the toggle reflects an external teardown (user revoked the
  // VPN in Settings, always-on takeover, or the OS killed the service).
  useEffect(() => {
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'active') setRunning(isVpnRunning());
    });
    return () => sub.remove();
  }, []);

  const start = useCallback(async () => {
    const ok = await CleanwayVpn.startVpn();
    // Trust the resolved boolean: the native service's isRunning flag is set asynchronously
    // and is not yet true at the moment startVpn() resolves.
    setRunning(ok);
    return ok;
  }, []);

  const stop = useCallback(async () => {
    await CleanwayVpn.stopVpn();
    setRunning(false);
  }, []);

  return { running, lastBlocked, start, stop };
}
