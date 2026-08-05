import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';

/** Must match CleanwayVpnService.CANARY_DOMAIN. */
export const CANARY_DOMAIN = 'block-canary.cleanway.ai';

/** Give the lookup a moment to reach the service and be answered. */
const CANARY_SETTLE_MS = 1200;
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
 * Ask the service for PROOF, don't infer it from a failure. We note the time,
 * trigger a lookup of CANARY_DOMAIN, then ask the native side whether it
 * answered a canary query after that instant. Only a query that actually
 * reached our tunnel can move that number.
 *
 * The previous version inferred "filtering is live" from an HTTPS request to
 * the canary throwing, gated behind a control request to the API. Both halves
 * were broken, in opposite directions:
 *
 *   - the control URL was https://api.cleanway.ai/api/v1/health, which is a
 *     404 (the route is /health, unprefixed). So the gate never opened, this
 *     function returned false forever, and a genuinely filtering tunnel was
 *     displayed as "needs attention" with a button that turns it off.
 *
 *   - had only that been fixed, the canary fetch would throw anyway, because
 *     block-canary.cleanway.ai does not exist in public DNS. `catch => true`
 *     would then report protected on any networked device, including when
 *     another VPN app had displaced our tunnel. A permanent false green — the
 *     exact placebo this project exists to avoid.
 *
 * Positive proof has neither failure mode, and it needs no public DNS record:
 * a dead tunnel, a device with no DNS at all, and a competing VPN all fail to
 * produce a fresh stamp, and none of them can fabricate one.
 */
export async function verifyFiltering(): Promise<boolean> {
  // Older native builds do not expose the counter. Report unverified rather
  // than falling back to a guess — never claim protection we cannot prove.
  if (typeof CleanwayVpn.lastCanaryAnswerAtMs !== 'function') return false;

  const startedAt = Date.now();
  try {
    // We do not care whether this resolves or connects — it exists purely to
    // put a canary query on the wire. Its outcome proves nothing on its own.
    await fetch(`https://${CANARY_DOMAIN}/`, { method: 'HEAD' });
  } catch {
    // Expected: the service answers NXDOMAIN, so this normally throws.
  }

  await new Promise((resolve) => setTimeout(resolve, CANARY_SETTLE_MS));

  try {
    return CleanwayVpn.lastCanaryAnswerAtMs() >= startedAt;
  } catch {
    return false;
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
    const sub = CleanwayVpn.addListener(
      'onDomainBlocked',
      (p: DomainBlockedPayload) => setLastBlocked(p),
    );
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
