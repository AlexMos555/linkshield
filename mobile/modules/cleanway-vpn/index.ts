import { useCallback, useEffect, useState } from 'react';
import { AppState } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';

/** Must match CleanwayVpnService.CANARY_DOMAIN. */
export const CANARY_DOMAIN = 'block-canary.cleanway.ai';

/** Overall probe deadline and the poll cadence within it. */
const CANARY_DEADLINE_MS = 2500;
const CANARY_POLL_MS = 150;
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
 * Ask the service for PROOF, don't infer it from a failure: read the
 * service's canary-answer counter, trigger a DNS lookup of a RANDOM subdomain
 * of the canary, and poll until the counter moves. Only a query that actually
 * transited our tunnel can move it, so a dead tunnel, a device with no DNS at
 * all, and a competing VPN all fail to produce proof — and none of them can
 * fabricate it.
 *
 * Three hardenings over the first stamp-based version, each from a confirmed
 * finding:
 *  - RANDOM LABEL: the OS resolver caches answers; a repeat lookup of the
 *    same name can be satisfied from cache without any packet reaching the
 *    tunnel, and the probe would fail on a healthy shield. A fresh label per
 *    probe cannot be cached.
 *  - COUNTER DELTA, not timestamps: the stamp compared Date.now() (JS) with
 *    System.currentTimeMillis() (Kotlin) — two steppable wall clocks. A
 *    monotonic counter delta has no clock semantics.
 *  - DEADLINE + POLL instead of a fixed sleep: the fetch itself gets an
 *    abort, the probe resolves as soon as proof arrives (usually well under
 *    a second) and gives up at CANARY_DEADLINE_MS instead of hanging on a
 *    network where the request never completes.
 */
export async function verifyFiltering(): Promise<boolean> {
  // Older native builds do not expose the counter. Report unverified rather
  // than falling back to a guess — never claim protection we cannot prove.
  if (typeof CleanwayVpn.canaryAnswerCount !== 'function') return false;

  let before: number;
  try {
    before = CleanwayVpn.canaryAnswerCount();
  } catch {
    return false;
  }

  // Fire the lookup and deliberately do not await it: its HTTP outcome proves
  // nothing (the name never resolves), it exists only to put a DNS query on
  // the wire. The abort keeps it from lingering past the probe.
  const abort = new AbortController();
  const abortTimer = setTimeout(() => abort.abort(), CANARY_DEADLINE_MS);
  const label = Math.random().toString(36).slice(2, 10);
  fetch(`https://${label}.${CANARY_DOMAIN}/`, { method: 'HEAD', signal: abort.signal })
    .catch(() => { /* expected — the whole point is that this cannot resolve */ });

  try {
    const deadline = Date.now() + CANARY_DEADLINE_MS;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, CANARY_POLL_MS));
      try {
        if (CleanwayVpn.canaryAnswerCount() > before) return true;
      } catch {
        return false;
      }
    }
    return false;
  } finally {
    clearTimeout(abortTimer);
    abort.abort();
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

/**
 * Did the user last leave the shield ON? False on older native builds, which
 * degrades to the ordinary "set up" flow.
 */
export function wasUserEnabled(): boolean {
  try {
    return typeof CleanwayVpn.wasUserEnabled === 'function' && CleanwayVpn.wasUserEnabled();
  } catch {
    return false;
  }
}

/**
 * Hostname of the device's strict Private DNS provider, or null when the
 * setting is Off/Automatic. Strict + our tunnel = no DNS for any app on the
 * phone (verified: `PrivateDnsBroken`, strict never falls back to plaintext),
 * so the app must not start the shield while this is non-null, and must show
 * the specific setting to change instead. Null on older native builds.
 */
export function privateDnsStrictHost(): string | null {
  try {
    return typeof CleanwayVpn.privateDnsStrictHost === 'function'
      ? CleanwayVpn.privateDnsStrictHost()
      : null;
  } catch {
    return null;
  }
}

/** Opens the settings screen where Private DNS lives. False if none exists. */
export function openPrivateDnsSettings(): boolean {
  try {
    return typeof CleanwayVpn.openPrivateDnsSettings === 'function' && CleanwayVpn.openPrivateDnsSettings();
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
