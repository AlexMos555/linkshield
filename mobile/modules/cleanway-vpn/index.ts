import { useCallback, useEffect, useState } from 'react';
import { AppState, PermissionsAndroid, Platform } from 'react-native';

import CleanwayVpn from './src/CleanwayVpnModule';

/** Must match CleanwayVpnService.CANARY_DOMAIN. */
export const CANARY_DOMAIN = 'block-canary.cleanway.ai';

/** Must match BlockList.LIST_CANARY — the line every published list carries. */
export const LIST_CANARY_DOMAIN = 'list-canary.cleanway.ai';

/** Overall probe deadline and the poll cadence within it. */
const CANARY_DEADLINE_MS = 2500;
const CANARY_POLL_MS = 150;
import type { BlocklistStatus, DomainBlockedPayload, VpnStoppedPayload, ShieldBlockEntry, ShieldBlockKind } from './src/CleanwayVpn.types';

export type { BlocklistStatus, DomainBlockedPayload, VpnStoppedPayload, ShieldBlockEntry, ShieldBlockKind };

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
  return probeCanary(CANARY_DOMAIN, () => CleanwayVpn.canaryAnswerCount?.());
}

/**
 * Second, stronger proof: that the LOADED LIST is what the DNS path blocks
 * from. `blocklistStatus()` is the service describing itself; this puts a
 * query for a random label under the list canary on the wire and waits for
 * the service's list-canary counter to move — which can only happen when the
 * loaded list actually contains the canary line and the decision path
 * consults it. A shield that shows a list count it cannot demonstrate is the
 * kind of claim this product does not make.
 */
export async function verifyListFiltering(): Promise<boolean> {
  return probeCanary(LIST_CANARY_DOMAIN, () => CleanwayVpn.listCanaryAnswerCount?.());
}

/**
 * Ask the service for PROOF, don't infer it from a failure: read a counter,
 * trigger a DNS lookup of a RANDOM subdomain, poll until the counter moves.
 * Only a query that actually transited our tunnel can move it, so a dead
 * tunnel, a device with no DNS at all, and a competing VPN all fail to
 * produce proof — and none of them can fabricate it.
 *
 * Three hardenings over the first stamp-based version, each from a confirmed
 * finding:
 *  - RANDOM LABEL: the OS resolver caches answers; a repeat lookup of the
 *    same name can be satisfied from cache without any packet reaching the
 *    tunnel, and the probe would fail on a healthy shield.
 *  - COUNTER DELTA, not timestamps: the stamp compared Date.now() (JS) with
 *    System.currentTimeMillis() (Kotlin) — two steppable wall clocks.
 *  - DEADLINE + POLL instead of a fixed sleep: resolves as soon as proof
 *    arrives, gives up at CANARY_DEADLINE_MS instead of hanging.
 */
async function probeCanary(domain: string, read: () => number | undefined): Promise<boolean> {
  let before: number | undefined;
  try {
    before = read();
  } catch {
    return false;
  }
  // Older native builds do not expose the counter. Report unverified rather
  // than falling back to a guess — never claim protection we cannot prove.
  if (typeof before !== 'number') return false;

  // Fire the lookup and deliberately do not await it: its HTTP outcome proves
  // nothing (the name never resolves), it exists only to put a DNS query on
  // the wire. The abort keeps it from lingering past the probe.
  const abort = new AbortController();
  const abortTimer = setTimeout(() => abort.abort(), CANARY_DEADLINE_MS);
  const label = Math.random().toString(36).slice(2, 10);
  fetch(`https://${label}.${domain}/`, { method: 'HEAD', signal: abort.signal })
    .catch(() => { /* expected — the whole point is that this cannot resolve */ });

  try {
    const deadline = Date.now() + CANARY_DEADLINE_MS;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, CANARY_POLL_MS));
      try {
        const now = read();
        if (typeof now === 'number' && now > before) return true;
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
/** Fires on every block/warn event from the service while JS is alive. */
export function addDomainBlockedListener(cb: (p: DomainBlockedPayload) => void) {
  return CleanwayVpn.addListener('onDomainBlocked', cb);
}

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

/**
 * The shield's persisted block log (newest first). Written by the service
 * even while no JS is alive, so "stopped 3 sites today" is true across app
 * kills and reboots. Empty on older native builds.
 */
export function recentShieldBlocks(limit = 50): ShieldBlockEntry[] {
  try {
    if (typeof CleanwayVpn.recentBlocks !== 'function') return [];
    return CleanwayVpn.recentBlocks(limit) ?? [];
  } catch {
    return [];
  }
}

/** Count of block-log entries since `sinceMs` (epoch millis). */
export function shieldBlockCountSince(sinceMs: number): number {
  try {
    return typeof CleanwayVpn.blockCountSince === 'function' ? CleanwayVpn.blockCountSince(sinceMs) : 0;
  } catch {
    return 0;
  }
}

/**
 * Lifetime blocked/warned totals (see ShieldBlockKind for the honesty split).
 *
 * Reads native lifetime counters, which live outside the 200-entry ring
 * buffer — so the number keeps growing for a heavy user instead of freezing
 * at 200. Falls back to counting the recent list on older native builds.
 */
export function shieldBlockTotals(): { blocked: number; warned: number } {
  try {
    if (typeof CleanwayVpn.blockLifetimeCounts === 'function') {
      const c = CleanwayVpn.blockLifetimeCounts() ?? {};
      return { blocked: c.blocked ?? 0, warned: c.warned ?? 0 };
    }
  } catch {
    /* fall through to the ring-buffer estimate */
  }
  const entries = recentShieldBlocks(200);
  return {
    blocked: entries.filter((e) => e.kind === 'blocked').length,
    warned: entries.filter((e) => e.kind === 'warned').length,
  };
}

/**
 * Android 13+ drops notifications unless POST_NOTIFICATIONS is granted, and
 * a block the person never hears about looks like a broken internet. Ask
 * once, right after the shield turns on — the moment the permission makes
 * sense. Never nags: a refusal is respected; the block log still records.
 */
export async function requestBlockNotificationPermission(): Promise<boolean> {
  if (Platform.OS !== 'android' || Platform.Version < 33) return true;
  try {
    const perm = PermissionsAndroid.PERMISSIONS.POST_NOTIFICATIONS;
    if (await PermissionsAndroid.check(perm)) return true;
    const res = await PermissionsAndroid.request(perm);
    return res === PermissionsAndroid.RESULTS.GRANTED;
  } catch {
    return false;
  }
}

/**
 * The blocklist the service is filtering with, and how fresh it is. On an
 * older native build (no list machinery) this reports "no list, stale" —
 * which is the truth: nothing is being blocked from a list.
 */
export function blocklistStatus(): BlocklistStatus {
  const none: BlocklistStatus = {
    version: 0, count: 0, revoked: false, ageMs: null, stale: true, hasCanary: false, lastError: null, lastFetchAt: 0,
  };
  try {
    return typeof CleanwayVpn.blocklistStatus === 'function' ? { ...none, ...CleanwayVpn.blocklistStatus() } : none;
  } catch {
    return none;
  }
}

export function refreshBlocklist(): void {
  try {
    CleanwayVpn.refreshBlocklist?.();
  } catch {
    /* older native build */
  }
}

/** Sites the person marked "not a scam", newest first. */
export function allowedDomains(): string[] {
  try {
    return CleanwayVpn.allowedDomains?.() ?? [];
  } catch {
    return [];
  }
}

/**
 * Mark a site as not-a-scam. The shield stops blocking it (and its
 * subdomains) until the person removes it. False for a name that is not a
 * domain.
 */
export function allowDomain(domain: string): boolean {
  try {
    return CleanwayVpn.allowDomain?.(domain) ?? false;
  } catch {
    return false;
  }
}

/** Undo an allow — the site can be blocked again. */
export function removeAllowedDomain(domain: string): void {
  try {
    CleanwayVpn.removeAllowedDomain?.(domain);
  } catch {
    /* older native build */
  }
}

/**
 * Open a URL in a real browser other than Cleanway (the link-guard "Open
 * anyway"). Returns false if no other browser is installed.
 */
export function openInBrowser(url: string): boolean {
  try {
    return typeof CleanwayVpn.openInBrowser === 'function' && CleanwayVpn.openInBrowser(url);
  } catch {
    return false;
  }
}

/** True when Cleanway is the default web-link handler (every tapped link is checked). */
export function isDefaultLinkHandler(): boolean {
  try {
    return typeof CleanwayVpn.isDefaultLinkHandler === 'function' && CleanwayVpn.isDefaultLinkHandler();
  } catch {
    return false;
  }
}

/** Ask the OS to make Cleanway the default link handler. Resolves false if nothing could be shown. */
export async function requestLinkHandler(): Promise<boolean> {
  try {
    return typeof CleanwayVpn.requestLinkHandler === 'function' ? await CleanwayVpn.requestLinkHandler() : false;
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
