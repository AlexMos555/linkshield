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

/** Mirror of the module's BlocklistStatus (kept structural so the hook does not import native types). */
export interface BlocklistStatusLike {
  version: number;
  count: number;
  revoked: boolean;
  ageMs: number | null;
  stale: boolean;
  hasCanary: boolean;
  lastError: string | null;
  lastFetchAt: number;
}

const NO_LIST: BlocklistStatusLike = {
  version: 0, count: 0, revoked: false, ageMs: null, stale: true, hasCanary: false, lastError: null, lastFetchAt: 0,
};

interface VpnModule {
  startVpn(): Promise<boolean>;
  stopVpn(): Promise<void>;
  isVpnRunning(): boolean;
  wasUserEnabled?(): boolean;
  privateDnsStrictHost?(): string | null;
  openPrivateDnsSettings?(): boolean;
  requestBlockNotificationPermission?(): Promise<boolean>;
  blocklistStatus?(): BlocklistStatusLike;
  refreshBlocklist?(): void;
  verifyFiltering(): Promise<boolean>;
  addVpnStoppedListener?(cb: () => void): VpnSubscription;
  openVpnSettings?(): boolean;
}

async function hasInternet(): Promise<boolean> {
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), 2500);
  try {
    // /health is the unprefixed route (see the 404 that broke the old probe).
    const r = await fetch("https://api.cleanway.ai/health", { method: "HEAD", signal: abort.signal });
    return r.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
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
  /**
   * True while a canary probe is in flight. The probe takes up to ~2.5s, and
   * without this flag the card showed its negative state for that whole
   * window — every foreground and every turn-on flashed "not confirmed" at
   * users whose protection was fine. The screen shows "checking…" instead.
   */
  probing: boolean;
  /**
   * True when the last probe failed AND the device could not reach the
   * internet at all. Filtering genuinely cannot be proven offline (there is
   * nothing to filter), but "0 shields active" on a plane reads as "broken".
   * Distinguished so the card can say "no internet right now" instead.
   */
  offline: boolean;
  /**
   * The user had the shield ON and it is not running now — a reboot without
   * always-on, an OEM battery manager, a force-stop. Nothing turned it off on
   * purpose, so it must not read as "never set up": the hero says protection
   * stopped, and one tap brings it back.
   */
  interrupted: boolean;
  /**
   * Hostname of the phone's strict Private DNS provider, or null. Non-null
   * means the shield CANNOT run: strict DoT + our tunnel = no DNS for any
   * app on the phone (verified 2026-08-18 — `ping example.com` → unknown
   * host while the shield showed "offline"). The service refuses to start
   * and steps aside if the setting flips while running; the card shows the
   * setting to change and a button that opens it.
   */
  privateDnsHost: string | null;
  openPrivateDnsSettings: () => void;
  /**
   * The blocklist the tunnel is filtering with. `stale` (no list, or older
   * than 24h) means listed-site protection is NOT active even while the
   * tunnel is green — the card shows it as its own honest line, never folded
   * into "You're protected".
   */
  blocklist: BlocklistStatusLike;
  refreshBlocklist: () => void;
  turnOn: () => Promise<void>;
  turnOff: () => Promise<void>;
  /**
   * Opens Settings → VPN for "Always-on VPN". The shield already returns by
   * itself after a reboot (verified 2026-08-18: BootReceiver → tunnel →
   * canary-green with no tap). Always-on closes the remaining gap: the system
   * starts it with the phone, before BOOT_COMPLETED reaches any app.
   */
  openVpnSettings: () => void;
}

export function useNetworkShield(): NetworkShield {
  const [vpn] = useState<VpnModule | null>(loadVpn);
  const [running, setRunning] = useState(false);
  const [verified, setVerified] = useState(false);
  const [probing, setProbing] = useState(false);
  const [offline, setOffline] = useState(false);
  const [interrupted, setInterrupted] = useState(false);
  const [privateDnsHost, setPrivateDnsHost] = useState<string | null>(null);
  const [blocklist, setBlocklist] = useState<BlocklistStatusLike>(NO_LIST);

  const readBlocklist = useCallback(() => {
    if (!vpn) return;
    try {
      setBlocklist(vpn.blocklistStatus?.() ?? NO_LIST);
    } catch {
      setBlocklist(NO_LIST);
    }
  }, [vpn]);

  const sync = useCallback(async () => {
    if (!vpn) return;
    // Read the setting first: it decides whether anything below can be
    // trusted. With strict Private DNS on, a running tunnel means a phone
    // with no DNS, and a failed probe means nothing about our filtering.
    setPrivateDnsHost(vpn.privateDnsStrictHost?.() ?? null);
    const isUp = vpn.isVpnRunning();
    setRunning(isUp);
    readBlocklist();
    if (!isUp) {
      setVerified(false);
      setProbing(false);
      // Not running — but did the user WANT it running? That is the difference
      // between "set up" and "it stopped; turn it back on".
      setInterrupted(vpn.wasUserEnabled?.() === true);
      return;
    }
    setInterrupted(false);
    // The probe takes a second or so. Without this flag the card sat in its
    // negative state for the whole window, so every single foreground flashed
    // an alarm at a user whose protection was fine.
    setProbing(true);
    try {
      const ok = await vpn.verifyFiltering();
      setVerified(ok);
      // A failed probe has two very different meanings. If our own API is
      // unreachable too, the device is offline and the honest message is
      // "no internet", not "we couldn't confirm filtering". Cheap HEAD, short
      // timeout; only consulted on the failure path.
      setOffline(ok ? false : !(await hasInternet()));
    } finally {
      setProbing(false);
    }
  }, [vpn, readBlocklist]);

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
      // The service also stops itself when Private DNS flips to strict; a
      // full sync picks up the reason (the setting) so the card can say why.
      void sync();
    });
    return () => {
      appSub.remove();
      stopSub?.remove();
    };
  }, [sync, vpn]);

  const turnOn = useCallback(async () => {
    if (!vpn) return;
    // Never even ask for consent while strict Private DNS is on: the service
    // would refuse anyway, and the user would have granted a permission for
    // nothing. Surface the setting instead.
    const strictHost = vpn.privateDnsStrictHost?.() ?? null;
    setPrivateDnsHost(strictHost);
    if (strictHost) return;
    const ok = await vpn.startVpn();
    setRunning(ok);
    if (!ok) {
      setVerified(false);
      return;
    }
    // startVpn resolves when consent lands, not when the tunnel is up —
    // establish() and the proxy-loop start happen asynchronously in the
    // service. Give the tunnel a beat before probing so a healthy turn-on
    // does not begin with a doomed probe, and show "checking…" meanwhile.
    setProbing(true);
    try {
      await new Promise((r) => setTimeout(r, 400));
      setVerified(await vpn.verifyFiltering());
    } finally {
      setProbing(false);
    }
    // The service loads the stored list at start and fetches if it is old;
    // read what it has, and read again a few seconds later so a first-ever
    // sync shows up without a foreground round-trip.
    readBlocklist();
    setTimeout(readBlocklist, 6000);
    // Now that protection is on, ask to be allowed to say when it stops a
    // site (Android 13+ drops notifications otherwise). After the probe so
    // the green state is not delayed by a dialog; result deliberately
    // ignored — a refusal is respected and the block log still records.
    void vpn.requestBlockNotificationPermission?.();
  }, [vpn, readBlocklist]);

  const turnOff = useCallback(async () => {
    if (!vpn) return;
    await vpn.stopVpn();
    setRunning(false);
    setVerified(false);
    // A deliberate pause is not an interruption.
    setInterrupted(false);
  }, [vpn]);

  const state: ShieldState =
    // Strict Private DNS overrides everything else: the shield cannot run
    // and the fix is a specific system setting, not anything in this app.
    privateDnsHost ? "conflict"
    : !running ? "setup"
    : verified ? "on"
    // Tunnel up, probe failed, and our own API is unreachable too: the phone
    // is offline. Nothing can be filtered because nothing is flowing — that
    // is not a shield problem, and it must not be shown as one.
    : offline ? "offline"
    // Running, but we could not PROVE filtering — either the probe is still in
    // flight or no canary answer came back. This used to render "conflict",
    // whose copy says "Your VPN is in charge right now": a specific accusation
    // nothing in the code actually detects. "unverified" says only what we
    // know — the tunnel is up and we have not confirmed it is filtering — and
    // its pill is deliberately not tappable, so an unproven state can no
    // longer offer "turn it off" as the one obvious action.
    : "unverified";

  const openVpnSettings = useCallback(() => {
    vpn?.openVpnSettings?.();
  }, [vpn]);

  const openPrivateDnsSettings = useCallback(() => {
    vpn?.openPrivateDnsSettings?.();
  }, [vpn]);

  const refreshBlocklist = useCallback(() => {
    vpn?.refreshBlocklist?.();
    setTimeout(readBlocklist, 4000);
  }, [vpn, readBlocklist]);

  return {
    available: vpn !== null,
    state, verified, probing, offline, interrupted, privateDnsHost, blocklist,
    turnOn, turnOff, openVpnSettings, openPrivateDnsSettings, refreshBlocklist,
  };
}
