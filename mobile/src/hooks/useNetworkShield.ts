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
  /**
   * The list canary answered: the DNS path really does block from THIS list,
   * proven the same way the tunnel is proven. Self-reported status is not
   * enough to put a number in front of a person.
   */
  proven?: boolean;
}

const NO_LIST: BlocklistStatusLike = {
  version: 0, count: 0, revoked: false, ageMs: null, stale: true, hasCanary: false, lastError: null, lastFetchAt: 0,
};

/**
 * Why protection stopped by itself (the module's ShieldStopReason): the VPN
 * permission was withdrawn or another VPN app took over, or strict Private
 * DNS was switched on. Null: nobody told us — a battery manager, a killed app.
 */
export type ShieldStopReason = "revoked" | "private_dns";

interface VpnModule {
  startVpn(): Promise<boolean>;
  stopVpn(): Promise<void>;
  isVpnRunning(): boolean;
  wasUserEnabled?(): boolean;
  lastStopReason?(): ShieldStopReason | null;
  privateDnsStrictHost?(): string | null;
  openPrivateDnsSettings?(): boolean;
  requestBlockNotificationPermission?(): Promise<boolean>;
  blocklistStatus?(): BlocklistStatusLike;
  refreshBlocklist?(): void;
  verifyFiltering(): Promise<boolean>;
  verifyListFiltering?(): Promise<boolean>;
  addVpnStoppedListener?(cb: () => void): VpnSubscription;
  addPauseChangedListener?(cb: (p: { until: number }) => void): VpnSubscription;
  addBlocklistChangedListener?(cb: () => void): VpnSubscription;
  addNetworkChangedListener?(cb: () => void): VpnSubscription;
  openVpnSettings?(): boolean;
  pauseProtection?(untilMs: number): void;
  resumeProtection?(): void;
  pausedUntil?(): number;
}

/** A timed pause, in minutes — the default, and the only length the app offers. */
export const PAUSE_MINUTES = 15;

/**
 * How long a connection change settles before the screen re-checks. A
 * network returning announces itself twice (connected, then confirmed by
 * Android a few seconds later); one check per burst is enough.
 */
const NETWORK_SETTLE_MS = 1000;

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
   * When a timed pause ends (epoch ms), 0 when not paused. While paused the
   * tunnel is up but nothing is blocked, so the shield does NOT count as
   * verified and the hero says "paused" — never a green "protected".
   */
  pausedUntil: number;
  /** Pause for [minutes]; protection comes back by itself (the service keeps time, not the app). */
  pause: (minutes: number) => void;
  /** End a timed pause now. */
  resume: () => void;
  /**
   * The user had the shield ON and it is not running now — a reboot without
   * always-on, an OEM battery manager, a force-stop, a withdrawn VPN
   * permission, strict Private DNS. Nothing the person did in this app turned
   * it off, so it must not read as "never set up": the hero says protection
   * stopped, and the button brings it back.
   */
  interrupted: boolean;
  /**
   * Why it stopped, when the service knows ([ShieldStopReason]); null when
   * nobody told it. The screen names the cause and the real steps back —
   * 1.0.2 said "usually after a reboot, one tap" whatever had happened.
   */
  stopReason: ShieldStopReason | null;
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
  const [stopReason, setStopReason] = useState<ShieldStopReason | null>(null);
  const [privateDnsHost, setPrivateDnsHost] = useState<string | null>(null);
  const [blocklist, setBlocklist] = useState<BlocklistStatusLike>(NO_LIST);
  const [pausedUntil, setPausedUntil] = useState(0);

  const readBlocklist = useCallback(() => {
    if (!vpn) return;
    try {
      const next = vpn.blocklistStatus?.() ?? NO_LIST;
      setBlocklist((prev) => ({ ...next, proven: next.version === prev.version ? prev.proven : undefined }));
    } catch {
      setBlocklist(NO_LIST);
    }
  }, [vpn]);

  /**
   * Prove the list is what the DNS path blocks from (list-canary counter),
   * rather than trusting the service's own description of itself.
   */
  const proveList = useCallback(async () => {
    if (!vpn?.verifyListFiltering) return;
    try {
      const ok = await vpn.verifyListFiltering();
      setBlocklist((prev) => ({ ...prev, proven: ok }));
    } catch {
      setBlocklist((prev) => ({ ...prev, proven: false }));
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
    setPausedUntil(isUp ? readPausedUntil(vpn) : 0);
    readBlocklist();
    if (!isUp) {
      setVerified(false);
      setProbing(false);
      // Not running — but did the user WANT it running? That is the difference
      // between "set up" and "it stopped; turn it back on".
      setInterrupted(vpn.wasUserEnabled?.() === true);
      setStopReason(readStopReason(vpn));
      return;
    }
    setInterrupted(false);
    setStopReason(null);
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
      // Only worth proving the list when the tunnel itself is proven.
      if (ok) void proveList();
    } finally {
      setProbing(false);
    }
  }, [vpn, readBlocklist, proveList]);

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
    // The pause can change without this screen doing anything: the
    // notification's "turn back on", or the pause running out. Follow the
    // service; coming back from a pause is proven again, not assumed.
    const pauseSub = vpn?.addPauseChangedListener?.(({ until }) => {
      const pausedNow = until > Date.now();
      setPausedUntil(pausedNow ? until : 0);
      if (!pausedNow) void sync();
    });
    // The connection came or went while the screen is open. 1.0.2 re-checked
    // only on a foreground and kept «Нет сети» for minutes after the network
    // was back. Event-driven, no polling; in the background a foreground
    // re-checks anyway, so nothing runs there.
    let settle: ReturnType<typeof setTimeout> | null = null;
    const netSub = vpn?.addNetworkChangedListener?.(() => {
      if (AppState.currentState !== "active") return;
      if (settle) clearTimeout(settle);
      settle = setTimeout(() => {
        settle = null;
        void sync();
      }, NETWORK_SETTLE_MS);
    });
    // A list lands seconds after the network comes back (the service's retry
    // on reconnect), usually with no re-check left to read it: without this
    // the screen kept «Списка ещё нет» over a phone that had one.
    const listSub = vpn?.addBlocklistChangedListener?.(() => {
      readBlocklist();
      void proveList();
    });
    return () => {
      appSub.remove();
      stopSub?.remove();
      pauseSub?.remove();
      netSub?.remove();
      listSub?.remove();
      if (settle) clearTimeout(settle);
    };
  }, [sync, vpn, readBlocklist, proveList]);

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
      const proven = await vpn.verifyFiltering();
      setVerified(proven);
      // Proof outranks a stale read. The consent dialog closing fires an
      // AppState "active" sync that can read isRunning before the service
      // has set it; seen on the emulator, the hero then counted the shield
      // as verified while its own card still said "set up".
      if (proven) setRunning(true);
    } finally {
      setProbing(false);
    }
    // The service loads the stored list at start and fetches if it is old;
    // read what it has, and read again a few seconds later so a first-ever
    // sync shows up without a foreground round-trip.
    readBlocklist();
    setTimeout(() => { readBlocklist(); void proveList(); }, 6000);
    // Now that protection is on, ask to be allowed to say when it stops a
    // site (Android 13+ drops notifications otherwise). After the probe so
    // the green state is not delayed by a dialog; result deliberately
    // ignored — a refusal is respected and the block log still records.
    void vpn.requestBlockNotificationPermission?.();
  }, [vpn, readBlocklist, proveList]);

  const turnOff = useCallback(async () => {
    if (!vpn) return;
    await vpn.stopVpn();
    setRunning(false);
    setVerified(false);
    setPausedUntil(0);
    // A deliberate pause is not an interruption.
    setInterrupted(false);
    setStopReason(null);
  }, [vpn]);

  const pause = useCallback((minutes: number) => {
    if (!vpn?.pauseProtection) return;
    const until = Date.now() + minutes * 60_000;
    vpn.pauseProtection(until);
    setPausedUntil(until);
  }, [vpn]);

  const resume = useCallback(() => {
    // The module clears the stored pause before it returns, so the sync
    // below reads the truth even though the service hears of the resume
    // later; the service's pause event then confirms it.
    vpn?.resumeProtection?.();
    setPausedUntil(0);
    void sync();
  }, [vpn, sync]);

  // The service ends the pause on its own; re-read then, so the card and the
  // hero come back to "on" without the person touching anything.
  useEffect(() => {
    if (pausedUntil <= 0) return;
    const timer = setTimeout(() => void sync(), Math.max(0, pausedUntil - Date.now()) + 1_000);
    return () => clearTimeout(timer);
  }, [pausedUntil, sync]);

  const paused = running && pausedUntil > Date.now();

  const state: ShieldState =
    // Strict Private DNS overrides everything else: the shield cannot run
    // and the fix is a specific system setting, not anything in this app.
    privateDnsHost ? "conflict"
    : !running ? "setup"
    // Paused: the tunnel is up and proves it, but nothing is blocked. Not
    // "on", and not counted by the hero.
    : paused ? "paused"
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
    setTimeout(() => { readBlocklist(); void proveList(); }, 4000);
  }, [vpn, readBlocklist, proveList]);

  return {
    available: vpn !== null,
    state, verified: verified && !paused, probing, offline, interrupted, stopReason, privateDnsHost, blocklist,
    pausedUntil: paused ? pausedUntil : 0, pause, resume,
    turnOn, turnOff, openVpnSettings, openPrivateDnsSettings, refreshBlocklist,
  };
}

/** Why the shield stopped by itself, or null — also null on builds that do not say. */
function readStopReason(vpn: VpnModule): ShieldStopReason | null {
  try {
    return vpn.lastStopReason?.() ?? null;
  } catch {
    return null;
  }
}

/** The pause end the service keeps, or 0 — also 0 on builds without timed pauses. */
function readPausedUntil(vpn: VpnModule): number {
  try {
    const until = vpn.pausedUntil?.() ?? 0;
    return until > Date.now() ? until : 0;
  } catch {
    return 0;
  }
}
