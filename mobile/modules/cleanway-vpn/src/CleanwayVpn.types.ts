/**
 * "blocked": the query got NXDOMAIN — the site never opened.
 * "warned": the verdict arrived after the first lookup had already been
 * forwarded (fail-open); future lookups are blocked, THIS visit may have
 * opened. Copy must never call a "warned" entry a block.
 */
export type ShieldBlockKind = 'blocked' | 'warned' | 'allowed';

export type DomainBlockedPayload = {
  /** The registrable domain that was blocked at DNS resolve time. */
  domain: string;
  /** Epoch millis when it was blocked. */
  ts: number;
  kind: ShieldBlockKind;
};

/** One entry of the service's persisted block log (newest first). */
export type ShieldBlockEntry = DomainBlockedPayload;

/** Emitted when the tunnel is torn down without the user asking for it. */
export type VpnStoppedPayload = {
  /**
   * "revoked" — the system or another VPN app took the tunnel away.
   * "private_dns" — strict Private DNS is on; the service stepped aside so
   * the phone keeps working (see PrivateDnsGuard).
   */
  reason: string;
};

export type CleanwayVpnModuleEvents = {
  onDomainBlocked: (params: DomainBlockedPayload) => void;
  onVpnStopped: (params: VpnStoppedPayload) => void;
};

/** What blocklist the service has loaded and how fresh it is (BlockList.kt). */
export type BlocklistStatus = {
  /** Publisher epoch of the loaded list; 0 when none. */
  version: number;
  count: number;
  revoked: boolean;
  /** Age since load by the larger of wall/monotonic clocks; null when no list. */
  ageMs: number | null;
  /** No list, or older than 24h — the card must not claim list protection. */
  stale: boolean;
  /** The list carries the list-canary line (proof it is our artifact). */
  hasCanary: boolean;
  lastError: string | null;
  lastFetchAt: number;
};
