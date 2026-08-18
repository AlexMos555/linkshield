export type DomainBlockedPayload = {
  /** The registrable domain that was blocked at DNS resolve time. */
  domain: string;
  /** Epoch millis when it was blocked. */
  ts: number;
};

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
