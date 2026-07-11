export type DomainBlockedPayload = {
  /** The registrable domain that was blocked at DNS resolve time. */
  domain: string;
  /** Epoch millis when it was blocked. */
  ts: number;
};

export type CleanwayVpnModuleEvents = {
  onDomainBlocked: (params: DomainBlockedPayload) => void;
};
