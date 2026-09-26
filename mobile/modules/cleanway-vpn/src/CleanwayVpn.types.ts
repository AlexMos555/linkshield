/**
 * "blocked": the site never opened — the DNS query got NXDOMAIN, or the link
 * guard stopped a tapped link to a listed site.
 * "warned": the link guard let a link open and the check of its site came
 * back dangerous afterwards; THIS visit may have opened. Copy must never call
 * a "warned" entry a block.
 * "allowed": the person said "not a scam".
 */
export type ShieldBlockKind = 'blocked' | 'warned' | 'allowed';

/**
 * Which shield acted (BlockLog.SOURCE_*): "dns" — the network shield ("All
 * apps"); "link" — the link guard ("Link checking").
 */
export type ShieldBlockSource = 'dns' | 'link';

export type DomainBlockedPayload = {
  /** The listed domain that was blocked (the suffix the list matched). */
  domain: string;
  /** Epoch millis when it was blocked. */
  ts: number;
  kind: ShieldBlockKind;
};

/**
 * One entry of the service's persisted block log (newest first). One entry
 * per event: repeats of a site within 10 minutes refresh `ts` instead of
 * adding rows. `source` is null for allows (and on older native builds).
 */
export type ShieldBlockEntry = DomainBlockedPayload & { source?: ShieldBlockSource | null };

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

// ── On-device message check (MessageAnalyzer.kt) ──────────────────────────

/**
 * Overall result of checking a pasted or shared message on the phone.
 * There is deliberately no "safe": a message can only show no signals.
 */
export type MessageVerdict = 'dangerous' | 'caution' | 'no_signals';

/**
 * What the on-device blocklist says about one link's host.
 * "system": a Google/Android host the shield never blocks so the phone keeps
 * working — NOT vouched for: anyone can publish a page on docs.google.com.
 * "allowed_by_user": the person marked the site "not a scam".
 * "unknown": not on the list — which says nothing about safety.
 */
export type MessageLinkStatus = 'blocked' | 'system' | 'allowed_by_user' | 'unknown';

/** Stable reason codes (MessageAnalyzer.ALL_REASONS). The UI must translate every one. */
export type MessageReason =
  | 'link_blocklisted'
  | 'claims_organisation'
  | 'threat_or_urgency'
  | 'asks_to_confirm_data'
  | 'reward_bait'
  | 'call_unknown_number'
  | 'link_not_official'
  | 'link_shortener'
  | 'link_messenger'
  | 'link_ip_address'
  | 'link_lookalike'
  | 'link_imitates_brand'
  | 'link_apk'
  | 'asks_for_code'
  | 'safe_account'
  | 'asks_for_payment'
  | 'relative_in_trouble'
  | 'install_app'
  | 'malware_lure'
  | 'sms_transfer_command'
  | 'disguised_letters'
  | 'sender_personal_number'
  | 'sender_mismatch';

/** The message looks like a known legitimate kind. Never reported next to a "dangerous" verdict. */
export type MessageLegitShape = 'login_code' | 'payment_alert' | 'pickup_code' | 'public_alert' | 'safety_notice';

export type MessageLink = {
  /** As written in the message, path included. Show it on the phone; never send it anywhere. */
  text: string;
  /** Lowercase punycode host — the only part that may go to the domain-only check. */
  host: string;
  status: MessageLinkStatus;
  /** clck.ru, vk.cc, bit.ly… — the real destination is hidden. */
  shortener: boolean;
  /** t.me, wa.me… — leads into a chat, not a website. */
  messenger: boolean;
};

export type MessageAnalysis = {
  verdict: MessageVerdict;
  /** Most important first. Empty for "no_signals". */
  reasons: MessageReason[];
  links: MessageLink[];
  /** Full phone numbers found, normalised to +<digits>. */
  phones: string[];
  legitShape: MessageLegitShape | null;
  /** Ids from message_rules.json of the organisations the text names (gosuslugi, sber, …). */
  organisations: string[];
  /** The text was longer than the analysed limit; only its start was read. */
  truncated: boolean;
  /** A synced blocklist was on the phone — without it every link is "unknown". */
  listAvailable: boolean;
  /** That list was published more than 48h ago. */
  listStale: boolean;
};

/**
 * analyzeMessage() result. "unsupported": not Android, or an older native
 * build. "failed": the check threw — the UI must say it could not check,
 * never imply the message is fine.
 */
export type MessageAnalysisResult =
  | ({ available: true } & MessageAnalysis)
  | { available: false; reason: 'unsupported' | 'failed' };
