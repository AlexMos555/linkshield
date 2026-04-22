/**
 * VPN Manager — Smart VPN/DNS Protection
 *
 * Detects user's network setup and chooses best protection mode:
 *
 *   Mode A: LOCAL VPN (no external VPN detected)
 *     → NEPacketTunnelProvider (iOS) / VpnService (Android)
 *     → Intercepts DNS queries only (no traffic inspection)
 *     → Checks every domain against bloom filter + API
 *
 *   Mode B: DNS PROFILE (user has NordVPN/ExpressVPN/etc.)
 *     → Configure device to use our DoH/DoT DNS resolver
 *     → Works alongside existing VPN
 *     → iOS: Configuration Profile
 *     → Android: Private DNS setting
 *
 *   Mode C: MANUAL ONLY (fallback)
 *     → No system-level protection
 *     → User checks links manually via app
 *     → Share sheet + clipboard monitoring
 *
 * NATIVE CODE REQUIRED:
 *   The actual VPN tunnel requires native iOS/Android code.
 *   This file manages the JS-side state and UI.
 *   Native modules are in ios/ and android/ directories.
 */

export type ProtectionMode = "vpn" | "dns" | "manual";

export interface ProtectionStatus {
  mode: ProtectionMode;
  active: boolean;
  vpnConflict: boolean;
  domainsChecked: number;
  domainsBlocked: number;
}

let _status: ProtectionStatus = {
  mode: "manual",
  active: false,
  vpnConflict: false,
  domainsChecked: 0,
  domainsBlocked: 0,
};

/**
 * Detect current protection mode.
 * Checks if another VPN is active → use DNS mode instead.
 */
export async function detectProtectionMode(): Promise<ProtectionMode> {
  // In a real app, this would check:
  // iOS: NEVPNManager.shared().connection.status
  // Android: ConnectivityManager.getActiveNetwork() → VPN capability

  // For now, default to manual (native code needed for VPN)
  return "manual";
}

/**
 * Start protection.
 */
export async function startProtection(): Promise<ProtectionStatus> {
  const mode = await detectProtectionMode();

  if (mode === "vpn") {
    // Start local VPN tunnel
    // Requires native module: CleanwayVPN.start()
    _status = { mode: "vpn", active: true, vpnConflict: false, domainsChecked: 0, domainsBlocked: 0 };
  } else if (mode === "dns") {
    // Configure DNS profile
    // Requires native module or MDM profile installation
    _status = { mode: "dns", active: true, vpnConflict: true, domainsChecked: 0, domainsBlocked: 0 };
  } else {
    // Manual mode — share sheet + clipboard
    _status = { mode: "manual", active: true, vpnConflict: false, domainsChecked: 0, domainsBlocked: 0 };
  }

  return _status;
}

/**
 * Stop protection.
 */
export async function stopProtection(): Promise<void> {
  // Stop VPN tunnel if running
  _status.active = false;
}

/**
 * Get current status.
 */
export function getProtectionStatus(): ProtectionStatus {
  return { ..._status };
}

/**
 * Record a domain check (called by DNS resolver).
 */
export function recordCheck(blocked: boolean) {
  _status.domainsChecked++;
  if (blocked) _status.domainsBlocked++;
}

/**
 * Get setup instructions for DNS mode.
 */
export function getDNSSetupInstructions(platform: "ios" | "android"): string[] {
  if (platform === "ios") {
    return [
      "1. Go to Settings → General → VPN & Device Management",
      "2. Tap 'DNS' → 'Configure DNS'",
      "3. Select 'Manual'",
      "4. Add DNS server: dns.cleanway.ai",
      "5. Save",
      "",
      "Or install our DNS profile (tap button below)",
    ];
  }
  return [
    "1. Go to Settings → Network & Internet → Private DNS",
    "2. Select 'Private DNS provider hostname'",
    "3. Enter: dns.cleanway.ai",
    "4. Save",
  ];
}
