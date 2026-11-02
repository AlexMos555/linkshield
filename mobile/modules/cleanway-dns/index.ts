import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo';

import { parseIosDnsReport } from './src/IosDnsSettings';
import type { IosDnsError, IosDnsReport } from './src/IosDnsSettings';

export type { IosDnsError, IosDnsReport };

/**
 * The iPhone's DNS protection (NEDNSSettingsManager, docs/IOS.md §4). Native
 * half: ios/CleanwayDnsModule.swift. The setup state machine that reads these
 * reports is src/utils/ios-dns.ts; the live hook is
 * src/hooks/useIosDnsProtection.ts.
 */
interface CleanwayDnsNative {
  /**
   * Raw reports — parseIosDnsReport (src/IosDnsSettings.ts) validates them.
   * They answer with a report, never reject. Optional: an iOS build from
   * before DNS protection lacks them.
   */
  dnsSettingsStatus?(): Promise<Record<string, unknown>>;
  installDnsSettings?(): Promise<Record<string, unknown>>;
  removeDnsSettings?(): Promise<Record<string, unknown>>;
  /** iOS changed the DNS configuration (turned on/off in Settings); read dnsSettingsStatus() again. */
  addListener(event: 'onDnsSettingsChanged', listener: () => void): { remove(): void };
}

// Optional: Android and web have no such module, and an app built without it
// must not crash on launch.
const native = Platform.OS === 'ios' ? requireOptionalNativeModule<CleanwayDnsNative>('CleanwayDns') : null;

/** This build can set up the iPhone's DNS protection (iOS, and a native build that has it). */
export function isIosDnsSupported(): boolean {
  return typeof native?.dnsSettingsStatus === 'function';
}

type DnsCall = 'dnsSettingsStatus' | 'installDnsSettings' | 'removeDnsSettings';

async function dnsCall(name: DnsCall): Promise<IosDnsReport | null> {
  if (!native || !isIosDnsSupported()) return null;
  try {
    const fn = native[name];
    if (typeof fn !== 'function') return null;
    return parseIosDnsReport(await fn.call(native));
  } catch {
    // The native side answers with a report, never a rejection; a throw here
    // is a bridge failure — say "failed", not "not set up".
    return parseIosDnsReport(null);
  }
}

/** What iOS has saved and whether the person turned it on. Null where there is no such layer. */
export function iosDnsStatus(): Promise<IosDnsReport | null> {
  return dnsCall('dnsSettingsStatus');
}

/** Save Cleanway's encrypted DNS in iOS. It stays off until the person picks it in Settings. */
export function installIosDns(): Promise<IosDnsReport | null> {
  return dnsCall('installDnsSettings');
}

/** Remove it from iOS altogether. */
export function removeIosDns(): Promise<IosDnsReport | null> {
  return dnsCall('removeDnsSettings');
}

/** iOS changed the DNS configuration (usually: the person switched it in Settings). */
export function addIosDnsChangedListener(cb: () => void): { remove: () => void } {
  if (!native || !isIosDnsSupported()) return { remove: () => {} };
  return native.addListener('onDnsSettingsChanged', cb);
}
