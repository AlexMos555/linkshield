import type { InstallSource } from './CleanwayVpn.types';

/** RuStore's package name: the installer of the RuStore build. */
export const RUSTORE_INSTALLER = 'ru.vk.store';

/** PackageInstaller.PACKAGE_SOURCE_* (API 33+). */
export const PACKAGE_SOURCE = {
  UNSPECIFIED: 0,
  OTHER: 1,
  STORE: 2,
  LOCAL_FILE: 3,
  DOWNLOADED_FILE: 4,
} as const;

/**
 * Turns the native installSource() map into a typed InstallSource, or null
 * when it is not an object at all.
 *
 * The JS bundle can meet an older or newer native build. A field that is
 * missing or of the wrong type reads as "not reported" — never as a claim
 * about where the app came from, which decides the set-up path the person
 * is sent down.
 */
export function parseInstallSource(raw: unknown): InstallSource | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  return {
    installer: packageName(r.installer),
    initiator: packageName(r.initiator),
    packageSource: sourceCode(r.packageSource),
  };
}

function packageName(v: unknown): string | null {
  return typeof v === 'string' && v.trim().length > 0 ? v : null;
}

function sourceCode(v: unknown): number | null {
  return typeof v === 'number' &&
    Number.isInteger(v) &&
    v >= PACKAGE_SOURCE.UNSPECIFIED &&
    v <= PACKAGE_SOURCE.DOWNLOADED_FILE
    ? v
    : null;
}
