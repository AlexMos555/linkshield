import type { BypassApp } from './CleanwayVpn.types';

/**
 * Typed rows for "Apps without the filter" from the native excludedApps() /
 * pickableApps() maps.
 *
 * The JS bundle and the native build ship separately, so a row is checked
 * field by field: one without a package name or a name to show is dropped
 * (a nameless row cannot be chosen knowingly), an odd optional field falls
 * back to its safe value, and a repeated package appears once.
 */
export function parseBypassApps(raw: unknown): BypassApp[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  const out: BypassApp[] = [];
  for (const row of raw) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const pkg = typeof r.package === 'string' ? r.package.trim() : '';
    const label = typeof r.label === 'string' ? r.label.trim() : '';
    if (!pkg || !label || seen.has(pkg)) continue;
    seen.add(pkg);
    out.push({
      package: pkg,
      label,
      icon: typeof r.icon === 'string' && r.icon.startsWith('data:image/') ? r.icon : null,
      suggested: r.suggested === true,
      isDefault: r.isDefault === true,
      // Unknown means "treat as a browser": refusing it is the safe side (canBypass).
      isBrowser: r.isBrowser !== false,
    });
  }
  return out;
}

/**
 * Can the person take [app] off the shield? Never a browser. Without the
 * filter, every site opened in it would go unchecked. "Take Chrome off the
 * protection" is also exactly what a scammer on the phone would ask for. An
 * unknown flag already reads as "browser" (parseBypassApps), so doubt means
 * no. The native excludeApp refuses browsers too.
 */
export function canBypass(app: BypassApp): boolean {
  return !app.isBrowser;
}

/**
 * The picker's two groups. Apps known to ask for the VPN to be turned off come
 * first — that is usually the one the person is looking for — then every other
 * app, by the name under its icon in the person's language. Browsers are never
 * suggested: without the filter, browsing in them would go unchecked.
 */
export function groupPickable(apps: readonly BypassApp[], locale: string): { suggested: BypassApp[]; others: BypassApp[] } {
  const byLabel = (a: BypassApp, b: BypassApp) =>
    a.label.localeCompare(b.label, locale, { sensitivity: 'base' }) || a.package.localeCompare(b.package);
  const suggested = apps.filter((a) => a.suggested && !a.isBrowser).sort(byLabel);
  const picked = new Set(suggested.map((a) => a.package));
  const others = apps.filter((a) => !picked.has(a.package)).sort(byLabel);
  return { suggested, others };
}
