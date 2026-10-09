/**
 * Expo config plugin: keep the iOS app's entitlements to what the iPhone app
 * really uses, so App Store review and provisioning see no capability the app
 * does not need. docs/IOS.md.
 *
 *   • aps-environment (Push Notifications) — expo-notifications' plugin adds
 *     it to every iOS build, but the iPhone app sends and receives no push
 *     notifications (block alerts come from the Android VPN service; nothing
 *     in the JS imports expo-notifications, and package.json keeps the module
 *     out of iOS autolinking). An unused push entitlement makes every
 *     provisioning profile need the Push capability and invites the question
 *     "why does this app ask for push?" in review. When iOS push is built,
 *     delete this strip and drop the autolinking exclude in the same change.
 *   • com.apple.developer.networking.networkextension — never on the app
 *     target here. The iOS DNS protection (docs/MOBILE_AUTO_PROTECTION.md)
 *     uses NEDNSSettingsManager with the `dns-settings` value, which the
 *     DNS-settings task adds on purpose; a stale `packet-tunnel-provider`
 *     (a VPN — App Review 5.4, Organization accounts only) must not creep
 *     back in from an old app.json.
 *
 * The app group (group.ai.cleanway.app) that expo-share-intent adds is kept:
 * the share extension hands the shared text to the app through it.
 *
 * ORDER: list this plugin FIRST in app.json `plugins`. Expo runs the mods of
 * later plugins before earlier ones, so only a plugin listed before
 * expo-notifications sees (and can drop) the entitlement it adds — listed
 * last, the strip ran first and aps-environment came back (checked with a
 * prebuild, 2026-10-09).
 */
const { withEntitlementsPlist } = require("@expo/config-plugins");

const STRIPPED = ["aps-environment"];
const NE_KEY = "com.apple.developer.networking.networkextension";
const VPN_VALUES = new Set(["packet-tunnel-provider", "app-proxy-provider", "packet-tunnel-provider-systemextension"]);

/** Returns the entitlements without the ones the iPhone app does not use. Pure. */
function patchEntitlements(entitlements) {
  const out = { ...entitlements };
  for (const key of STRIPPED) delete out[key];
  if (Array.isArray(out[NE_KEY])) {
    const kept = out[NE_KEY].filter((v) => !VPN_VALUES.has(v));
    if (kept.length > 0) out[NE_KEY] = kept;
    else delete out[NE_KEY];
  }
  return out;
}

function withIosAppStore(config) {
  return withEntitlementsPlist(config, (cfg) => {
    cfg.modResults = patchEntitlements(cfg.modResults);
    return cfg;
  });
}

module.exports = withIosAppStore;
module.exports._patch = patchEntitlements;
