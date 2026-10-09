import ExpoModulesCore

// The iOS half of the cleanway-vpn module. The JS API (modules/cleanway-vpn/index.ts)
// is shared with Android, where it drives a local DNS-filter VPN; every
// Android-only function is optional in JS and simply absent here, so the app
// treats it as "not on this platform".
//
// iOS does NOT get a VPN (App Review 5.4 restricts VPN apps to Organization
// accounts). Its protection layers (docs/MOBILE_AUTO_PROTECTION.md, docs/IOS.md)
// are built in separate steps and report their status to the home screen
// through src/utils/platform-features.ts:
//   - DNS protection: NEDNSSettingsManager (encrypted DNS, `dns-settings`
//     Network Extension value) — its status functions belong in this module;
//   - scam-text filter: an ILMessageFilterExtension target;
//   - Safari Web Extension target.
// Until then the VPN calls below are honest no-ops: never "running".
public class CleanwayVpnModule: Module {
  public func definition() -> ModuleDefinition {
    Name("CleanwayVpn")

    Events("onDomainBlocked")

    AsyncFunction("startVpn") { () -> Bool in
      return false
    }

    AsyncFunction("stopVpn") { () in
    }

    Function("isRunning") { () -> Bool in
      return false
    }
  }
}
