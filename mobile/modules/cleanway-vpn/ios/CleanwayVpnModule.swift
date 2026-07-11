import ExpoModulesCore

// iOS system-wide DNS VPN (NEPacketTunnelProvider) is a SEPARATE track: App Review 5.4
// requires an Organization Apple Developer account plus a Network Extension target.
// Until that ships, expose a no-op so the JS API is identical across platforms and the
// UI can simply show "iOS coming soon".
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
