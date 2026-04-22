# Mobile native VPN — integration runbook

Cleanway mobile ships a DNS-only VPN on both platforms. The native code lives in:

```
mobile/native/ios/
  PacketTunnelProvider.swift   — NEPacketTunnelProvider entry point
  DNSParser.swift              — pure-Swift wire-format parser (testable)
  DNSParserTests.swift         — Swift Testing suite
mobile/native/android/
  CleanwayVpnService.kt      — VpnService entry point
  DnsUtil.kt                   — pure-Kotlin wire-format parser (testable)
  DnsUtilTest.kt               — kotlin.test JVM suite
```

## Privacy invariants (DO NOT REGRESS)

- Only DNS queries are parsed. No TCP/UDP payload is ever inspected.
- Only domain names leave the device (via `GET /api/v1/public/check/{domain}`).
- System suffixes (`google.com`, `apple.com`, `cleanway.ai`, …) are NEVER blocked — they are centralized in `DomainPolicy` on both platforms. Keep the two lists in sync.

## Expo integration — required config plugin

The current Expo managed workflow does not register the native VPN targets. A config plugin is required to:

1. **iOS**: add a Network Extension target with `NEPacketTunnelProvider` entitlement, wire the `App Groups` capability to `group.ai.cleanway.app`, and copy `PacketTunnelProvider.swift` + `DNSParser.swift` into the extension target.
2. **Android**: add `VpnService` declaration + `BIND_VPN_SERVICE` permission to the merged `AndroidManifest.xml`, and include `CleanwayVpnService.kt` + `DnsUtil.kt` in the app sources.

Scaffold:

```
mobile/plugins/with-cleanway-vpn/
  index.ts             — entry plugin, composes iOS + Android
  ios.ts               — withXcodeProject + withEntitlementsPlist
  android.ts           — withAndroidManifest + withSourceFiles
```

Apply in `app.json`:

```json
{
  "expo": {
    "plugins": ["./plugins/with-cleanway-vpn"]
  }
}
```

## Running unit tests

**iOS** (from main app target — no simulator required):
```bash
xcodebuild test -scheme Cleanway \
  -only-testing:CleanwayTests/DNSParserTests \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

**Android** (pure JVM):
```bash
./gradlew :app:testDebugUnitTest --tests "ai.cleanway.app.DnsUtil*"
./gradlew :app:testDebugUnitTest --tests "ai.cleanway.app.DomainPolicyTest"
```

Both suites parse synthesized DNS query packets to assert:

- QNAME extraction (happy path, multi-label, rejects pointers, rejects oversized labels, rejects short packets)
- NXDOMAIN response synthesis (QR/AA/RCODE bits, address swap, port swap)
- `wrapResponse` payload wrapping and out-of-bounds guards
- `DomainPolicy.isSystemDomain` exact/suffix/case-insensitive behavior

## Known gaps — roadmap

| Gap | Why it matters | Fix |
|---|---|---|
| No DNS message compression support | Queries with compressed QNAME are rejected (fail-safe) | RFC 1035 §4.1.4 parser — needed for IDN + very long names |
| No IPv6 support | Tunnel is v4-only | Add v6 branch in `DNSParser.extractDomain` + tunnel settings |
| No DNSSEC validation | Upstream (1.1.1.1) already validates | Optional — add if threat model expands |
| No persistent blocklist cache | Rebuilt on VPN restart | Wire to app-group / EncryptedSharedPreferences |
| No battery telemetry | Can't detect regressions | Add `os_signpost` / Android battery profiler hooks |
| No Detox/Maestro flows | Tunnel can't be started from automated tests (needs user permission prompt) | Maestro cloud run with pre-granted permission |

## Debugging a real device

### iOS

1. Attach via Xcode → Debug → Attach to Process → pick `Cleanway (Extension)` once the VPN is enabled.
2. Console app on the Mac: filter for `subsystem == "ai.cleanway.app"` and `category == "vpn.tunnel"`.
3. If the tunnel fails to start, the error message is logged via `os.Logger.error("tunnel_start_failed: …")`.

### Android

```bash
adb logcat -s CleanwayVPN:V
```

Expected log stream on healthy startup:

```
CleanwayVPN I tunnel_started
```

If it logs `establish() returned null`, the VPN permission was revoked — prompt the user to re-enable via the app.

## Security review checklist (before every release)

- [ ] `DomainPolicy.systemSuffixes` identical on iOS and Android
- [ ] Upstream DNS host is `1.1.1.1` only — no fallback to user-attacker-controlled hosts
- [ ] `API_BASE` is the production Railway URL (or env-driven in a debug build)
- [ ] `notifyBlocked` only writes `domain` + timestamp — never IPs, URLs, user IDs
- [ ] `@Volatile` / actor isolation on all shared state
- [ ] No `print` / `Log.d` statements leaking PII — only `Log.v` / `Logger.debug` with `privacy: .public`/`.private` attributes
- [ ] Crash-test: revoke VPN permission mid-run → service should self-stop cleanly
