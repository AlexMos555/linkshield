Pod::Spec.new do |s|
  s.name           = 'CleanwayDns'
  s.version        = '1.0.0'
  s.summary        = 'Cleanway: the iPhone DNS protection'
  s.description    = 'Saves, reads and removes the encrypted DNS setting (NEDNSSettingsManager, DNS-over-HTTPS to dns.cleanway.ai) and tells the app when iOS reports a change. docs/IOS.md section 4.'
  s.author         = 'Cleanway'
  s.homepage       = 'https://cleanway.ai'
  # Must not be above the app's deployment target (Expo SDK 56+: iOS 16.4).
  # Under SDK 54 (target 15.1) it was 16.4, and Expo's autolinking silently
  # skipped the pod — the app then died at launch with "Cannot find native
  # module" (found on the iOS 26.2 simulator, 2026-10-09).
  s.platforms      = {
    :ios => '16.4'
  }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  # Swift/Objective-C compatibility
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
