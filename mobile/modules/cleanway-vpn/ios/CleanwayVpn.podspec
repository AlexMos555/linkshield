Pod::Spec.new do |s|
  s.name           = 'CleanwayVpn'
  s.version        = '1.0.0'
  s.summary        = 'Cleanway native module (iOS half)'
  s.description    = 'The iOS half of the cleanway-vpn Expo module. The JS API is shared with Android; on iOS the protection layers (DNS settings, SMS filter, Safari extension) are separate targets — see docs/IOS.md.'
  s.author         = 'Cleanway'
  s.homepage       = 'https://cleanway.ai'
  # Must not be above the app's deployment target (Expo SDK 54: iOS 15.1).
  # It was 16.4, and Expo's autolinking silently skipped the pod — the app
  # then died at launch with "Cannot find native module 'CleanwayVpn'"
  # (found on the iOS 26.2 simulator, 2026-10-09).
  s.platforms      = {
    :ios => '15.1'
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
