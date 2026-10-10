Pod::Spec.new do |s|
  s.name           = 'CleanwaySmsFilter'
  s.version        = '1.1.0'
  s.summary        = 'Cleanway scam-text filter: the app side'
  s.description    = 'Hands the server switches for the on-device SMS check to the CleanwaySmsFilter extension through the app group, tells the app whether this build carries the extension, and runs the same on-device message engine for the in-app message check. The filter itself is the CleanwaySmsFilter target (plugins/withSmsFilter.js); docs/IOS.md section 5.'
  s.author         = 'Cleanway'
  s.homepage       = 'https://cleanway.ai'
  # Not above the app's deployment target (Expo SDK 54: iOS 15.1), or autolinking skips the pod.
  s.platforms      = {
    :ios => '15.1'
  }
  s.source         = { git: '' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  # Engine/ and EngineAssets/ are symlinks to the one engine the filter
  # extension compiles (mobile/targets/sms-filter/Sources/CleanwayMessageEngine)
  # and the assets Android ships (modules/cleanway-vpn/android/src/main/assets):
  # one vocabulary and one model for the filter, the app and Android.
  s.source_files = "*.swift", "Engine/*.swift"
  s.resource_bundles = { 'CleanwayMessageEngineAssets' => ['EngineAssets/*'] }
end
