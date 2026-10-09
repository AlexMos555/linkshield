Pod::Spec.new do |s|
  s.name           = 'CleanwaySmsFilter'
  s.version        = '1.0.0'
  s.summary        = 'Cleanway scam-text filter: the app side'
  s.description    = 'Hands the server switches for the on-device SMS check to the CleanwaySmsFilter extension through the app group, and tells the app whether this build carries the extension. The filter itself is the CleanwaySmsFilter target (plugins/withSmsFilter.js); docs/IOS.md section 5.'
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

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
