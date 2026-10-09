Pod::Spec.new do |s|
  s.name           = 'CleanwaySafari'
  s.version        = '1.0.0'
  s.summary        = 'Cleanway: the Safari extension status for the iPhone app'
  s.description    = 'Reads whether the Cleanway Safari Web Extension is switched on (iOS 26.2+) and when it last ran on a web page (app group), and opens its page in Settings. docs/IOS.md.'
  s.author         = 'Cleanway'
  s.homepage       = 'https://cleanway.ai'
  # Not above the app's deployment target (Expo SDK 54: iOS 15.1), or Expo's
  # autolinking silently skips the pod and the app dies at launch.
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
