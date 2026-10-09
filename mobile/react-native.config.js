/**
 * Native module autolinking overrides (read by Expo's autolinking when Gradle
 * configures the Android project).
 *
 * react-native-purchases (Google Play billing via RevenueCat) is linked only
 * into the Google Play build — see plugins/store-billing-linking.js. Build the
 * Play APK / AAB with EXPO_PUBLIC_DISTRIBUTION=play set for the whole build
 * (prebuild AND gradle), e.g. in the EAS profile or mobile/.env.
 *
 * Gradle caches the autolinking result (android/build/generated/autolinking/)
 * keyed on package.json / the lock / this file — NOT on the environment. After
 * changing EXPO_PUBLIC_DISTRIBUTION, regenerate android/ (`expo prebuild --clean`).
 */
const { storeBillingLinked, buildEnv } = require("./plugins/store-billing-linking");

const dependencies = {};
if (!storeBillingLinked(buildEnv(__dirname))) {
  // Android only: the site APK and RuStore must not carry Play Billing. iOS
  // always links it: every iPhone build is the App Store one, which pays
  // through StoreKit (docs/IOS.md). StoreKit asks for no permission.
  dependencies["react-native-purchases"] = { platforms: { android: null } };
}

module.exports = { dependencies };
