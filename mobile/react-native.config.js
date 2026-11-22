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
 * changing EXPO_PUBLIC_DISTRIBUTION, regenerate android/ (`expo prebuild --clean`);
 * a release build whose android/ was generated for another value stops at
 * the start of gradle (plugins/withDistributionGuard.js).
 */
const { storeBillingLinked, buildEnv } = require("./plugins/store-billing-linking");

/**
 * Installed, never linked (Expo SDK 58). expo-router 58 depends on
 * react-native-drawer-layout (only for `expo-router/drawer`, which the app does
 * not use), and npm installs that package's required peers with it:
 * react-native-gesture-handler and react-native-reanimated (+ worklets for
 * reanimated 4). Nothing the app bundles imports them: app code does not
 * (plugins/__tests__/plugins.test.js), and expo-router reaches them only
 * from `expo-router/drawer` and `expo-router/js-stack`. Left to autolinking,
 * their native code would still be compiled into both apps: two more native
 * libraries, a bigger APK, and worklets' known Hermes V1 memory growth
 * (docs/EXPO_UPGRADE_PLAN.md §2.2, risk 10). Importing one of them later
 * means removing it from this list first, or the app crashes on start
 * ("TurboModuleRegistry.getEnforcing(...): 'RNGestureHandlerModule' could
 * not be found").
 */
const NOT_LINKED = ["react-native-gesture-handler", "react-native-reanimated", "react-native-worklets"];

const dependencies = {};
for (const name of NOT_LINKED) dependencies[name] = { platforms: { android: null, ios: null } };
if (!storeBillingLinked(buildEnv(__dirname))) {
  // Android only: the site APK and RuStore must not carry Play Billing. iOS
  // always links it: every iPhone build is the App Store one, which pays
  // through StoreKit (docs/IOS.md). StoreKit asks for no permission.
  dependencies["react-native-purchases"] = { platforms: { android: null } };
}

module.exports = { dependencies };
