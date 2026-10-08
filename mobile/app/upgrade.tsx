/**
 * The old plans page (Free / Personal $4.99 / Family $9.99, "14-day trial")
 * is gone: its prices were no longer the plan's, and its buttons linked to
 * the web checkout, which a Google Play build must never do. There is one
 * place to pay now — the paywall (app/paywall.tsx), which pays through the
 * store in a store build and on cleanway.ai only in the APK from our site.
 * The route stays so an old link or a saved deep link still lands somewhere.
 */
import { Redirect } from "expo-router";

export default function UpgradeScreen() {
  return <Redirect href={{ pathname: "/paywall", params: { from: "upgrade" } }} />;
}
