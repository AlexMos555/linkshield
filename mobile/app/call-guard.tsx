/**
 * "I'm being called" — the stop screen on demand.
 *
 * Reached from the home button and from the after-call notice
 * (cleanway:///call-guard?after=1). The same screen as the one that steps in
 * front of a pause / allow / "open anyway" during a call, without an action
 * behind it: only "keep protection", "call a close one" when a number is
 * saved, and the honest line about what Cleanway cannot see.
 */
import { useCallback } from "react";
import { useRouter } from "expo-router";
import { CallGuardScreen } from "../src/components/call/CallGuardScreen";
import { useCallState } from "../src/hooks/useCallState";

export default function CallGuardRoute() {
  const router = useRouter();
  const { reason } = useCallState();

  const leave = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

  return <CallGuardScreen mode="on_demand" reason={reason} onKeep={leave} />;
}
