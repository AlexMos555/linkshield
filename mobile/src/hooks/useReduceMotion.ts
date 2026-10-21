import { useEffect, useState } from "react";
import { AccessibilityInfo } from "react-native";

/**
 * The system "Reduce motion" setting (iOS) / "Remove animations" (Android),
 * kept live: it follows the switch if the person flips it while the app is
 * open. `null` until the first answer arrives, so a caller can hold an
 * animation back instead of starting it and snapping it to the end.
 */
export function useReduceMotion(): boolean | null {
  const [reduce, setReduce] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    AccessibilityInfo.isReduceMotionEnabled()
      .then((on) => { if (alive) setReduce(on); })
      // Unknown: animate as before rather than freezing the screen.
      .catch(() => { if (alive) setReduce(false); });
    const sub = AccessibilityInfo.addEventListener("reduceMotionChanged", setReduce);
    return () => {
      alive = false;
      sub.remove();
    };
  }, []);
  return reduce;
}
