import { Ionicons } from "@expo/vector-icons";

/**
 * Side-effecting import (app/_layout.tsx): every Ionicons glyph is hidden
 * from VoiceOver / TalkBack by default.
 *
 * An icon font draws each icon as one private-use character inside a <Text>.
 * A screen reader stopped on it and said nothing (or "unpronounceable") —
 * an empty stop next to almost every line of this app. Here an icon always
 * sits beside words that say the same thing (status is never icon- or
 * colour-only), and icon-only buttons carry their own accessibilityLabel on
 * the button, so the glyph itself never needs to be read.
 *
 * An icon that must be read on its own can still opt back in per use:
 * `<Ionicons accessibilityElementsHidden={false} importantForAccessibility="yes"
 * accessibilityLabel="…" />`.
 *
 * Done through defaultProps rather than by editing ~90 call sites; the
 * expo wrapper shares this object with the class it renders
 * (@expo/vector-icons createIconSet).
 */
const DECORATIVE = {
  accessible: false,
  accessibilityElementsHidden: true,
  importantForAccessibility: "no-hide-descendants",
} as const;

const icon = Ionicons as unknown as { defaultProps?: Record<string, unknown> };
icon.defaultProps = { ...(icon.defaultProps ?? {}), ...DECORATIVE };

export {};
