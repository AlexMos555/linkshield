/**
 * Cleanway Dark Theme — 2026 refresh (docs/design/shield-checklist-design.md)
 *
 * Old keys stay exported as aliases so untouched screens keep working; their
 * values shift to the new palette so the whole app moves together.
 */

export const colors = {
  // Core surfaces
  bg: "#0B1220",
  surface: "#FFFFFF0A",
  surfaceRaised: "#FFFFFF12",
  stroke: "#FFFFFF14",
  hairline: "#FFFFFF0F",

  // Text
  textPrimary: "#F1F5F9",
  textSecondary: "#94A3B8",
  textMuted: "#6B7A93",
  textDisabled: "#475569",

  // Semantic — the only three hues in the app
  green: "#34D399",
  greenWash: "#34D3991F",
  greenStroke: "#34D39940",
  blue: "#4C8DFF",
  bluePressed: "#3A75E8",
  blueWash: "#4C8DFF1F",
  amber: "#FBBF24",
  amberWash: "#FBBF241F",
  amberStroke: "#FBBF2440",
  danger: "#F87171",
  dangerWash: "#F871711F",
  dangerStroke: "#F8717140",

  // Legacy aliases (do not use in new code)
  bgCard: "#141A28",
  bgInput: "#1A2233",
  border: "#1E2536",
  text: "#F1F5F9",
  textDark: "#475569",
  safe: "#34D399",
  safeBg: "#34D3991F",
  caution: "#FBBF24",
  cautionBg: "#FBBF241F",
  dangerous: "#F87171",
  dangerousBg: "#F871711F",
  primary: "#4C8DFF",
  primaryBg: "#4C8DFF1F",
  accent: "#34D399",
  white: "#F8FAFC",
};

export const space = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
  huge: 48,
};

// Legacy alias (old screens use spacing.md=16 semantics)
export const spacing = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  xxl: 48,
};

export const radius = {
  card: 20,
  control: 14,
  pill: 10,
  chip: 10,
  icon: 12,
  full: 999,
};

export const type = {
  display: { fontSize: 34, lineHeight: 40, fontWeight: "700" as const },
  title1: { fontSize: 28, lineHeight: 34, fontWeight: "600" as const },
  title2: { fontSize: 20, lineHeight: 25, fontWeight: "600" as const },
  headline: { fontSize: 17, lineHeight: 22, fontWeight: "600" as const },
  body: { fontSize: 15, lineHeight: 20, fontWeight: "400" as const },
  caption: { fontSize: 13, lineHeight: 18, fontWeight: "400" as const },
};

export const sectionHeader = {
  fontSize: 13,
  lineHeight: 18,
  fontWeight: "600" as const,
  textTransform: "uppercase" as const,
  letterSpacing: 0.6,
  color: colors.textMuted,
};

// Legacy alias
export const fontSize = {
  xs: 10,
  sm: 12,
  md: 14,
  lg: 16,
  xl: 20,
  xxl: 28,
  hero: 48,
};

export const levelColors = {
  safe: colors.green,
  caution: colors.amber,
  dangerous: colors.danger,
} as const;

export const levelWashes = {
  safe: colors.greenWash,
  caution: colors.amberWash,
  dangerous: colors.dangerWash,
} as const;

export const levelStrokes = {
  safe: colors.greenStroke,
  caution: colors.amberStroke,
  dangerous: colors.dangerStroke,
} as const;

export const levelLabels = {
  safe: "Looks safe",
  caution: "Be careful",
  dangerous: "Dangerous",
} as const;

// Legacy (emoji glyph icons are removed from the UI; kept only for old imports)
export const levelIcons = {
  safe: "✓",
  caution: "⚠",
  dangerous: "✗",
} as const;
