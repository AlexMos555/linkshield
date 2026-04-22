/**
 * Cleanway Dark Theme
 */

export const colors = {
  bg: "#0f172a",
  bgCard: "#1e293b",
  bgInput: "#111827",
  border: "#334155",

  text: "#e2e8f0",
  textSecondary: "#94a3b8",
  textMuted: "#64748b",
  textDark: "#475569",

  safe: "#22c55e",
  safeBg: "#052e16",
  caution: "#f59e0b",
  cautionBg: "#451a03",
  dangerous: "#ef4444",
  dangerousBg: "#450a0a",

  primary: "#3b82f6",
  primaryBg: "#1e3a5f",
  accent: "#22c55e",

  white: "#f8fafc",
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  xxl: 48,
};

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
  safe: colors.safe,
  caution: colors.caution,
  dangerous: colors.dangerous,
} as const;

export const levelIcons = {
  safe: "\u2713",
  caution: "\u26A0",
  dangerous: "\u2717",
} as const;

export const levelLabels = {
  safe: "Safe",
  caution: "Caution",
  dangerous: "Dangerous",
} as const;
