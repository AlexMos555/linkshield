import type { ReactNode } from "react";
import { ActivityIndicator, ScrollView, StyleSheet, Text, TouchableOpacity, View, type StyleProp, type ViewStyle } from "react-native";
import { Ionicons } from "@expo/vector-icons";

import { colors, radius, space } from "../../utils/theme";

/**
 * The subscription screens' building blocks. Big type (17–20 pt body), targets
 * of 52 dp and more, one idea per card: the first reader is someone's mother
 * on a phone with the font size turned up, and the second is TalkBack.
 */
export const MIN_TARGET = 52;

export type Tone = "neutral" | "green" | "amber" | "danger";

const TONE_STYLE: Record<Tone, { bg: string; stroke: string; text: string }> = {
  neutral: { bg: colors.surface, stroke: colors.stroke, text: colors.textPrimary },
  green: { bg: colors.greenWash, stroke: colors.greenStroke, text: colors.green },
  amber: { bg: colors.amberWash, stroke: colors.amberStroke, text: colors.amber },
  danger: { bg: colors.dangerWash, stroke: colors.dangerStroke, text: colors.danger },
};

export function Screen({ children }: { children: ReactNode }) {
  return (
    <ScrollView style={s.screen} contentContainerStyle={s.content} keyboardShouldPersistTaps="handled">
      {children}
    </ScrollView>
  );
}

export function Card({ tone = "neutral", children, style }: { tone?: Tone; children: ReactNode; style?: StyleProp<ViewStyle> }) {
  const t = TONE_STYLE[tone];
  return <View style={[s.card, { backgroundColor: t.bg, borderColor: t.stroke }, style]}>{children}</View>;
}

export function CardTitle({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  return <Text style={[s.cardTitle, { color: TONE_STYLE[tone].text }]} accessibilityRole="header">{children}</Text>;
}

export function CardBody({ children }: { children: ReactNode }) {
  return <Text style={s.cardBody}>{children}</Text>;
}

/** A quiet line with the ⓘ mark: an honest limit, a condition, a next step. */
export function Hint({ children, icon = "information-circle-outline" }: { children: ReactNode; icon?: keyof typeof Ionicons.glyphMap }) {
  return (
    <View style={s.hintRow}>
      <Ionicons name={icon} size={16} color={colors.textSecondary} />
      <Text style={s.hint}>{children}</Text>
    </View>
  );
}

/** A line with a check mark — what a plan includes. */
export function CheckLine({ children }: { children: ReactNode }) {
  return (
    <View style={s.hintRow}>
      <Ionicons name="checkmark-circle" size={18} color={colors.green} />
      <Text style={s.checkLine}>{children}</Text>
    </View>
  );
}

export type ButtonKind = "primary" | "secondary" | "danger" | "text";

interface BigButtonProps {
  label: string;
  onPress: () => void;
  kind?: ButtonKind;
  disabled?: boolean;
  busy?: boolean;
  a11yLabel?: string;
  icon?: keyof typeof Ionicons.glyphMap;
}

export function BigButton({ label, onPress, kind = "primary", disabled, busy, a11yLabel, icon }: BigButtonProps) {
  const off = disabled || busy;
  const labelColor = kind === "primary" ? "#FFFFFF" : kind === "danger" ? colors.danger : colors.textPrimary;
  return (
    <TouchableOpacity
      style={[s.button, s[kind], off && s.buttonOff]}
      onPress={onPress}
      disabled={off}
      activeOpacity={0.85}
      accessibilityRole="button"
      accessibilityLabel={a11yLabel ?? label}
      accessibilityState={{ disabled: off, busy }}
    >
      {busy ? <ActivityIndicator color={labelColor} /> : (
        <View style={s.buttonInner}>
          {icon ? <Ionicons name={icon} size={20} color={labelColor} /> : null}
          <Text style={[s.buttonLabel, { color: labelColor }]}>{label}</Text>
        </View>
      )}
    </TouchableOpacity>
  );
}

export function Spinner() {
  return (
    <View style={s.spinner}>
      <ActivityIndicator color={colors.green} size="large" />
    </View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.bg },
  content: { padding: space.xl, paddingBottom: space.huge, gap: space.md },
  card: { borderWidth: 1, borderRadius: radius.card, padding: space.xl, gap: space.sm },
  cardTitle: { fontSize: 22, lineHeight: 28, fontWeight: "700" },
  cardBody: { fontSize: 17, lineHeight: 24, color: colors.textPrimary },
  hintRow: { flexDirection: "row", alignItems: "flex-start", gap: space.sm, marginTop: 2 },
  hint: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, flex: 1 },
  checkLine: { fontSize: 16, lineHeight: 22, color: colors.textPrimary, flex: 1 },
  button: {
    minHeight: MIN_TARGET, borderRadius: radius.control, alignItems: "center", justifyContent: "center",
    paddingHorizontal: space.lg, paddingVertical: space.md,
  },
  buttonInner: { flexDirection: "row", alignItems: "center", gap: space.sm },
  buttonLabel: { fontSize: 18, fontWeight: "600", textAlign: "center" },
  buttonOff: { opacity: 0.55 },
  primary: { backgroundColor: colors.blue },
  secondary: { backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke },
  danger: { backgroundColor: colors.dangerWash, borderWidth: 1, borderColor: colors.dangerStroke },
  text: { backgroundColor: "transparent" },
  spinner: { paddingVertical: space.huge, alignItems: "center" },
});
