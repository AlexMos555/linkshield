import type { ReactNode } from "react";
import { Modal, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { colors, type as typo, space, radius } from "../../utils/theme";

interface SheetFrameProps {
  onClose: () => void;
  children: ReactNode;
}

/**
 * The bottom sheet History opens for one entry — a shield event
 * (ShieldEventSheet) or an SMS the automatic check flagged (SmsAlertSheet).
 * One frame, so both close the same way and read the same to a screen reader.
 */
export function SheetFrame({ onClose, children }: SheetFrameProps) {
  return (
    <Modal visible transparent animationType="fade" onRequestClose={onClose}>
      <View style={s.frame}>
        {/* The scrim is a sibling BEHIND the sheet, not its parent: a
            touchable parent would swallow the sheet into one screen-reader
            button, and a tap on the sheet would close it. Screen-reader users
            close with the button or Back (onRequestClose). */}
        <Pressable
          style={[StyleSheet.absoluteFill, s.scrim]}
          onPress={onClose}
          accessible={false}
          importantForAccessibility="no"
        />
        <View style={s.sheet}>
          <ScrollView contentContainerStyle={s.content} bounces={false}>
            {children}
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

/** "Label: value", read out as one line. */
export function Fact({ label, value }: { label: string; value: string }) {
  return (
    <View style={sheetStyles.factRow} accessible accessibilityLabel={`${label}: ${value}`}>
      <Text style={sheetStyles.factLabel}>{label}</Text>
      <Text style={sheetStyles.factValue}>{value}</Text>
    </View>
  );
}

const s = StyleSheet.create({
  frame: { flex: 1, justifyContent: "flex-end" },
  scrim: { backgroundColor: "#0B1220E6" },
  sheet: {
    maxHeight: "88%",
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
  },
  content: { padding: space.xxl, paddingBottom: space.huge },
});

/** The pieces both sheets are built from. */
export const sheetStyles = StyleSheet.create({
  headRow: { flexDirection: "row", alignItems: "center", gap: space.md },
  icon: {
    width: 44, height: 44, borderRadius: radius.icon, borderWidth: 1,
    alignItems: "center", justifyContent: "center",
  },
  what: { ...typo.headline, flex: 1 },
  title: { ...typo.title2, color: colors.textPrimary, marginTop: space.lg },
  body: { ...typo.body, color: colors.textSecondary, marginTop: space.sm },
  facts: { marginTop: space.lg, gap: space.sm },
  factRow: { flexDirection: "row", gap: space.sm, flexWrap: "wrap" },
  factLabel: { ...typo.body, color: colors.textMuted },
  factValue: { ...typo.body, color: colors.textPrimary, flexShrink: 1 },
  advice: { ...typo.body, color: colors.textPrimary, marginTop: space.lg },
  primaryBtn: {
    minHeight: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl, paddingHorizontal: space.lg,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondaryBtn: {
    minHeight: 50, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center", marginTop: space.md, paddingHorizontal: space.lg,
  },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary },
  quietBtn: { minHeight: 48, alignItems: "center", justifyContent: "center", marginTop: space.sm },
  quietLabel: { ...typo.body, color: colors.textSecondary, textAlign: "center" },
});
