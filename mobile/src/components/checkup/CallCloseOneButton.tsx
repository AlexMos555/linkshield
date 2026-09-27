import { useState } from "react";
import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius } from "../../utils/theme";
import { useCloseOne } from "../../hooks/useCloseOne";
import { callCloseOne } from "../../services/checkup-actions";
import type { CloseOne } from "../../utils/checkup";

/**
 * The big "Позвонить близкому" button: opens the dialer with the saved
 * number filled in. The person still presses call — no call permission.
 */
export function CallButton({ contact }: { contact: CloseOne }) {
  const { t } = useTranslation();
  const [failed, setFailed] = useState(false);
  const label = contact.name
    ? t("mobile.checkup.call.button_named", { name: contact.name })
    : t("mobile.checkup.call.button");
  return (
    <>
      <TouchableOpacity
        style={s.button}
        onPress={() => void callCloseOne(contact.number).then((ok) => setFailed(!ok))}
        activeOpacity={0.85}
        accessibilityRole="button"
        accessibilityLabel={label}
      >
        <Ionicons name="call" size={22} color={colors.green} />
        <Text style={s.label} numberOfLines={2}>{label}</Text>
      </TouchableOpacity>
      {failed && <Text style={s.failed}>{t("mobile.checkup.call.dial_failed")}</Text>}
    </>
  );
}

/**
 * On a warning — a blocked site, a dangerous message — the one step that
 * beats every scam script: hang up and call someone you trust. Shown only
 * once the person has saved a number on the checkup screen; nothing
 * otherwise, so no warning grows a button that goes nowhere.
 */
export function CallCloseOneButton() {
  const { t } = useTranslation();
  const { contact } = useCloseOne();
  if (!contact) return null;
  return (
    <View style={s.wrap}>
      <Text style={s.prompt}>{t("mobile.checkup.call.prompt")}</Text>
      <CallButton contact={contact} />
    </View>
  );
}

const s = StyleSheet.create({
  wrap: { marginBottom: space.md },
  prompt: { fontSize: 16, lineHeight: 22, color: colors.textPrimary, marginBottom: space.sm },
  button: {
    minHeight: 56, flexDirection: "row", gap: space.md,
    alignItems: "center", justifyContent: "center",
    backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke,
    borderRadius: radius.control, paddingHorizontal: space.xl, paddingVertical: space.sm,
  },
  label: { fontSize: 18, lineHeight: 24, fontWeight: "600", color: colors.textPrimary, flexShrink: 1, textAlign: "center" },
  failed: { fontSize: 14, lineHeight: 20, color: colors.amber, marginTop: space.sm, textAlign: "center" },
});
