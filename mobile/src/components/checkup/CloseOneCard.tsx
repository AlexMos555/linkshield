import { useState } from "react";
import { View, Text, StyleSheet, TouchableOpacity, TextInput, Alert } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, space, radius } from "../../utils/theme";
import { isContactPickerSupported, pickContactPhone } from "../../../modules/cleanway-vpn";
import { makeCloseOne, MAX_NAME_LENGTH, type CloseOne } from "../../utils/checkup";
import { formatPhone } from "../../utils/phone-number";
import type { CloseOneState } from "../../hooks/useCloseOne";
import { CallButton } from "./CallCloseOneButton";

/**
 * "Позвонить близкому": the person picks someone they trust — from the
 * address book through the system picker (no contacts permission), or by
 * typing the number — and gets one big button that opens the dialer.
 *
 * The number stays in this phone's secure storage and goes nowhere. This is
 * the one family step the app can see, so its "done" is the saved number
 * itself rather than a mark.
 */
export function CloseOneCard({ state }: { state: CloseOneState }) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const saved = state.contact;

  async function persist(contact: CloseOne): Promise<void> {
    if (await state.save(contact)) {
      setEditing(false);
      setError(null);
    } else {
      setError("mobile.checkup.call.save_failed");
    }
  }

  async function pick(): Promise<void> {
    const picked = await pickContactPhone();
    if (!picked) return; // backed out of the picker — nothing to say
    const contact = makeCloseOne(picked.name, picked.number);
    if (contact) await persist(contact);
    else setError("mobile.checkup.call.pick_invalid");
  }

  function confirmRemove(): void {
    Alert.alert(t("mobile.checkup.call.remove_title"), t("mobile.checkup.call.remove_body"), [
      { text: t("mobile.checkup.call.cancel"), style: "cancel" },
      {
        text: t("mobile.checkup.call.remove"),
        style: "destructive",
        onPress: () => {
          void state.remove().then((ok) => setError(ok ? null : "mobile.checkup.call.save_failed"));
        },
      },
    ]);
  }

  return (
    <View style={s.card}>
      <View style={s.titleRow}>
        <View style={s.iconBox}>
          <Ionicons name={saved ? "checkmark-circle" : "call-outline"} size={24} color={saved ? colors.green : colors.textSecondary} />
        </View>
        <Text style={s.title}>{t("mobile.checkup.call.title")}</Text>
      </View>
      <Text style={s.why}>{t("mobile.checkup.call.why")}</Text>

      {editing ? (
        <TypedNumberForm
          initial={saved}
          onPick={isContactPickerSupported() ? () => void pick() : undefined}
          onSave={(contact) => void persist(contact)}
          onInvalid={() => setError("mobile.checkup.call.invalid")}
          onCancel={() => { setEditing(false); setError(null); }}
        />
      ) : saved ? (
        <View style={s.block}>
          <Text style={s.savedName}>{saved.name ?? t("mobile.checkup.call.saved")}</Text>
          <Text style={s.savedNumber}>{formatPhone(saved.number)}</Text>
          <View style={s.gap}><CallButton contact={saved} /></View>
          <View style={s.linkRow}>
            <TextLink label={t("mobile.checkup.call.change")} onPress={() => setEditing(true)} />
            <TextLink label={t("mobile.checkup.call.remove")} onPress={confirmRemove} danger />
          </View>
        </View>
      ) : (
        <View style={s.block}>
          {isContactPickerSupported() && (
            <Button label={t("mobile.checkup.call.pick")} icon="person-circle-outline" primary onPress={() => void pick()} />
          )}
          <Button
            label={t("mobile.checkup.call.type")}
            icon="keypad-outline"
            primary={!isContactPickerSupported()}
            onPress={() => { setEditing(true); setError(null); }}
          />
        </View>
      )}

      {error && <Text style={s.error}>{t(error)}</Text>}

      <View style={s.noteRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textSecondary} />
        <Text style={s.note}>{t("mobile.checkup.call.saved_note")}</Text>
      </View>
    </View>
  );
}

interface FormProps {
  initial: CloseOne | null;
  /** Choose someone else from the address book instead; absent without a picker. */
  onPick?: () => void;
  onSave: (contact: CloseOne) => void;
  onInvalid: () => void;
  onCancel: () => void;
}

function TypedNumberForm({ initial, onPick, onSave, onInvalid, onCancel }: FormProps) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial?.name ?? "");
  const [number, setNumber] = useState(initial?.number ?? "");

  function submit() {
    const contact = makeCloseOne(name, number);
    if (contact) onSave(contact);
    else onInvalid();
  }

  return (
    <View style={s.block}>
      {onPick && <Button label={t("mobile.checkup.call.pick")} icon="person-circle-outline" onPress={onPick} />}
      <Text style={s.fieldLabel}>{t("mobile.checkup.call.number_label")}</Text>
      <TextInput
        style={s.input}
        value={number}
        onChangeText={setNumber}
        keyboardType="phone-pad"
        autoComplete="tel"
        textContentType="telephoneNumber"
        accessibilityLabel={t("mobile.checkup.call.number_label")}
      />
      <Text style={s.fieldLabel}>{t("mobile.checkup.call.name_label")}</Text>
      <TextInput
        style={s.input}
        value={name}
        onChangeText={setName}
        maxLength={MAX_NAME_LENGTH}
        autoCapitalize="words"
        accessibilityLabel={t("mobile.checkup.call.name_label")}
      />
      <Button label={t("mobile.checkup.call.save")} primary onPress={submit} />
      <Button label={t("mobile.checkup.call.cancel")} onPress={onCancel} />
    </View>
  );
}

interface ButtonProps {
  label: string;
  onPress: () => void;
  primary?: boolean;
  icon?: keyof typeof Ionicons.glyphMap;
}

function Button({ label, onPress, primary = false, icon }: ButtonProps) {
  return (
    <TouchableOpacity
      style={primary ? s.primary : s.secondary}
      onPress={onPress}
      activeOpacity={0.85}
      accessibilityRole="button"
    >
      {icon && <Ionicons name={icon} size={22} color={primary ? "#FFFFFF" : colors.textPrimary} />}
      <Text style={primary ? s.primaryLabel : s.secondaryLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

function TextLink({ label, onPress, danger = false }: { label: string; onPress: () => void; danger?: boolean }) {
  return (
    <TouchableOpacity
      onPress={onPress}
      accessibilityRole="button"
      hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}
    >
      <Text style={[s.textLink, danger && { color: colors.danger }]}>{label}</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  titleRow: { flexDirection: "row", alignItems: "center", gap: space.md },
  iconBox: {
    width: 44, height: 44, borderRadius: radius.icon, backgroundColor: colors.surface,
    alignItems: "center", justifyContent: "center",
  },
  title: { fontSize: 19, lineHeight: 25, fontWeight: "600", color: colors.textPrimary, flex: 1 },
  why: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, marginTop: space.md },
  block: { marginTop: space.md },
  gap: { marginTop: space.md },

  savedName: { fontSize: 18, lineHeight: 24, fontWeight: "600", color: colors.textPrimary, textAlign: "center" },
  savedNumber: { fontSize: 17, lineHeight: 23, color: colors.textSecondary, textAlign: "center", marginTop: 2 },
  linkRow: { flexDirection: "row", justifyContent: "space-around", marginTop: space.md },
  textLink: { fontSize: 16, fontWeight: "600", color: colors.blue, paddingVertical: space.xs },

  fieldLabel: { fontSize: 15, lineHeight: 20, color: colors.textSecondary, marginBottom: space.xs, marginTop: space.sm },
  input: {
    minHeight: 52, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke,
    backgroundColor: colors.surfaceRaised, color: colors.textPrimary, fontSize: 18, paddingHorizontal: space.md,
  },

  primary: {
    minHeight: 54, flexDirection: "row", gap: space.sm, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.sm,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF", textAlign: "center" },
  secondary: {
    minHeight: 54, flexDirection: "row", gap: space.sm, borderRadius: radius.control,
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.sm,
  },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary, textAlign: "center" },

  error: { fontSize: 15, lineHeight: 21, color: colors.amber, marginTop: space.sm },
  noteRow: { flexDirection: "row", alignItems: "flex-start", gap: 6, marginTop: space.md },
  note: { fontSize: 13, lineHeight: 18, color: colors.textSecondary, flex: 1 },
});
