import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";

export type ShieldState =
  | "setup"
  | "on"
  | "paused"
  | "conflict"
  | "network-blocked"
  | "unverified"
  /** Tunnel up but the phone has no internet — nothing to filter, not a fault. */
  | "offline";

interface ShieldCardProps {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  description: string;
  honesty: string;
  state: ShieldState;
  stateCopy?: string;
  onAction?: () => void;
  /**
   * Explicit, secondary way OUT of a running shield. The status pill on the
   * right is deliberately not a toggle — an accidental tap must never switch
   * protection off — but a running shield with no exit at all sends the user
   * hunting through system VPN settings. Rendered only when provided and only
   * for running states; the caller confirms before acting.
   */
  onPause?: () => void;
}

const AMBER_STATES: ReadonlySet<ShieldState> = new Set(["conflict", "network-blocked"]);

/**
 * One shield, one honest state. The status control on the right is the only
 * interactive element for non-default states; ON is a pill, never a toggle.
 * Every card carries an ⓘ honesty line — non-negotiable (spec §2.4).
 */
export function ShieldCard(props: ShieldCardProps) {
  const { icon, title, description, honesty, state, stateCopy, onAction, onPause } = props;
  const { t } = useTranslation();
  const running = state === "on" || state === "unverified" || state === "conflict" || state === "offline";
  const amber = AMBER_STATES.has(state);
  const iconColor = state === "on" ? colors.green : amber ? colors.amber : colors.textSecondary;
  const desc = stateCopy ?? description;

  return (
    <View style={s.card}>
      <View style={s.titleRow}>
        <View style={s.iconBox}>
          <Ionicons name={icon} size={22} color={iconColor} />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={s.title}>{title}</Text>
          {/* No line cap. State copy is a full honest sentence or two, and a
              cap ate the half that mattered ("…and will filter as soon as
              you're back onl…"). The card grows; that is fine. */}
          <Text style={[s.desc, amber && { color: colors.amber }]}>
            {desc}
          </Text>
        </View>
        <StatusControl state={state} onAction={onAction} />
      </View>
      <View style={s.honestyRow}>
        <Ionicons name="information-circle-outline" size={13} color={colors.textSecondary} />
        <Text style={s.honesty}>{honesty}</Text>
      </View>
      {running && onPause && (
        <TouchableOpacity
          style={s.pauseRow}
          onPress={onPause}
          activeOpacity={0.7}
          accessibilityRole="button"
          accessibilityLabel={t("mobile.shield.status.pause_action")}
        >
          <Ionicons name="pause-circle-outline" size={15} color={colors.textMuted} />
          <Text style={s.pauseLabel}>{t("mobile.shield.status.pause_action")}</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

function StatusControl({ state, onAction }: { state: ShieldState; onAction?: () => void }) {
  const { t } = useTranslation();
  if (state === "setup") {
    return (
      <TouchableOpacity
        style={s.setupBtn}
        onPress={onAction}
        activeOpacity={0.85}
        hitSlop={{ top: 4, bottom: 4, left: 4, right: 4 }}
        accessibilityRole="button"
        accessibilityLabel={t("mobile.shield.status.setup_btn")}
      >
        <Text style={s.setupLabel}>{t("mobile.shield.status.setup_btn")}</Text>
      </TouchableOpacity>
    );
  }
  if (state === "on") {
    return (
      <View style={[s.pill, { backgroundColor: colors.greenWash, borderColor: colors.greenStroke }]}>
        <Ionicons name="checkmark-circle" size={16} color={colors.green} />
        <Text style={[s.pillLabel, { color: colors.green }]}>{t("mobile.shield.status.on_pill")}</Text>
      </View>
    );
  }
  if (state === "paused") {
    return (
      <TouchableOpacity
        style={[s.pill, { backgroundColor: colors.surface, borderColor: colors.stroke }]}
        onPress={onAction}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Ionicons name="pause-circle-outline" size={16} color={colors.textSecondary} />
        <Text style={[s.pillLabel, { color: colors.textSecondary }]}>{t("mobile.shield.status.paused_pill")}</Text>
      </TouchableOpacity>
    );
  }
  if (state === "unverified") {
    return (
      <View style={[s.pill, { backgroundColor: colors.surface, borderColor: colors.stroke }]}>
        <Text style={[s.pillLabel, { color: colors.textSecondary }]}>{t("mobile.shield.status.unverified_pill")}</Text>
      </View>
    );
  }
  if (state === "offline") {
    return (
      <View style={[s.pill, { backgroundColor: colors.surface, borderColor: colors.stroke }]}>
        <Ionicons name="cloud-offline-outline" size={16} color={colors.textSecondary} />
        <Text style={[s.pillLabel, { color: colors.textSecondary }]}>{t("mobile.shield.status.offline_pill")}</Text>
      </View>
    );
  }
  // conflict / network-blocked
  return (
    <TouchableOpacity
      style={[s.pill, { backgroundColor: colors.amberWash, borderColor: colors.amberStroke }]}
      onPress={onAction}
      activeOpacity={0.85}
      accessibilityRole="button"
    >
      <Ionicons name="alert-circle" size={16} color={colors.amber} />
      <Text style={[s.pillLabel, { color: colors.amber }]}>{t("mobile.shield.status.attention_pill")}</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  pauseRow: {
    flexDirection: "row", alignItems: "center", gap: 6,
    alignSelf: "flex-start", marginTop: space.sm, paddingVertical: 6, paddingHorizontal: 2,
  },
  pauseLabel: { ...typo.caption, color: colors.textMuted },
  card: {
    backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg,
  },
  titleRow: { flexDirection: "row", alignItems: "flex-start", gap: space.md },
  iconBox: {
    width: 40, height: 40, borderRadius: radius.icon,
    backgroundColor: "#FFFFFF0A",
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.headline, color: colors.textPrimary },
  desc: { ...typo.body, color: colors.textSecondary, marginTop: 2 },
  honestyRow: { flexDirection: "row", alignItems: "flex-start", gap: 6, marginTop: 10 },
  honesty: { ...typo.caption, color: colors.textSecondary, flex: 1 },
  setupBtn: {
    height: 36, paddingHorizontal: 14,
    backgroundColor: colors.blue, borderRadius: radius.pill,
    alignItems: "center", justifyContent: "center",
  },
  setupLabel: { fontSize: 15, fontWeight: "700", color: "#FFFFFF" },
  pill: {
    flexDirection: "row", alignItems: "center", gap: 4,
    borderWidth: 1, borderRadius: radius.pill,
    paddingHorizontal: 10, paddingVertical: 5,
  },
  pillLabel: { fontSize: 13, fontWeight: "600" },
});
