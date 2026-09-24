import { View, Text, StyleSheet, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";
import type { HistoryFilter } from "../../utils/history-model";
import { useProtectionActive } from "../../hooks/useProtectionActive";

interface HistoryEmptyProps {
  filter: HistoryFilter;
  onCheckLink: () => void;
  onCheckMessage: () => void;
  /** Go to the Shield tab and start the same turn-on flow its button starts. */
  onTurnOn: () => void;
}

interface EmptyAction {
  label: string;
  onPress: () => void;
}

interface EmptyViewProps {
  icon: keyof typeof Ionicons.glyphMap;
  iconColor?: string;
  title: string;
  body: string;
  primary?: EmptyAction;
  secondary?: EmptyAction;
}

function EmptyView({ icon, iconColor = colors.textSecondary, title, body, primary, secondary }: EmptyViewProps) {
  return (
    <View style={s.empty}>
      <View style={s.emptyIcon}>
        <Ionicons name={icon} size={22} color={iconColor} />
      </View>
      <Text style={s.title}>{title}</Text>
      <Text style={s.body}>{body}</Text>
      {primary && (
        <TouchableOpacity style={s.primaryBtn} onPress={primary.onPress} activeOpacity={0.85} accessibilityRole="button">
          <Text style={s.primaryLabel}>{primary.label}</Text>
        </TouchableOpacity>
      )}
      {secondary && (
        <TouchableOpacity style={s.secondaryBtn} onPress={secondary.onPress} activeOpacity={0.85} accessibilityRole="button">
          <Text style={s.secondaryLabel}>{secondary.label}</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

/**
 * What an empty History says depends on WHY it is empty. "Nothing blocked
 * yet" is reassuring only while protection is on; said to someone whose
 * protection is off it is a lie of omission — nothing can be blocked at all.
 * So the blocked/all views read the live shield state and offer to turn
 * protection on, with the link check as the second action.
 */
export function HistoryEmpty({ filter, onCheckLink, onCheckMessage, onTurnOn }: HistoryEmptyProps) {
  const { t } = useTranslation();
  const checkLink: EmptyAction = { label: t("mobile.history.empty_cta"), onPress: onCheckLink };

  if (filter === "checked") {
    return (
      <EmptyView
        icon="search-outline"
        title={t("mobile.history.empty_checked_title")}
        body={t("mobile.history.empty_checked_body")}
        primary={checkLink}
      />
    );
  }
  if (filter === "sms") {
    return (
      <EmptyView
        icon="chatbubble-ellipses-outline"
        title={t("mobile.history.empty_sms_title")}
        body={t("mobile.history.empty_sms_body")}
        primary={{ label: t("mobile.home.sms_check.cta"), onPress: onCheckMessage }}
      />
    );
  }
  if (filter === "warned") {
    return (
      <EmptyView
        icon="alert-circle-outline"
        title={t("mobile.history.empty_warned_title")}
        body={t("mobile.history.empty_warned_body")}
        secondary={checkLink}
      />
    );
  }
  return <ProtectionEmpty checkLink={checkLink} onTurnOn={onTurnOn} />;
}

function ProtectionEmpty({ checkLink, onTurnOn }: { checkLink: EmptyAction; onTurnOn: () => void }) {
  const { t } = useTranslation();
  const protection = useProtectionActive();

  // No shield on this platform (iOS): History holds only what was checked by hand.
  if (!protection.available) {
    return (
      <EmptyView
        icon="time-outline"
        title={t("mobile.history.empty_title")}
        body={t("mobile.history.empty_body")}
        primary={checkLink}
      />
    );
  }
  if (protection.active) {
    return (
      <EmptyView
        icon="shield-checkmark-outline"
        iconColor={colors.green}
        title={t("mobile.history.empty_on_title")}
        body={t("mobile.history.empty_on_body")}
        secondary={checkLink}
      />
    );
  }
  return (
    <EmptyView
      icon="shield-outline"
      iconColor={colors.amber}
      title={t("mobile.history.empty_off_title")}
      body={t("mobile.history.empty_off_body")}
      primary={{ label: t("mobile.home.cta_turn_on"), onPress: onTurnOn }}
      secondary={checkLink}
    />
  );
}

const s = StyleSheet.create({
  empty: { alignItems: "center", paddingHorizontal: space.md, paddingTop: space.xxxl },
  emptyIcon: {
    width: 56, height: 56, borderRadius: radius.icon,
    backgroundColor: colors.surfaceRaised, borderWidth: 1, borderColor: colors.stroke,
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.title2, color: colors.textPrimary, marginTop: space.lg, textAlign: "center" },
  body: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },
  primaryBtn: {
    minHeight: 50, paddingHorizontal: space.xxxl, backgroundColor: colors.blue,
    borderRadius: radius.control, alignItems: "center", justifyContent: "center",
    marginTop: space.xl, alignSelf: "stretch",
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondaryBtn: {
    minHeight: 50, paddingHorizontal: space.xxxl, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.control, alignItems: "center", justifyContent: "center",
    marginTop: space.md, alignSelf: "stretch",
  },
  secondaryLabel: { fontSize: 17, fontWeight: "600", color: colors.textPrimary },
});
