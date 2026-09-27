import { View, Text, StyleSheet, ActivityIndicator, TouchableOpacity } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";

/**
 * Pieces the two link-check screens (app/shared.tsx, app/result.tsx) share
 * for the states the list-first verdict adds (src/hooks/useDomainCheck.ts).
 */

interface ServerDetailsNoteProps {
  /** The server check is in flight. */
  pending: boolean;
  /** It failed (the verdict on screen came from the list alone). */
  failed: boolean;
  /** It answered "safe" — for a site the list calls a scam. */
  calm: boolean;
  onRetry: () => void;
}

/**
 * Under a verdict from the on-device list: what the server part is doing.
 * The verdict itself never waits for it and never changes because of it.
 */
export function ServerDetailsNote({ pending, failed, calm, onRetry }: ServerDetailsNoteProps) {
  const { t } = useTranslation();
  if (pending) {
    return (
      <View style={s.row} accessibilityLiveRegion="polite">
        <ActivityIndicator size="small" color={colors.textMuted} />
        <Text style={s.note}>{t("mobile.result.details_loading")}</Text>
      </View>
    );
  }
  if (failed) {
    return (
      <View style={s.column}>
        <Text style={s.noteCentered}>{t("mobile.result.details_failed")}</Text>
        <TouchableOpacity onPress={onRetry} activeOpacity={0.7} accessibilityRole="button" style={s.retry}>
          <Text style={s.retryLabel}>{t("mobile.result.details_retry")}</Text>
        </TouchableOpacity>
      </View>
    );
  }
  if (calm) return <Text style={s.noteCentered}>{t("mobile.result.listed_server_calm")}</Text>;
  return null;
}

/**
 * The name does not exist. Said plainly — not scored as a scam for having no
 * HTTPS and no mail server, which is what a typo in a bank's address used to
 * get (report #18).
 */
export function NotFoundCard({ domain }: { domain: string }) {
  const { t } = useTranslation();
  return (
    <View
      style={s.card}
      accessibilityRole="summary"
      accessibilityLabel={`${t("mobile.result.not_found_title")}. ${domain}`}
    >
      <Ionicons name="help-circle-outline" size={48} color={colors.amber} />
      <Text style={s.title}>{t("mobile.result.not_found_title")}</Text>
      <Text style={s.domain}>{domain}</Text>
      <Text style={s.body}>{t("mobile.result.not_found_body")}</Text>
    </View>
  );
}

/** The verdict ring's place when there is no score to put in it: the list decided. */
export function ListedMark({ size }: { size: number }) {
  return (
    <View style={[s.mark, { width: size, height: size, borderRadius: size / 2 }]}>
      <Ionicons name="warning" size={Math.round(size * 0.42)} color={colors.danger} />
    </View>
  );
}

const s = StyleSheet.create({
  row: {
    flexDirection: "row", alignItems: "center", justifyContent: "center",
    gap: space.sm, marginTop: space.md,
  },
  column: { alignItems: "center", marginTop: space.md },
  note: { ...typo.caption, color: colors.textMuted },
  noteCentered: { ...typo.caption, color: colors.textMuted, textAlign: "center", marginTop: space.md },
  retry: { minHeight: 44, justifyContent: "center", paddingHorizontal: space.md },
  retryLabel: { ...typo.body, fontWeight: "600", color: colors.blue },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.amberStroke,
    borderRadius: radius.card, padding: space.xxl,
    alignItems: "center", marginBottom: space.md,
  },
  title: { ...typo.title2, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  domain: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  body: { ...typo.body, color: colors.textPrimary, textAlign: "center", marginTop: space.md },

  mark: {
    borderWidth: 8, borderColor: colors.dangerStroke,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
});
