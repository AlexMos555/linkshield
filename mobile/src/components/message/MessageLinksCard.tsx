import { View, Text, StyleSheet, ActivityIndicator } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { MessageLink } from "../../../modules/cleanway-vpn";
import { colors, space, radius } from "../../utils/theme";
import { LINK_KEYS } from "../../utils/message-labels";
import { linkVerdict, type LinkCheck, type LinkVerdict } from "../../utils/message-verdict";

interface Props {
  links: MessageLink[];
  linkChecks: Readonly<Record<string, LinkCheck>>;
  /** A synced blocklist was on the phone; without it no link could match it. */
  listAvailable: boolean;
  listStale: boolean;
}

type Look = { icon: keyof typeof Ionicons.glyphMap; color: string };

// Only the list and the server may paint a link red or amber. A short link or
// a clean server answer stays neutral: neither proves anything about safety.
// Nothing here wears a shield tick — not even a site the person allowed.
const LOOKS: Record<Exclude<LinkVerdict, "checking">, Look> = {
  blocked: { icon: "close-circle", color: colors.danger },
  dangerous: { icon: "close-circle", color: colors.danger },
  caution: { icon: "alert-circle", color: colors.amber },
  shortener: { icon: "eye-off-outline", color: colors.textSecondary },
  messenger: { icon: "chatbubbles-outline", color: colors.textSecondary },
  allowed: { icon: "person-outline", color: colors.textSecondary },
  system: { icon: "help-circle-outline", color: colors.textMuted },
  clean: { icon: "checkmark-circle-outline", color: colors.textSecondary },
  not_checked: { icon: "help-circle-outline", color: colors.textMuted },
  rate_limited: { icon: "time-outline", color: colors.textMuted },
  offline: { icon: "cloud-offline-outline", color: colors.textMuted },
  timeout: { icon: "time-outline", color: colors.textMuted },
  failed: { icon: "help-circle-outline", color: colors.textMuted },
};

/**
 * The links found in the message, each with what we know about it. The link
 * is shown as written so the person recognises it; only its host was ever
 * sent anywhere.
 */
export function MessageLinksCard({ links, linkChecks, listAvailable, listStale }: Props) {
  const { t } = useTranslation();
  return (
    <View style={s.card}>
      <Text style={s.cardTitle}>{t("mobile.message.links_title")}</Text>
      {links.map((link, i) => (
        <LinkRow key={`${i}:${link.text}`} link={link} verdict={linkVerdict(link, linkChecks)} first={i === 0} />
      ))}
      {!listAvailable ? (
        <Text style={s.note}>{t("mobile.message.list_missing")}</Text>
      ) : listStale ? (
        <Text style={s.note}>{t("mobile.message.list_stale")}</Text>
      ) : null}
    </View>
  );
}

function LinkRow({ link, verdict, first }: { link: MessageLink; verdict: LinkVerdict; first: boolean }) {
  const { t } = useTranslation();
  const label = t(LINK_KEYS[verdict]);
  const look = verdict === "checking" ? null : LOOKS[verdict];
  return (
    <View
      style={[s.row, !first && s.rowBorder]}
      accessible
      accessibilityLabel={`${link.host}. ${label}`}
    >
      <Text style={s.link} numberOfLines={2} ellipsizeMode="middle">{link.text}</Text>
      <View style={s.statusRow}>
        {look ? (
          <Ionicons name={look.icon} size={18} color={look.color} />
        ) : (
          <ActivityIndicator size="small" color={colors.textSecondary} />
        )}
        <Text style={[s.status, { color: look?.color ?? colors.textSecondary }]}>{label}</Text>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { fontSize: 18, lineHeight: 24, fontWeight: "600", color: colors.textPrimary, marginBottom: space.xs },
  row: { paddingVertical: space.md },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  link: { fontSize: 16, lineHeight: 22, color: colors.textPrimary },
  statusRow: { flexDirection: "row", alignItems: "center", gap: space.sm, marginTop: 6 },
  status: { fontSize: 16, lineHeight: 22, fontWeight: "600", flex: 1 },
  note: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, marginTop: space.sm },
});
