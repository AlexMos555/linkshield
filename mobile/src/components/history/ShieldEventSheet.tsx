import { useMemo } from "react";
import {
  Alert, Modal, Pressable, ScrollView, StyleSheet, Text, TouchableOpacity, View,
} from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space, radius } from "../../utils/theme";
import type { ShieldItem } from "../../utils/history-model";
import { SHIELD_KIND_KEYS, SHIELD_SOURCE_KEYS } from "../../utils/history-labels";
import { absoluteTime, relativeTime } from "../../utils/relative-time";
import { allowedSites, allowSite, removeAllowedSite } from "../../services/shield-log";
import { HISTORY_TONES, shieldIcon, shieldTone } from "./HistoryRows";

interface ShieldEventSheetProps {
  /** The event to explain; null keeps the sheet closed. */
  item: ShieldItem | null;
  onClose: () => void;
  /** An allow was added or removed: the list must be re-read. */
  onChanged: () => void;
  /** "More about this site" — the caller closes the sheet and opens the site's check. */
  onMore: (domain: string) => void;
}

/**
 * Why a shield acted, in plain words: what happened, when, which shield, and
 * what (if anything) to do now.
 *
 * The rescue ("not a scam — allow it") is here because a person who cannot
 * undo a false positive turns protection off altogether. It is the quietest
 * button on the sheet and sits behind a confirm, so the sheet never nudges
 * anyone toward opening a scam site. "Close" is the main action: for a block
 * there is nothing to do.
 */
export function ShieldEventSheet({ item, onClose, onChanged, onMore }: ShieldEventSheetProps) {
  const { t, i18n } = useTranslation();
  // Read when the sheet opens: the allow list can change in Settings or from
  // a notification between two openings.
  const allowedNow = useMemo(
    () => (item?.kind === "allowed" ? allowedSites().includes(item.domain) : false),
    [item],
  );

  if (!item) return null;

  const tone = HISTORY_TONES[shieldTone(item)];
  const when = [relativeTime(item.ts, t), absoluteTime(item.ts, i18n.language)].filter(Boolean).join(" · ");
  const source = item.source ? t(SHIELD_SOURCE_KEYS[item.source]) : "";
  const body = item.kind === "blocked" ? t("mobile.history.detail.blocked_body")
    : item.kind === "warned" ? t("mobile.history.detail.warned_body")
    : allowedNow ? t("mobile.history.detail.allowed_body")
    : t("mobile.history.detail.allowed_removed_body");
  const advice = item.kind === "blocked" ? t("mobile.history.detail.blocked_calm")
    : item.kind === "warned" ? t("mobile.history.detail.warned_advice")
    : "";

  function confirmAllow(domain: string) {
    Alert.alert(
      t("mobile.settings.allow_confirm_title"),
      t("mobile.history.detail.allow_confirm_body", { domain }),
      [
        { text: t("mobile.settings.clear_cancel"), style: "cancel" },
        {
          text: t("mobile.history.shield_allow_action"),
          onPress: () => {
            allowSite(domain);
            onClose();
            onChanged();
          },
        },
      ],
    );
  }

  function blockAgain(domain: string) {
    removeAllowedSite(domain);
    onClose();
    onChanged();
  }

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
            <View style={s.headRow}>
              <View style={[s.icon, { backgroundColor: tone.wash, borderColor: tone.stroke }]}>
                <Ionicons name={shieldIcon(item)} size={24} color={tone.color} />
              </View>
              <Text style={[s.what, { color: tone.color }]} accessibilityRole="header">
                {t(SHIELD_KIND_KEYS[item.kind])}
              </Text>
            </View>

            <Text style={s.domain} selectable>{item.domain}</Text>
            <Text style={s.body}>{body}</Text>

            <View style={s.facts}>
              {when !== "" && <Fact label={t("mobile.history.detail.when")} value={when} />}
              {source !== "" && item.kind !== "allowed" && (
                <Fact
                  label={t(item.kind === "warned" ? "mobile.history.detail.by_warned" : "mobile.history.detail.by_blocked")}
                  value={source}
                />
              )}
            </View>

            {advice !== "" && <Text style={s.advice}>{advice}</Text>}

            <TouchableOpacity style={s.primaryBtn} onPress={onClose} activeOpacity={0.85} accessibilityRole="button">
              <Text style={s.primaryLabel}>{t("mobile.history.detail.close")}</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={s.secondaryBtn}
              onPress={() => onMore(item.domain)}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Text style={s.secondaryLabel}>{t("mobile.history.detail.more")}</Text>
            </TouchableOpacity>

            {item.kind !== "allowed" && (
              <TouchableOpacity
                style={s.quietBtn}
                onPress={() => confirmAllow(item.domain)}
                activeOpacity={0.85}
                accessibilityRole="button"
              >
                <Text style={s.quietLabel}>{t("mobile.history.detail.allow")}</Text>
              </TouchableOpacity>
            )}

            {item.kind === "allowed" && allowedNow && (
              <TouchableOpacity
                style={s.quietBtn}
                onPress={() => blockAgain(item.domain)}
                activeOpacity={0.85}
                accessibilityRole="button"
              >
                <Text style={s.quietLabel}>{t("mobile.history.detail.block_again")}</Text>
              </TouchableOpacity>
            )}
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <View style={s.factRow} accessible accessibilityLabel={`${label}: ${value}`}>
      <Text style={s.factLabel}>{label}</Text>
      <Text style={s.factValue}>{value}</Text>
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
  headRow: { flexDirection: "row", alignItems: "center", gap: space.md },
  icon: {
    width: 44, height: 44, borderRadius: radius.icon, borderWidth: 1,
    alignItems: "center", justifyContent: "center",
  },
  what: { ...typo.headline, flex: 1 },
  domain: { ...typo.title2, color: colors.textPrimary, marginTop: space.lg },
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
