import { useMemo } from "react";
import { Alert, Text, TouchableOpacity, View } from "react-native";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { ShieldItem } from "../../utils/history-model";
import { SHIELD_KIND_KEYS, SHIELD_SOURCE_KEYS } from "../../utils/history-labels";
import { absoluteTime, relativeTime } from "../../utils/relative-time";
import { allowedSites, allowSite, removeAllowedSite } from "../../services/shield-log";
import { HISTORY_TONES, shieldIcon, shieldTone } from "./HistoryRows";
import { Fact, SheetFrame, sheetStyles as s } from "./SheetFrame";

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
    <SheetFrame onClose={onClose}>
      <View style={s.headRow}>
        <View style={[s.icon, { backgroundColor: tone.wash, borderColor: tone.stroke }]}>
          <Ionicons name={shieldIcon(item)} size={24} color={tone.color} />
        </View>
        <Text style={[s.what, { color: tone.color }]} accessibilityRole="header">
          {t(SHIELD_KIND_KEYS[item.kind])}
        </Text>
      </View>

      <Text style={s.title} selectable>{item.domain}</Text>
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
    </SheetFrame>
  );
}
