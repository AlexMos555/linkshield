import { useState, useCallback } from "react";
import {
  View, Text, StyleSheet, ScrollView, Modal, TouchableOpacity, Platform, Alert,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { colors, type as typo, space, radius } from "../../src/utils/theme";
import { getStats } from "../../src/services/database";
import { HeroShield } from "../../src/components/shield/HeroShield";
import { CheckAnythingCard } from "../../src/components/shield/CheckAnythingCard";
import { RolloutList, RolloutItem } from "../../src/components/shield/RolloutList";
import { ShieldCard } from "../../src/components/shield/ShieldCard";
import { useNetworkShield } from "../../src/hooks/useNetworkShield";

/**
 * Shield Checklist home (docs/MOBILE_AUTO_PROTECTION.md §2,
 * docs/design/shield-checklist-design.md).
 *
 * Honesty contract: the hero reflects only VERIFIED shields. On iOS v1
 * nothing is verifiable yet, so the hero stays neutral and unbuilt shields
 * sit in a muted "Rolling out" section. No placebo states, no passive
 * clipboard monitoring (killed by design, not restyled).
 */

function rolloutItems(t: TFunction, platform: string): RolloutItem[] {
  const browser: RolloutItem = {
    icon: "compass-outline",
    title: t("mobile.shield.browser.title"),
    line: t(platform === "android" ? "mobile.rollout.browser_android" : "mobile.rollout.browser_ios"),
  };
  const messages: RolloutItem = {
    icon: "chatbubble-outline",
    title: t("mobile.shield.messages.title"),
    line: t(platform === "android" ? "mobile.rollout.messages_android" : "mobile.rollout.messages_ios"),
  };
  if (platform === "android") return [browser, messages];
  return [
    {
      icon: "globe-outline",
      title: t("mobile.shield.network.title"),
      line: t("mobile.rollout.network_ios"),
    },
    browser,
    messages,
  ];
}

export default function HomeScreen() {
  const router = useRouter();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [shareSheetVisible, setShareSheetVisible] = useState(false);
  const network = useNetworkShield();
  const { t } = useTranslation();

  useFocusEffect(useCallback(() => {
    getStats().then(setStats).catch(() => {});
  }, []));

  // Only shields that are shipped AND verifiable on this platform can count.
  // A running-but-unverified tunnel deliberately counts as 0.
  const totalCount = network.available ? 1 : 0;
  const verifiedCount = network.verified ? 1 : 0;
  const heroState =
    totalCount > 0 && verifiedCount === totalCount ? "all"
    : verifiedCount > 0 ? "partial"
    : "none";
  const needsSetup = network.available && network.state === "setup";

  const rollout = rolloutItems(t, Platform.OS);

  function confirmPause() {
    Alert.alert(
      t("mobile.shield.pause_confirm_title"),
      t("mobile.shield.pause_confirm_body"),
      [
        { text: t("mobile.settings.clear_cancel"), style: "cancel" },
        {
          text: t("mobile.shield.status.pause_action"),
          style: "destructive",
          onPress: () => void network.turnOff(),
        },
      ],
    );
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <HeroShield
        state={heroState}
        verifiedCount={verifiedCount}
        totalCount={totalCount}
        // No alarm state exists any more: nothing in the code detects a
        // competing VPN, so nothing may claim one. Unproven is shown as
        // unproven, not as a warning.
        attention={false}
      />

      {needsSetup && (
        <>
          {network.interrupted && (
            // The user had this on and something else turned it off (reboot
            // without always-on, a battery manager). Say so — "let's set up"
            // would tell them their earlier setup never happened.
            <View style={s.interruptedRow}>
              <Ionicons name="alert-circle-outline" size={15} color={colors.amber} />
              <Text style={s.interruptedText}>{t("mobile.home.interrupted")}</Text>
            </View>
          )}
          <TouchableOpacity
            style={s.cta}
            onPress={() => void network.turnOn()}
            activeOpacity={0.85}
            accessibilityRole="button"
          >
            <Text style={s.ctaLabel}>
              {t(network.interrupted ? "mobile.home.cta_turn_back_on" : "mobile.home.cta_turn_on")}
            </Text>
          </TouchableOpacity>
        </>
      )}

      {network.available && (
        <View style={s.section}>
          <ShieldCard
            icon="globe-outline"
            title={t("mobile.shield.network.title")}
            description={t("mobile.shield.network.desc")}
            honesty={t("mobile.shield.network.honesty")}
            state={network.state}
            stateCopy={
              network.state === "on" ? t("mobile.shield.network.state_on")
              // Probe in flight: say "checking" rather than flashing the
              // negative state at someone whose protection is fine.
              : network.probing ? t("mobile.shield.network.state_checking")
              : network.state === "offline" ? t("mobile.shield.network.state_offline")
              : network.state === "unverified" ? t("mobile.shield.network.state_unverified")
              : t("mobile.shield.network.state_setup")
            }
            onAction={() => void (network.state === "setup" ? network.turnOn() : undefined)}
            // The status pill only acts in "setup". Switching a running shield
            // OFF goes through the explicit pause row below, behind a confirm —
            // for a while there was no way out of a running shield at all
            // except the system VPN settings, which is its own kind of lie.
            onPause={confirmPause}
          />
          {network.verified && (
            // Android drops the VPN consent on reboot, so protection does not
            // come back by itself. Say so plainly and point at the one setting
            // that fixes it, rather than letting the user find out the hard way.
            <TouchableOpacity
              style={s.hintRow}
              onPress={network.openVpnSettings}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Ionicons name="information-circle-outline" size={13} color={colors.textSecondary} />
              <Text style={s.hintText}>{t("mobile.shield.always_on_hint")}</Text>
              <Ionicons name="chevron-forward" size={14} color={colors.textMuted} />
            </TouchableOpacity>
          )}
        </View>
      )}

      <View style={s.section}>
        <CheckAnythingCard
          onOpen={() => router.push("/check")}
          onPaste={() => router.push({ pathname: "/check", params: { paste: "1" } })}
          onScanQr={() => router.push("/scanner")}
          onHowToShare={() => setShareSheetVisible(true)}
        />
      </View>

      <View style={s.section}>
        <RolloutList items={rollout} />
      </View>

      {(stats.total_checks > 0 || stats.threats_blocked > 0) && (
        <View style={[s.section, s.activityCard]}>
          <ActivityColumn value={stats.total_checks} label={t("mobile.home.activity.checked")} />
          <ActivityColumn value={stats.threats_blocked} label={t("mobile.home.activity.blocked")} />
          <ActivityColumn value={stats.threats_warned} label={t("mobile.home.activity.warned")} />
        </View>
      )}

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
<Text style={s.privacy}>{t("mobile.home.privacy")}</Text>
      </View>

      <ShareHowToSheet visible={shareSheetVisible} onClose={() => setShareSheetVisible(false)} />
    </ScrollView>
  );
}

function ActivityColumn({ value, label }: { value: number; label: string }) {
  return (
    <View style={s.activityCol}>
      <Text style={s.activityNum}>{value}</Text>
      <Text style={s.activityLabel}>{label}</Text>
    </View>
  );
}

function ShareHowToSheet({ visible, onClose }: { visible: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <TouchableOpacity style={s.scrim} activeOpacity={1} onPress={onClose}>
        <View style={s.sheet}>
          <Text style={s.sheetTitle}>{t("mobile.home.check.share_sheet_title")}</Text>
<Text style={s.sheetBody}>{t("mobile.home.check.share_sheet_body")}</Text>
          <TouchableOpacity style={s.sheetBtn} onPress={onClose} activeOpacity={0.85}>
            <Text style={s.sheetBtnLabel}>{t("mobile.home.check.share_sheet_ok")}</Text>
          </TouchableOpacity>
        </View>
      </TouchableOpacity>
    </Modal>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 120 },
  section: { marginTop: space.xl + space.sm },

  interruptedRow: {
    flexDirection: "row", alignItems: "flex-start", gap: 6,
    marginTop: space.lg, paddingHorizontal: space.xs,
  },
  interruptedText: { ...typo.caption, color: colors.amber, flex: 1 },

  cta: {
    height: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  ctaLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  hintRow: {
    flexDirection: "row", alignItems: "center", gap: 6,
    marginTop: space.sm, paddingHorizontal: space.xs,
  },
  hintText: { ...typo.caption, color: colors.textSecondary, flex: 1 },

  activityCard: {
    flexDirection: "row",
    backgroundColor: colors.surface,
    borderRadius: radius.card,
    paddingVertical: space.lg,
  },
  activityCol: { flex: 1, alignItems: "center" },
  activityNum: { fontSize: 20, lineHeight: 25, fontWeight: "600", color: colors.textPrimary },
  activityLabel: { ...typo.caption, color: colors.textMuted, marginTop: 2 },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxl, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },

  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    padding: space.xxl, paddingBottom: space.huge,
  },
  sheetTitle: { ...typo.headline, color: colors.textPrimary },
  sheetBody: { ...typo.body, color: colors.textSecondary, marginTop: space.sm },
  sheetBtn: {
    height: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  sheetBtnLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
});
