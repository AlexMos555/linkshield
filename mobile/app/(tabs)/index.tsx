import { useState, useCallback, useEffect } from "react";
import {
  View, Text, StyleSheet, ScrollView, Modal, TouchableOpacity, Platform, Alert, Linking,
} from "react-native";
import { useRouter, useFocusEffect, useLocalSearchParams } from "expo-router";
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
import { useShieldBlockTotals } from "../../src/hooks/useShieldBlockTotals";
import { useUpdateCheck } from "../../src/hooks/useUpdateCheck";
import { useLinkGuard } from "../../src/hooks/useLinkGuard";
import { UpdateBanner } from "../../src/components/shield/UpdateBanner";
import { MessageCheckCard } from "../../src/components/shield/MessageCheckCard";
import { SmsShieldCard } from "../../src/components/shield/SmsShieldCard";
import { useSmsShield } from "../../src/hooks/useSmsShield";
import { isSmsShieldListening } from "../../src/utils/sms-shield-view";
import { rustoreListingUrl } from "../../src/config/stores";
import { isMessageCheckSupported, isVpnRunning, linkListAvailable, privateDnsStrictHost } from "../../modules/cleanway-vpn";
import type { HistoryFilter } from "../../src/utils/history-model";

/**
 * Shield Checklist home (docs/MOBILE_AUTO_PROTECTION.md §2,
 * docs/design/shield-checklist-design.md).
 *
 * Honesty contract: the hero reflects only VERIFIED shields. On iOS v1
 * nothing is verifiable yet, so the hero stays neutral and unbuilt shields
 * sit in a muted "Rolling out" section. No placebo states, no passive
 * clipboard monitoring (killed by design, not restyled).
 */

function rolloutItems(t: TFunction, platform: string, messageCheck: boolean): RolloutItem[] {
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
  // On Android the browser/link layer ships as the Link-checking shield card
  // and SMS as the message-check card, so nothing is "rolling out" there. No
  // line promises an automatic check of every incoming SMS: only the RuStore
  // build can do that (it has its own card), and the website APK must never
  // ask for SMS access. The SMS row stays only for a native build without the
  // analyzer, where it is still true.
  if (platform === "android") return messageCheck ? [] : [messages];
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
  // setup=1: History's "Turn on protection" sends people here to run the
  // same flow as the button below, instead of a second copy of it.
  const { setup } = useLocalSearchParams<{ setup?: string }>();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [shareSheetVisible, setShareSheetVisible] = useState(false);
  const network = useNetworkShield();
  // The link guard (Android): when Cleanway is the default link handler, tapped
  // links are checked before they open — the exact SMS-phishing defense.
  const linkGuard = useLinkGuard();
  // The SMS check (Android, native analyzer present). A tool, not a shield:
  // it is deliberately left out of the hero counts below.
  const [messageCheck] = useState(() => isMessageCheckSupported());
  // The automatic check of every incoming SMS — a real shield, but only in
  // the RuStore build (`supported`); everywhere else it does not exist.
  const sms = useSmsShield();
  // The website APK may point to the RuStore build for that, once its
  // listing is live; until then the line does not exist.
  const [storeUrl] = useState(() => (sms.supported || Platform.OS !== "android" ? null : rustoreListingUrl()));
  // The link guard checks tapped links against the blocklist, and only the
  // "All apps" shield downloads one — so the SMS card may promise checked
  // links only once a list exists.
  const [linkListReady, setLinkListReady] = useState(false);
  // What the DNS shield did — including while the app was closed. Merged
  // into the activity card so "Blocked" counts real protection, not only
  // links the person pasted by hand.
  const shieldTotals = useShieldBlockTotals();
  const { t, i18n } = useTranslation();
  // Sideloaded (Tele2 direct-APK) users have no store to push updates; offer a
  // fresher build here, and insist if the running one is below the security floor.
  const update = useUpdateCheck(i18n.language);

  useFocusEffect(useCallback(() => {
    getStats().then(setStats).catch(() => {});
  }, []));

  useFocusEffect(useCallback(() => {
    let alive = true;
    void linkListAvailable().then((ok) => {
      if (alive) setLinkListReady(ok);
    });
    return () => {
      alive = false;
    };
  }, [network.state, network.blocklist.count]));

  const blockedTotal = stats.threats_blocked + shieldTotals.blocked;
  // An SMS the automatic check flagged was warned about, never blocked: the
  // phone's SMS app shows it anyway. History's Warned filter lists the same.
  const warnedTotal = stats.threats_warned + shieldTotals.warned + sms.status.flaggedCount;

  // Only shields that are shipped AND verifiable on this platform can count;
  // a running-but-unverified tunnel deliberately counts as 0. Equally, every
  // shield that DOES exist on this device must be counted, or the
  // headline lies: with only the DNS shield counted, a phone whose link guard
  // was never set up still read "All shields on and verified". The manual SMS
  // check is not a shield (it acts only on what the person hands it) and
  // stays out; the automatic one (RuStore build) is, and counts as verified
  // only with permission, receiver, notifications and battery all in place.
  const totalCount = (network.available ? 1 : 0) + (linkGuard.available ? 1 : 0) + (sms.supported ? 1 : 0);
  const verifiedCount = (network.verified ? 1 : 0) + (linkGuard.on ? 1 : 0) + (sms.verified ? 1 : 0);
  const heroState =
    totalCount > 0 && verifiedCount === totalCount ? "all"
    : verifiedCount > 0 ? "partial"
    : "none";
  const needsSetup = network.available && network.state === "setup";

  const rollout = rolloutItems(t, Platform.OS, messageCheck);

  /**
   * Prominent disclosure, shown BEFORE Android's own consent dialog.
   *
   * Play requires a VpnService app to explain, in its own UI, what the VPN is
   * for and what it does with traffic — and our own bar says a person should
   * never grant something this large without being told plainly. The system
   * dialog says "can monitor network traffic", which is frightening and
   * uninformative; this says what we actually do (match names on the phone,
   * forward the rest to a public resolver, read nothing else).
   */
  function startWithDisclosure() {
    Alert.alert(
      t("mobile.shield.disclosure.title"),
      t("mobile.shield.disclosure.body"),
      [
        { text: t("mobile.shield.disclosure.cancel"), style: "cancel" },
        { text: t("mobile.shield.disclosure.continue"), onPress: () => void network.turnOn() },
      ],
      { cancelable: true },
    );
  }

  useEffect(() => {
    if (setup !== "1") return;
    router.setParams({ setup: undefined });
    // Only where the button itself would show: not running, and no strict
    // Private DNS (then the card explains which setting to change instead).
    if (network.available && !isVpnRunning() && !privateDnsStrictHost()) startWithDisclosure();
    // startWithDisclosure is recreated each render; the param is the trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setup, network.available]);

  /**
   * The counters open History on the matching filter, so "Blocked 3" can
   * always be answered with "which three". The filters are defined by what
   * these numbers add up (see history-model.ts).
   */
  function openHistory(filter: HistoryFilter) {
    router.navigate({ pathname: "/history", params: { filter } });
  }

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
        interrupted={needsSetup && network.interrupted}
      />

      <UpdateBanner status={update} />

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
            onPress={startWithDisclosure}
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
              // Strict Private DNS: the one state whose fix is a system
              // setting. Name the provider so the user recognises it.
              network.state === "conflict"
                ? t("mobile.shield.network.state_private_dns", { host: network.privateDnsHost ?? "" })
              : network.state === "on" ? t("mobile.shield.network.state_on")
              // Probe in flight: say "checking" rather than flashing the
              // negative state at someone whose protection is fine.
              : network.probing ? t("mobile.shield.network.state_checking")
              : network.state === "offline" ? t("mobile.shield.network.state_offline")
              : network.state === "unverified" ? t("mobile.shield.network.state_unverified")
              : t("mobile.shield.network.state_setup")
            }
            onAction={() => {
              if (network.state === "setup") startWithDisclosure();
              else if (network.state === "conflict") network.openPrivateDnsSettings();
            }}
            // The status pill only acts in "setup". Switching a running shield
            // OFF goes through the explicit pause row below, behind a confirm —
            // for a while there was no way out of a running shield at all
            // except the system VPN settings, which is its own kind of lie.
            onPause={confirmPause}
          />
          {(network.state === "on" || network.state === "unverified" || network.state === "offline") && (
            // The list is a separate truth from the tunnel: green tunnel +
            // no/stale list = nothing is being blocked from the list. Say it
            // in its own line, never fold it into "You're protected".
            <TouchableOpacity
              style={s.hintRow}
              onPress={network.refreshBlocklist}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Ionicons
                name={network.blocklist.stale ? "alert-circle-outline" : "list-outline"}
                size={13}
                color={network.blocklist.stale ? colors.amber : colors.textSecondary}
              />
              <Text style={[s.hintText, network.blocklist.stale && { color: colors.amber }]}>
                {network.blocklist.count > 0 && !network.blocklist.stale
                  // "updated 0h ago" is what a freshly synced list said — the
                  // first thing a new user reads about it, and it sounds like
                  // a bug. Under an hour it just says "just updated".
                  ? (network.blocklist.ageMs ?? 0) < 3_600_000
                    ? t("mobile.shield.blocklist.status_fresh", { count: network.blocklist.count })
                    : t("mobile.shield.blocklist.status", {
                        count: network.blocklist.count,
                        hours: Math.round((network.blocklist.ageMs ?? 0) / 3_600_000),
                      })
                  : network.blocklist.count > 0
                    ? t("mobile.shield.blocklist.stale", { count: network.blocklist.count })
                    : t("mobile.shield.blocklist.missing")}
              </Text>
              <Ionicons name="refresh-outline" size={14} color={colors.textMuted} />
            </TouchableOpacity>
          )}
          {network.state === "conflict" && (
            <TouchableOpacity
              style={s.hintRow}
              onPress={network.openPrivateDnsSettings}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Ionicons name="settings-outline" size={13} color={colors.amber} />
              <Text style={[s.hintText, { color: colors.amber }]}>{t("mobile.shield.network.private_dns_cta")}</Text>
              <Ionicons name="chevron-forward" size={14} color={colors.amber} />
            </TouchableOpacity>
          )}
          {network.verified && (
            // Protection returns on its own after a reboot; Always-on VPN
            // additionally starts it with the phone, before any app receives
            // BOOT_COMPLETED. Offer it as an upgrade, not as a requirement.
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

      {linkGuard.available && (
        <View style={s.section}>
          <ShieldCard
            icon="link-outline"
            title={t("mobile.shield.linkguard.title")}
            description={t("mobile.shield.linkguard.desc")}
            honesty={t("mobile.shield.linkguard.honesty")}
            // Live RoleManager check — green here means Cleanway really is the
            // default link handler, not a placebo. Setup offers to become one.
            state={linkGuard.on ? "on" : "setup"}
            stateCopy={
              linkGuard.on
                ? t("mobile.shield.linkguard.state_on")
                : t("mobile.shield.linkguard.state_setup")
            }
            onAction={() => {
              // ON is a pill, not a toggle (same contract as the network card):
              // tapping opens the system screen where the role can be handed
              // back, because there is no API to release it ourselves.
              if (linkGuard.on) void linkGuard.manage();
              else void linkGuard.enable();
            }}
          />
        </View>
      )}

      {sms.supported && (
        <View style={s.section}>
          <SmsShieldCard sms={sms} />
        </View>
      )}

      {messageCheck && (
        <View style={s.section}>
          <MessageCheckCard
            onOpen={() => router.push("/message")}
            linkGuardAvailable={linkGuard.available}
            linkGuardOn={linkGuard.on}
            linkListReady={linkListReady}
            autoSms={sms.supported ? (isSmsShieldListening(sms.view) ? "listening" : "off") : undefined}
            onOpenStore={storeUrl ? () => void Linking.openURL(storeUrl).catch(() => {}) : undefined}
          />
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

      {rollout.length > 0 && (
        <View style={s.section}>
          <RolloutList items={rollout} />
        </View>
      )}

      {(stats.total_checks > 0 || blockedTotal > 0 || warnedTotal > 0) && (
        <View style={[s.section, s.activityCard]}>
          <View style={s.activityRow}>
            <ActivityColumn
              value={stats.total_checks}
              label={t("mobile.home.activity.checked")}
              onPress={() => openHistory("checked")}
            />
            <ActivityColumn
              value={blockedTotal}
              label={t("mobile.home.activity.blocked")}
              onPress={() => openHistory("blocked")}
            />
            <ActivityColumn
              value={warnedTotal}
              label={t("mobile.home.activity.warned")}
              onPress={() => openHistory("warned")}
            />
          </View>
          <Text style={s.activityHint}>{t("mobile.home.activity.hint")}</Text>
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

interface ActivityColumnProps {
  value: number;
  label: string;
  onPress: () => void;
}

function ActivityColumn({ value, label, onPress }: ActivityColumnProps) {
  const { t } = useTranslation();
  return (
    <TouchableOpacity
      style={s.activityCol}
      onPress={onPress}
      activeOpacity={0.7}
      accessibilityRole="button"
      accessibilityLabel={t("mobile.home.activity.open_a11y", { label, value })}
    >
      <Text style={s.activityNum}>{value}</Text>
      <Text style={s.activityLabel}>{label}</Text>
    </TouchableOpacity>
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
    backgroundColor: colors.surface,
    borderRadius: radius.card,
    paddingVertical: space.sm,
  },
  activityRow: { flexDirection: "row" },
  // Each column is its own button; the padding makes the whole cell the
  // target, not just the digits.
  activityCol: { flex: 1, alignItems: "center", paddingVertical: space.sm, minHeight: 56 },
  activityNum: { fontSize: 20, lineHeight: 25, fontWeight: "600", color: colors.blue },
  activityLabel: { ...typo.caption, color: colors.textSecondary, marginTop: 2, textAlign: "center" },
  activityHint: {
    ...typo.caption, color: colors.textMuted, textAlign: "center",
    paddingHorizontal: space.md, paddingBottom: space.sm,
  },

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
