import { useState, useCallback, useEffect } from "react";
import {
  View, Text, StyleSheet, ScrollView, Modal, TouchableOpacity, Platform, Alert,
} from "react-native";
import { useRouter, useFocusEffect, useLocalSearchParams } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { colors, type as typo, space, radius } from "../../src/utils/theme";
import { getStats } from "../../src/services/database";
import { HeroShield, type HeroHold } from "../../src/components/shield/HeroShield";
import { PauseSheet } from "../../src/components/shield/PauseSheet";
import { CheckAnythingCard } from "../../src/components/shield/CheckAnythingCard";
import { RolloutList, RolloutItem } from "../../src/components/shield/RolloutList";
import { IosProtectionCard } from "../../src/components/shield/IosProtectionCard";
import { SmsFilterSetupSheet } from "../../src/components/shield/SmsFilterSetupSheet";
import {
  androidProtectionShown, heroWithoutShieldsKeys, homePrivacyKey, iosProtectionLayers, iosProtectionShown,
  shareHowToKey, smsFilterLayerStatus, type IosLayerId,
} from "../../src/utils/platform-features";
import { smsFilterInstalled } from "../../modules/cleanway-sms-filter";
import { ShieldCard } from "../../src/components/shield/ShieldCard";
import { useNetworkShield, PAUSE_MINUTES, type ShieldStopReason } from "../../src/hooks/useNetworkShield";
import { clockTime } from "../../src/utils/relative-time";
import { useShieldBlockTotals } from "../../src/hooks/useShieldBlockTotals";
import { useUpdateCheck } from "../../src/hooks/useUpdateCheck";
import { useLinkGuard } from "../../src/hooks/useLinkGuard";
import { UpdateBanner } from "../../src/components/shield/UpdateBanner";
import { FREEMIUM } from "../../src/services/freemium";
import { selfUpdateAllowed } from "../../src/utils/freemium";
import { MessageCheckCard } from "../../src/components/shield/MessageCheckCard";
import { KeepAliveCard } from "../../src/components/shield/KeepAliveCard";
import { useKeepAlive } from "../../src/hooks/useKeepAlive";
import { shieldForKeepAlive } from "../../src/utils/keep-alive";
import { callState, isMessageCheckSupported, isVpnRunning, linkListAvailable, privateDnsStrictHost } from "../../modules/cleanway-vpn";
import { CallHelpButton } from "../../src/components/call/CallHelpButton";
import { useCallGuard } from "../../src/components/call/CallGuardProvider";
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

/** Why protection stopped by itself → what the screen says about it. */
const INTERRUPTED_KEYS: Record<ShieldStopReason | "unknown", string> = {
  revoked: "mobile.home.interrupted_revoked",
  private_dns: "mobile.home.interrupted_private_dns",
  unknown: "mobile.home.interrupted",
};

/**
 * Android only. The iPhone's layers are listed by IosProtectionCard
 * (src/utils/platform-features.ts) instead.
 */
function rolloutItems(t: TFunction, platform: string, messageCheck: boolean): RolloutItem[] {
  // On Android the browser/link layer ships as the Link-checking shield card
  // and SMS as the message-check card, so nothing is "rolling out" there. No
  // line promises an automatic check of every incoming SMS: that needs SMS
  // permissions this app deliberately does not ask for. The SMS row stays
  // only for a native build without the analyzer, where it is still true.
  if (!androidProtectionShown(platform) || messageCheck) return [];
  return [
    {
      icon: "chatbubble-outline",
      title: t("mobile.shield.messages.title"),
      line: t("mobile.rollout.messages_android"),
    },
  ];
}

export default function HomeScreen() {
  const router = useRouter();
  // setup=1: History's "Turn on protection" sends people here to run the
  // same flow as the button below, instead of a second copy of it.
  const { setup } = useLocalSearchParams<{ setup?: string }>();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [shareSheetVisible, setShareSheetVisible] = useState(false);
  const [pauseSheetVisible, setPauseSheetVisible] = useState(false);
  const [smsSetupVisible, setSmsSetupVisible] = useState(false);
  const network = useNetworkShield();
  // The stop screen: a pause asked for during (or right after) a phone call
  // is what a scammer asks for, so it goes through the guard first.
  const callGuard = useCallGuard();
  // "I'm being called" only where the phone's calls can be seen at all
  // (Android with the native module); elsewhere the button would open a
  // screen about calls the app knows nothing of.
  const [callHelp] = useState(() => callState() !== null);
  // The link guard (Android): when Cleanway is the default link handler, tapped
  // links are checked before they open — the exact SMS-phishing defense.
  const linkGuard = useLinkGuard();
  // The SMS check (Android, native analyzer present). A tool, not a shield:
  // it is deliberately left out of the hero counts below.
  const [messageCheck] = useState(() => isMessageCheckSupported());
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
  // The check still runs in store builds (it carries the server's switches,
  // src/lib/remote-config.ts) but only the site APK shows the banner: a store
  // build is updated by its store, never by a download link.
  const update = useUpdateCheck(i18n.language);
  // What keeps the shield running with the app closed (battery, the phone
  // maker's own manager, alerts, Always-on). Re-read when the shield changes:
  // Always-on can only be read while it runs.
  const keepAlive = useKeepAlive(`${network.state}:${network.verified}`);

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
  const warnedTotal = stats.threats_warned + shieldTotals.warned;

  // Only shields that are shipped AND verifiable on this platform can count;
  // a running-but-unverified tunnel deliberately counts as 0. Equally, every
  // shield that DOES exist on this device must be counted, or the
  // headline lies: with only the DNS shield counted, a phone whose link guard
  // was never set up still read "All shields on and verified". The SMS check
  // is not a shield (it acts only on what the person hands it) and stays out.
  const totalCount = (network.available ? 1 : 0) + (linkGuard.available ? 1 : 0);
  const verifiedCount = (network.verified ? 1 : 0) + (linkGuard.on ? 1 : 0);
  const heroState =
    totalCount > 0 && verifiedCount === totalCount ? "all"
    : verifiedCount > 0 ? "partial"
    : "none";
  const needsSetup = network.available && network.state === "setup";
  // Was on, and something else stopped it: not a first setup (ShieldState "stopped").
  const stopped = needsSetup && network.interrupted;
  // "Keep protection on" once the person has turned the shield on: running,
  // paused, or stopped by something else — the case it exists to prevent.
  // Not before the first setup (nothing to keep yet), and not under strict
  // Private DNS, where the card above names the one setting that matters.
  const showKeepAlive = network.available && (stopped || (network.state !== "setup" && network.state !== "conflict"));
  // Paused or blocked by Private DNS: whatever else is on, the hero is not green.
  const heroHold: HeroHold | null =
    network.state === "paused" ? { kind: "paused", until: network.pausedUntil }
    : network.state === "conflict" ? { kind: "conflict" }
    : null;

  const rollout = rolloutItems(t, Platform.OS, messageCheck);
  // iPhone: no shield exists yet, so the hero says what the app does now
  // instead of "let's set up — 0 shields active".
  const heroOverride = heroWithoutShieldsKeys(Platform.OS, totalCount);
  // The iPhone's protection layers. Each later step (Safari extension, SMS
  // filter, DNS settings) passes its status here; until then all are "coming".
  const iosLayers = iosProtectionShown(Platform.OS)
    ? iosProtectionLayers({ sms_filter: smsFilterLayerStatus(smsFilterInstalled()) })
    : null;
  // "Set up" on a layer: the scam-text filter's steps (iOS lets only the person enable it).
  const onIosSetUp = (id: IosLayerId) => {
    if (id === "sms_filter") setSmsSetupVisible(true);
  };

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

  /**
   * Pause goes through PauseSheet: the scam warning first, 15 minutes by
   * default with protection returning by itself, "until I turn it back on"
   * second, and "keep protection" the most prominent choice.
   */
  function confirmPause() {
    callGuard.guard("pause", () => setPauseSheetVisible(true));
  }

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <HeroShield
        state={heroState}
        verifiedCount={verifiedCount}
        totalCount={totalCount}
        override={heroOverride}
        // No alarm state exists any more: nothing in the code detects a
        // competing VPN, so nothing may claim one. Unproven is shown as
        // unproven, not as a warning.
        attention={false}
        interrupted={stopped}
        hold={heroHold}
        offline={network.state === "offline"}
      />

      {selfUpdateAllowed(FREEMIUM.distribution) && <UpdateBanner status={update} />}

      {callHelp && (
        <View style={s.section}>
          <CallHelpButton onPress={() => router.push("/call-guard")} />
        </View>
      )}

      {needsSetup && (
        <>
          {stopped && (
            // The user had this on and something else turned it off. Say so —
            // "let's set up" would tell them their earlier setup never
            // happened — and say what, and the steps it really takes to come
            // back: after a withdrawn permission Android asks again.
            <View style={s.interruptedRow}>
              <Ionicons name="alert-circle-outline" size={15} color={colors.amber} />
              <Text style={s.interruptedText}>
                {t(INTERRUPTED_KEYS[network.stopReason ?? "unknown"], {
                  button: t("mobile.shield.disclosure.continue"),
                })}
              </Text>
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
            state={stopped ? "stopped" : network.state}
            stateCopy={
              // Strict Private DNS: the one state whose fix is a system
              // setting. Name the provider so the user recognises it.
              network.state === "conflict"
                ? t("mobile.shield.network.state_private_dns", { host: network.privateDnsHost ?? "" })
              : network.state === "paused"
                ? t("mobile.shield.network.state_paused_until", { time: clockTime(network.pausedUntil, i18n.language) })
              : network.state === "on" ? t("mobile.shield.network.state_on")
              // Probe in flight: say "checking" rather than flashing the
              // negative state at someone whose protection is fine.
              : network.probing ? t("mobile.shield.network.state_checking")
              // Offline, the list on the phone still blocks — say so only
              // when there is one (no seed and no sync yet: nothing to block by).
              : network.state === "offline"
                ? t(network.blocklist.count > 0
                  ? "mobile.shield.network.state_offline"
                  : "mobile.shield.network.state_offline_no_list")
              : network.state === "unverified" ? t("mobile.shield.network.state_unverified")
              : stopped ? t("mobile.shield.network.state_stopped", { button: t("mobile.home.cta_turn_back_on") })
              : t("mobile.shield.network.state_setup")
            }
            onAction={() => {
              if (network.state === "setup") startWithDisclosure();
              else if (network.state === "conflict") network.openPrivateDnsSettings();
              else if (network.state === "paused") network.resume();
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
          {network.state === "paused" && (
            // Said as a button, not only as the pill: turning protection back
            // on must be the easiest thing on this screen.
            <TouchableOpacity
              style={s.hintRow}
              onPress={network.resume}
              activeOpacity={0.85}
              accessibilityRole="button"
            >
              <Ionicons name="play-circle-outline" size={15} color={colors.blue} />
              <Text style={[s.hintText, s.resumeText]}>{t("mobile.shield.resume_now")}</Text>
              <Ionicons name="chevron-forward" size={14} color={colors.blue} />
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
        </View>
      )}

      {showKeepAlive && (
        // Protection health: the shield, the battery exemption, the phone
        // maker's own battery manager, alerts, and Always-on VPN (optional —
        // protection already returns by itself after a reboot; Always-on
        // starts it with the phone, before any app receives BOOT_COMPLETED).
        <View style={s.section}>
          <KeepAliveCard shield={shieldForKeepAlive(network.state, network.verified)} keepAlive={keepAlive} />
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
            // "Known scam sites won't open" only while there is a list to
            // know them by — without one, every link opens and is checked after.
            stateCopy={t(
              !linkGuard.on ? "mobile.shield.linkguard.state_setup"
              : linkListReady ? "mobile.shield.linkguard.state_on"
              : "mobile.shield.linkguard.state_no_list",
            )}
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

      {messageCheck && (
        <View style={s.section}>
          <MessageCheckCard
            onOpen={() => router.push("/message")}
            linkGuardAvailable={linkGuard.available}
            linkGuardOn={linkGuard.on}
            linkListReady={linkListReady}
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

      {iosLayers && (
        <View style={s.section}>
          <IosProtectionCard layers={iosLayers} onSetUp={onIosSetUp} />
        </View>
      )}

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
        <Text style={s.privacy}>{t(homePrivacyKey(Platform.OS))}</Text>
      </View>

      <ShareHowToSheet visible={shareSheetVisible} onClose={() => setShareSheetVisible(false)} />
      <SmsFilterSetupSheet visible={smsSetupVisible} onClose={() => setSmsSetupVisible(false)} />
      <PauseSheet
        visible={pauseSheetVisible}
        minutes={PAUSE_MINUTES}
        onKeep={() => setPauseSheetVisible(false)}
        onPauseTimed={() => {
          setPauseSheetVisible(false);
          network.pause(PAUSE_MINUTES);
        }}
        onPauseUntilOn={() => {
          setPauseSheetVisible(false);
          void network.turnOff();
        }}
      />
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
          <Text style={s.sheetBody}>{t(shareHowToKey(Platform.OS))}</Text>
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
    minHeight: 50, paddingHorizontal: space.lg, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  ctaLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  hintRow: {
    flexDirection: "row", alignItems: "center", gap: 6,
    marginTop: space.sm, paddingHorizontal: space.xs,
  },
  hintText: { ...typo.caption, color: colors.textSecondary, flex: 1 },
  resumeText: { fontSize: 15, fontWeight: "600", color: colors.blue },

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
    minHeight: 50, paddingHorizontal: space.lg, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  sheetBtnLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
});
