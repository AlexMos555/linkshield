import { useState, useCallback } from "react";
import {
  View, Text, StyleSheet, ScrollView, Modal, TouchableOpacity, Platform,
} from "react-native";
import { useRouter, useFocusEffect } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { colors, type as t, space, radius } from "../../src/utils/theme";
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

const ROLLOUT_IOS: RolloutItem[] = [
  {
    icon: "globe-outline",
    title: "Every app",
    line: "Blocks scam sites in almost every app. In final testing — not on iPhone yet.",
  },
  {
    icon: "compass-outline",
    title: "Your browser",
    line: "Warns you right on the page in Safari. Coming next.",
  },
  {
    icon: "chatbubble-outline",
    title: "Text messages",
    line: "Filters scam texts (SMS). Planned — it will never be able to see iMessage.",
  },
];

const ROLLOUT_ANDROID: RolloutItem[] = [
  {
    icon: "compass-outline",
    title: "Your browser",
    line: "Checks links you tap in any app, before they open. Coming next.",
  },
  {
    icon: "chatbubble-outline",
    title: "Text messages",
    line: "Not possible for us on Android yet — sharing a text to Cleanway is the way to check one.",
  },
];

export default function HomeScreen() {
  const router = useRouter();
  const [stats, setStats] = useState({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });
  const [shareSheetVisible, setShareSheetVisible] = useState(false);
  const network = useNetworkShield();

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

  const rollout = Platform.OS === "android" ? ROLLOUT_ANDROID : ROLLOUT_IOS;

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <HeroShield
        state={heroState}
        verifiedCount={verifiedCount}
        totalCount={totalCount}
        attention={network.state === "conflict"}
      />

      {needsSetup && (
        <TouchableOpacity
          style={s.cta}
          onPress={() => void network.turnOn()}
          activeOpacity={0.85}
          accessibilityRole="button"
        >
          <Text style={s.ctaLabel}>Turn on protection</Text>
        </TouchableOpacity>
      )}

      {network.available && (
        <View style={s.section}>
          <ShieldCard
            icon="globe-outline"
            title="Every app"
            description="Blocks known scam sites in almost every app — even inside WhatsApp"
            honesty="Can't catch brand-new scam sites, or apps that bring their own private DNS"
            state={network.state}
            stateCopy={
              network.state === "on" ? "On. Working right now."
              : network.state === "conflict"
                ? "Your VPN is in charge right now. Cleanway steps aside so nothing breaks."
                : "One-time setup, about a minute."
            }
            onAction={() => void (network.state === "setup" ? network.turnOn() : network.turnOff())}
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

      <View style={s.section}>
        <RolloutList items={rollout} />
      </View>

      {(stats.total_checks > 0 || stats.threats_blocked > 0) && (
        <View style={[s.section, s.activityCard]}>
          <ActivityColumn value={stats.total_checks} label="Checked" />
          <ActivityColumn value={stats.threats_blocked} label="Blocked" />
          <ActivityColumn value={stats.threats_warned} label="Warned" />
        </View>
      )}

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        <Text style={s.privacy}>
          We check website names on our servers — never your passwords, messages, or browsing history.
        </Text>
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
  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <TouchableOpacity style={s.scrim} activeOpacity={1} onPress={onClose}>
        <View style={s.sheet}>
          <Text style={s.sheetTitle}>How to share</Text>
          <Text style={s.sheetBody}>
            From any app, tap Share, then choose Cleanway. We'll check the link and tell you if
            it's safe.
          </Text>
          <TouchableOpacity style={s.sheetBtn} onPress={onClose} activeOpacity={0.85}>
            <Text style={s.sheetBtnLabel}>Got it</Text>
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

  cta: {
    height: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  ctaLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },

  activityCard: {
    flexDirection: "row",
    backgroundColor: colors.surface,
    borderRadius: radius.card,
    paddingVertical: space.lg,
  },
  activityCol: { flex: 1, alignItems: "center" },
  activityNum: { fontSize: 20, lineHeight: 25, fontWeight: "600", color: colors.textPrimary },
  activityLabel: { ...t.caption, color: colors.textMuted, marginTop: 2 },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xxl, paddingHorizontal: space.md,
  },
  privacy: { ...t.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },

  scrim: { flex: 1, backgroundColor: "#0B1220E6", justifyContent: "flex-end" },
  sheet: {
    backgroundColor: "#141A28",
    borderTopLeftRadius: radius.card, borderTopRightRadius: radius.card,
    padding: space.xxl, paddingBottom: space.huge,
  },
  sheetTitle: { ...t.headline, color: colors.textPrimary },
  sheetBody: { ...t.body, color: colors.textSecondary, marginTop: space.sm },
  sheetBtn: {
    height: 50, borderRadius: radius.control, backgroundColor: colors.blue,
    alignItems: "center", justifyContent: "center", marginTop: space.xl,
  },
  sheetBtnLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
});
