import { useCallback, useState, type ReactNode } from "react";
import {
  View, Text, StyleSheet, ScrollView, TouchableOpacity, Alert, ActivityIndicator,
} from "react-native";
import { useFocusEffect, useLocalSearchParams, useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius, sectionHeader } from "../src/utils/theme";
import { getSessionState } from "../src/services/auth";
import { getEntitlement, unlinkDevice, type AccountDevice, type EntitlementResponse } from "../src/services/api";
import { linkThisDevice, signOutUnlinkedDevice } from "../src/services/account";
import { rememberEntitlement } from "../src/services/freemium";
import { confirmDeleteAccount, signOutEverywhereLocal } from "../src/services/account-actions";
import { accountFailure, planKey, platformKey, sourceKey, statusKey } from "../src/utils/account-session";
import { paidPlansVisible } from "../src/config/market";

type IconName = keyof typeof Ionicons.glyphMap;

const PLATFORM_ICONS: Record<string, IconName> = {
  android: "phone-portrait-outline",
  ios: "phone-portrait-outline",
  extension: "extension-puzzle-outline",
  web: "globe-outline",
};

type Load =
  | { kind: "loading" }
  | { kind: "signed_out" }
  | { kind: "error" }
  | { kind: "ready"; email: string; ent: EntitlementResponse };

/**
 * Account: who is signed in, the plan, the devices it covers (unlink one),
 * sign out, delete account.
 *
 * Opened with `?limit=1` when this phone could not be linked because every
 * device seat is taken (src/services/account.ts): a banner explains it and
 * each unlink retries linking this phone.
 */
export default function AccountScreen() {
  const router = useRouter();
  const { t, i18n } = useTranslation();
  const params = useLocalSearchParams<{ limit?: string }>();
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [limitMode, setLimitMode] = useState(params.limit === "1");
  const [busyId, setBusyId] = useState<string | null>(null);

  const formatDate = useCallback(
    (iso?: string | null) => {
      if (!iso) return "";
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? "" : d.toLocaleDateString(i18n.language);
    },
    [i18n.language],
  );

  const refresh = useCallback(async () => {
    const st = await getSessionState();
    if (st.kind === "none") {
      setLoad({ kind: "signed_out" });
      return;
    }
    const email = st.kind === "ok" ? st.session.email : st.email ?? "";
    const { data, error } = await getEntitlement();
    if (data) {
      setLoad({ kind: "ready", email, ent: data });
      void rememberEntitlement(data);
    } else if (accountFailure(error) === "signed_out") {
      setLoad({ kind: "signed_out" });
    } else if (accountFailure(error) !== "revoked") {
      // revoked: the app-wide listener signs out and leaves this screen.
      setLoad({ kind: "error" });
    }
  }, []);

  useFocusEffect(useCallback(() => {
    void refresh();
  }, [refresh]));

  const leave = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

  async function doUnlink(device: AccountDevice): Promise<void> {
    setBusyId(device.id);
    const { data, error } = await unlinkDevice(device.id);
    setBusyId(null);
    if (!data) {
      if (accountFailure(error) !== "revoked") {
        Alert.alert(t("mobile.account.unlink_failed"));
      }
      return;
    }
    if (device.is_current) {
      // Unlinked this very phone: it is signed out like any unlinked device
      // (no "removed on another device" notice — the person just did it).
      await signOutUnlinkedDevice(false);
      leave();
      return;
    }
    if (load.kind === "ready") setLoad({ ...load, ent: data });
    if (limitMode) {
      // A seat is free now — link this phone into it.
      const linked = await linkThisDevice();
      if (linked.kind === "ok") {
        setLimitMode(false);
        setLoad((prev) => (prev.kind === "ready" ? { ...prev, ent: linked.entitlement } : prev));
      }
    }
  }

  function confirmUnlink(device: AccountDevice): void {
    const name = device.name || t(platformKey(device.platform));
    Alert.alert(
      t("mobile.account.unlink_confirm_title"),
      device.is_current
        ? t("mobile.account.unlink_this_confirm_body")
        : t("mobile.account.unlink_confirm_body", { name }),
      [
        { text: t("mobile.settings.clear_cancel"), style: "cancel" },
        { text: t("mobile.account.unlink"), style: "destructive", onPress: () => void doUnlink(device) },
      ],
    );
  }

  async function signOutHere(): Promise<void> {
    await signOutEverywhereLocal();
    leave();
  }

  if (load.kind === "loading") {
    return <View style={[s.container, s.center]}><ActivityIndicator color={colors.textSecondary} /></View>;
  }
  if (load.kind === "signed_out" || load.kind === "error") {
    const signedOut = load.kind === "signed_out";
    return (
      <View style={[s.container, s.center, { padding: space.xl }]}>
        <Text style={s.message}>
          {signedOut ? t("mobile.account.not_signed_in") : t("mobile.account.load_failed")}
        </Text>
        <TouchableOpacity
          style={s.button}
          accessibilityRole="button"
          onPress={() => (signedOut ? router.replace("/auth") : void refresh())}
        >
          <Text style={s.buttonText}>
            {signedOut ? t("mobile.settings.sign_in") : t("mobile.account.retry")}
          </Text>
        </TouchableOpacity>
      </View>
    );
  }

  const { ent, email } = load;
  const paid = ent.plan !== "free";
  const source = sourceKey(ent.source);
  const status = statusKey(ent.status, Boolean(ent.period_end));
  const showUpgrade = paidPlansVisible(i18n.language);

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      {limitMode && (
        <View style={s.banner} accessibilityRole="alert">
          <Text style={s.bannerTitle}>{t("mobile.account.limit_title")}</Text>
          <Text style={s.bannerBody}>{t("mobile.account.limit_body", { limit: ent.device_limit })}</Text>
          <View style={s.bannerActions}>
            {/* Free: a plan adds devices. TODO(billing): paid plans can't buy
                an extra device in the app yet (Play Billing / RevenueCat, §2) —
                until then a paid account can only unlink one. */}
            {showUpgrade && !paid && (
              <TouchableOpacity style={s.button} accessibilityRole="button" onPress={() => router.push("/upgrade")}>
                <Text style={s.buttonText}>{t("mobile.account.add_device")}</Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity style={s.linkButton} accessibilityRole="button" onPress={() => void signOutHere()}>
              <Text style={s.linkText}>{t("mobile.account.limit_not_now")}</Text>
            </TouchableOpacity>
          </View>
        </View>
      )}

      <Section title={t("mobile.account.signed_in_as")}>
        <Row first icon="mail-outline" label={email} />
      </Section>

      <Section title={t("mobile.account.plan_title")}>
        <Row
          first
          icon={paid ? "shield-checkmark-outline" : "shield-outline"}
          label={t(planKey(ent.plan))}
          desc={[
            source ? t(source) : null,
            status ? t(status, { date: formatDate(ent.period_end) }) : null,
            paid ? null : t("mobile.account.free_desc"),
          ].filter(Boolean).join(" · ")}
          right={!paid && showUpgrade ? <Text style={s.pill}>{t("mobile.settings.upgrade")}</Text> : undefined}
          onPress={!paid && showUpgrade ? () => router.push("/upgrade") : undefined}
        />
      </Section>

      <Section
        title={`${t("mobile.account.devices_title")} · ${t("mobile.account.devices_count", {
          used: ent.devices_used,
          limit: ent.device_limit,
        })}`}
        footnote={t("mobile.account.devices_note")}
      >
        {ent.devices.length === 0 ? (
          <Row first label={t("mobile.account.devices_empty")} />
        ) : (
          ent.devices.map((d, i) => (
            <Row
              key={d.id}
              first={i === 0}
              icon={PLATFORM_ICONS[d.platform] ?? "globe-outline"}
              label={d.name || t(platformKey(d.platform))}
              desc={d.is_current
                ? t("mobile.account.this_device")
                : t("mobile.account.last_seen", { date: formatDate(d.last_seen_at) })}
              right={busyId === d.id
                ? <ActivityIndicator color={colors.textSecondary} />
                : (
                  <TouchableOpacity
                    onPress={() => confirmUnlink(d)}
                    accessibilityRole="button"
                    accessibilityLabel={`${t("mobile.account.unlink")} ${d.name ?? ""}`}
                    hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                  >
                    <Text style={s.danger}>{t("mobile.account.unlink")}</Text>
                  </TouchableOpacity>
                )}
            />
          ))
        )}
      </Section>

      <Section title={t("mobile.settings.account")}>
        <Row first icon="log-out-outline" label={t("mobile.settings.sign_out")} onPress={() => void signOutHere()} />
        <Row
          icon="trash-outline"
          iconColor={colors.danger}
          tint={colors.danger}
          label={t("mobile.account.delete")}
          desc={t("mobile.account.delete_desc")}
          onPress={() => confirmDeleteAccount(t, leave)}
        />
      </Section>
    </ScrollView>
  );
}

function Section({ title, footnote, children }: { title: string; footnote?: string; children: ReactNode }) {
  return (
    <View style={s.section}>
      <Text style={s.sectionTitle}>{title}</Text>
      <View style={s.card}>{children}</View>
      {footnote ? <Text style={s.footnote}>{footnote}</Text> : null}
    </View>
  );
}

function Row({ label, desc, right, onPress, first, icon, iconColor, tint }: {
  label: string; desc?: string; right?: ReactNode; onPress?: () => void;
  first?: boolean; icon?: IconName; iconColor?: string; tint?: string;
}) {
  const inner = (
    <>
      {icon ? <Ionicons name={icon} size={18} color={iconColor ?? colors.textSecondary} /> : null}
      <View style={s.rowText}>
        <Text style={[s.rowLabel, tint ? { color: tint } : null]}>{label}</Text>
        {desc ? <Text style={s.rowDesc}>{desc}</Text> : null}
      </View>
      {right}
    </>
  );
  const style = [s.row, !first && s.rowBorder];
  if (!onPress) return <View style={style}>{inner}</View>;
  return (
    <TouchableOpacity style={style} onPress={onPress} activeOpacity={0.85} accessibilityRole="button">
      {inner}
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  center: { justifyContent: "center", alignItems: "center" },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 80 },
  message: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginBottom: space.lg },

  banner: {
    marginTop: space.lg, padding: space.lg, borderRadius: radius.card,
    backgroundColor: colors.amberWash, borderWidth: 1, borderColor: colors.amberStroke,
  },
  bannerTitle: { ...typo.headline, color: colors.textPrimary },
  bannerBody: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  bannerActions: { flexDirection: "row", alignItems: "center", gap: space.md, marginTop: space.md, flexWrap: "wrap" },

  button: {
    backgroundColor: colors.blue, borderRadius: radius.control,
    paddingHorizontal: space.lg, minHeight: 44, justifyContent: "center",
  },
  buttonText: { ...typo.body, fontWeight: "600", color: "#FFFFFF" },
  linkButton: { minHeight: 44, justifyContent: "center", paddingHorizontal: space.sm },
  linkText: { ...typo.body, color: colors.textSecondary },

  section: { marginTop: space.xxl },
  sectionTitle: { ...sectionHeader, marginBottom: space.sm, marginLeft: space.xs },
  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, paddingVertical: space.xs,
  },
  footnote: { ...typo.caption, color: colors.textSecondary, marginTop: space.sm, paddingHorizontal: space.xs },

  row: { flexDirection: "row", alignItems: "center", gap: space.md, minHeight: 52, paddingVertical: space.md },
  rowBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  rowText: { flex: 1 },
  rowLabel: { ...typo.body, fontWeight: "600", color: colors.textPrimary },
  rowDesc: { ...typo.caption, color: colors.textSecondary, marginTop: 2 },
  danger: { ...typo.body, fontWeight: "600", color: colors.danger },
  pill: {
    backgroundColor: colors.blue, color: "#FFFFFF", overflow: "hidden",
    borderRadius: radius.pill, paddingHorizontal: space.md, paddingVertical: 6,
    fontSize: 13, lineHeight: 18, fontWeight: "600",
  },
});
