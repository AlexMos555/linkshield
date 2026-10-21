import { useCallback, useEffect, useMemo, useState } from "react";
import {
  View, Text, StyleSheet, FlatList, RefreshControl, ActivityIndicator, Platform,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import { colors, type as typo, space } from "../../src/utils/theme";
import {
  HISTORY_FILTERS, filterHistory, findShieldEvent, findSmsAlert, isTruncated, parseDeepLinkDomain,
  parseDeepLinkSmsId, parseHistoryFilter,
  type HistoryFilter, type HistoryItem, type ShieldItem, type SmsAlertItem,
} from "../../src/utils/history-model";
import { filterHintKey } from "../../src/utils/history-labels";
import { useHistoryItems } from "../../src/hooks/useHistoryItems";
import { FilterChips } from "../../src/components/history/FilterChips";
import { HistoryRow } from "../../src/components/history/HistoryRows";
import { HistoryEmpty } from "../../src/components/history/HistoryEmpty";
import { ShieldEventSheet } from "../../src/components/history/ShieldEventSheet";
import { SmsAlertSheet } from "../../src/components/history/SmsAlertSheet";
import { isMessageCheckSupported, smsAutoSupported } from "../../modules/cleanway-vpn";

/**
 * History: what the shields did on their own, and what the person checked.
 *
 * Route params (all optional):
 *  - filter: all | blocked | warned | checked | sms — set by the home
 *    counters ("Blocked 3" opens filter=blocked) and by the chips here.
 *  - domain: from a block notification (cleanway:///history?filter=blocked&
 *    domain=…). Opens that site's entry once, then is cleared. Ignored unless
 *    the site is really in the block log: the scheme is public, and a crafted
 *    link must not put a made-up site and its "allow" button on screen.
 *  - sms: from an SMS warning (cleanway:///history?filter=sms&sms=<id>).
 *    Opens that flagged SMS once, then is cleared — and only if the SMS event
 *    log holds that id, for the same reason.
 */
export default function HistoryScreen() {
  const { t } = useTranslation();
  const router = useRouter();
  const params = useLocalSearchParams<{ filter?: string; domain?: string; sms?: string }>();
  const filter = parseHistoryFilter(params.filter);
  const deepLinkDomain = parseDeepLinkDomain(params.domain);
  const deepLinkSmsId = parseDeepLinkSmsId(params.sms);
  const history = useHistoryItems();
  const { reload } = history;
  const [open, setOpen] = useState<ShieldItem | null>(null);
  const [openAlert, setOpenAlert] = useState<SmsAlertItem | null>(null);
  const [messageCheck] = useState(() => isMessageCheckSupported());
  const [smsAuto] = useState(() => smsAutoSupported());

  const visible = useMemo(() => filterHistory(history.items, filter), [history.items, filter]);
  const hasSmsAlerts = useMemo(() => history.items.some((i) => i.type === "sms_alert"), [history.items]);
  // The SMS chip only where a message can be checked, or where old rows exist.
  const filters = useMemo(
    () => HISTORY_FILTERS.filter(
      (f) => f !== "sms" || messageCheck || smsAuto || history.items.some((i) => i.type === "sms" || i.type === "sms_alert"),
    ),
    [messageCheck, smsAuto, history.items],
  );
  const hasCheckRows = useMemo(() => visible.some((i) => i.type === "check"), [visible]);
  const hint = filterHintKey(filter, smsAuto || hasSmsAlerts);

  // A notification tap: re-read first (the block happened after the last
  // read), then open the entry, then drop the param so a later focus or
  // re-render does not open it again.
  useEffect(() => {
    if (!deepLinkDomain) return;
    let cancelled = false;
    void reload().then((fresh) => {
      if (cancelled) return;
      setOpen(findShieldEvent(fresh, deepLinkDomain, filter));
      router.setParams({ domain: undefined });
    });
    return () => {
      cancelled = true;
    };
  }, [deepLinkDomain, filter, reload, router]);

  // An SMS warning tap: same order — the warning was written by another
  // process just before, so re-read, then open, then drop the param.
  useEffect(() => {
    if (!deepLinkSmsId) return;
    let cancelled = false;
    void reload().then((fresh) => {
      if (cancelled) return;
      setOpenAlert(findSmsAlert(fresh, deepLinkSmsId));
      router.setParams({ sms: undefined });
    });
    return () => {
      cancelled = true;
    };
  }, [deepLinkSmsId, reload, router]);

  const selectFilter = useCallback((next: HistoryFilter) => {
    // In the route, not in local state: a counter on the home screen sets the
    // same param, so tapping "Blocked" there after picking "All" here works.
    router.setParams({ filter: next });
  }, [router]);

  const openMore = useCallback((domain: string) => {
    setOpen(null);
    // from=history: looking a site up again is not a new check, and must not
    // add a second "dangerous" row to the counters.
    router.push({ pathname: "/result", params: { domain, from: "history" } });
  }, [router]);

  const renderItem = useCallback(
    ({ item }: { item: HistoryItem }) => <HistoryRow item={item} onOpenShield={setOpen} onOpenSmsAlert={setOpenAlert} />,
    [],
  );

  if (history.loading) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.loadingText}>{t("mobile.history.loading")}</Text>
      </View>
    );
  }

  return (
    <View style={s.container}>
      <FlatList
        data={visible}
        keyExtractor={(item) => item.key}
        renderItem={renderItem}
        initialNumToRender={12}
        maxToRenderPerBatch={12}
        windowSize={7}
        removeClippedSubviews={Platform.OS === "android"}
        ListHeaderComponent={
          <View style={s.header}>
            <FilterChips filters={filters} selected={filter} onSelect={selectFilter} />
            <Text style={s.hint}>{t(hint)}</Text>
            {hasCheckRows && <Text style={s.hint}>{t("mobile.history.score_hint")}</Text>}
          </View>
        }
        ListEmptyComponent={
          <HistoryEmpty
            filter={filter}
            smsWarnings={smsAuto}
            onCheckLink={() => router.push("/check")}
            onCheckMessage={() => router.push("/message")}
            onTurnOn={() => router.navigate({ pathname: "/", params: { setup: "1" } })}
          />
        }
        ListFooterComponent={
          <View style={s.footer}>
            {isTruncated(filter, history.gaps) && visible.length > 0 && (
              <Text style={s.truncated}>{t("mobile.history.truncated")}</Text>
            )}
            <View style={s.privacyRow}>
              <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
              <Text style={s.privacy}>{t("mobile.history.privacy")}</Text>
            </View>
          </View>
        }
        contentContainerStyle={s.content}
        refreshControl={
          <RefreshControl refreshing={history.refreshing} onRefresh={history.refresh} tintColor={colors.blue} />
        }
      />
      <ShieldEventSheet
        item={open}
        onClose={() => setOpen(null)}
        onChanged={() => void reload()}
        onMore={openMore}
      />
      <SmsAlertSheet item={openAlert} onClose={() => setOpenAlert(null)} />
    </View>
  );
}

const s = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, padding: space.xxxl,
  },
  loadingText: { ...typo.body, color: colors.textSecondary, marginTop: space.lg },

  header: { marginBottom: space.md, gap: space.sm },
  hint: { ...typo.caption, color: colors.textMuted },

  footer: { marginTop: space.lg, gap: space.md },
  truncated: { ...typo.caption, color: colors.textMuted, textAlign: "center" },
  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
