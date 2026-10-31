/**
 * The paywall — one sheet, opened where the free plan's daily limit stopped
 * a check (by itself once a day, or from the "detailed analysis is in the
 * subscription" card), and from "Upgrade" in Settings / Account
 * (`?from=upgrade`). docs/ACCOUNTS_BILLING_PLAN.md §5, §11.
 *
 * Price large, one primary button, a plain list of what the plan adds, a
 * small "already paying" link and a close button. It never says protection
 * stops: sites on the scam list are blocked paid or not.
 *
 * Paying (src/utils/freemium.ts purchaseAction):
 *   • not signed in, on Android → sign in first (a plan belongs to an
 *     account), then the purchase continues by itself on return;
 *   • the APK from our site → the site's checkout, in the browser;
 *   • the Google Play build → Google Play billing (src/services/store-billing.ts):
 *     monthly / yearly with the store's own prices, then our server confirms;
 *     never a link to the web checkout, never a price typed into the app;
 *   • the iPhone app → the App Store, the same way (App Review 3.1.1: no
 *     web checkout, no other store); Terms of Use and Privacy Policy links
 *     under the button (3.1.2). No account needed (5.1.1; STORE_PURCHASE_
 *     WITHOUT_ACCOUNT): buying and "Restore" work signed out, the phone
 *     counts its own plan, and the paid sheet then offers signing in — only
 *     to use the plan on Android and in the browser extension. Signing in
 *     stays one tap away (someone paying on another device must not buy
 *     twice), and on a phone where someone signed in before, a signed-out
 *     purchase or restore first says it would move a subscription this
 *     Apple ID pays in that account to this phone only. Without
 *     EXPO_PUBLIC_REVENUECAT_IOS_KEY the build has no paid plans at all
 *     (PAID_PLANS_OFFERED): nothing opens this sheet, and a stray link to it
 *     lands on home;
 *   • RuStore → not built yet: "coming soon" up front, the button off and no
 *     sign-in first (paywallSaleOff); Settings and Account have no entry to
 *     this sheet there (paidPlansVisible) — the same for a Play build made
 *     without its RevenueCat key;
 *   • Russia → phone-balance billing is not merged yet: "coming soon" (the
 *     Play build does not mention other ways to pay).
 * Coming back to the sheet re-reads the plan; once it is paid, it says so,
 * where it was paid, and (store plans) offers "Manage subscription".
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, Pressable, Linking, AppState, ActivityIndicator, Platform, Alert,
} from "react-native";
import { Redirect, useFocusEffect, useLocalSearchParams, useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Localization from "expo-localization";
import Constants from "expo-constants";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../src/utils/theme";
import { getSessionState } from "../src/services/auth";
import { getEntitlement, type EntitlementResponse } from "../src/services/api";
import { FREEMIUM, PAID_PLANS_OFFERED, applyEntitlement, devicePlanPaid, isPaid } from "../src/services/freemium";
import {
  BILLING_STORE, STORE_PURCHASE_WITHOUT_ACCOUNT, loadStorePlans, restoreStorePurchases, startStorePurchase,
  storeBillingOn, storeHadAccount, storeRestoreSuggested,
} from "../src/services/store-billing";
import {
  PRICES, WEB_CHECKOUT_URL, isPaidEntitlement, marketFor, paywallBenefits, paywallSaleOff, priceDisplay,
  purchaseAction, revenueCatStore, webCheckoutAllowed, type PaywallBenefit,
} from "../src/utils/freemium";
import {
  APP_STORE_SUBSCRIPTIONS_URL, manageSubscriptionUrl, storeCopyKeys, storeErrorNoteKey, warnBeforeWithoutAccount,
  type PlanPeriod,
} from "../src/utils/store-billing";
import { sourceKey } from "../src/utils/account-session";
import { PRIVACY_POLICY_URL, TERMS_URL } from "../src/utils/legal-urls";
import { StorePlans, type StorePlansState } from "../src/components/paywall/StorePlans";
import { PublishedPrice } from "../src/components/paywall/PublishedPrice";

type IconName = keyof typeof Ionicons.glyphMap;

const BENEFITS: Record<PaywallBenefit, { icon: IconName; key: string }> = {
  unlimited: { icon: "infinite-outline", key: "mobile.paywall.benefit_unlimited" },
  sms: { icon: "chatbox-ellipses-outline", key: "mobile.paywall.benefit_sms" },
  text_model: { icon: "document-text-outline", key: "mobile.paywall.benefit_text_model" },
  devices: { icon: "phone-portrait-outline", key: "mobile.paywall.benefit_devices" },
};
// Only what this build can do and paying adds: no build reads SMS by itself
// yet, the call guard is free for everyone, and the iPhone app has no
// message analyzer (paywallBenefits).
const SHOWN_BENEFITS = paywallBenefits(FREEMIUM.distribution).map((b) => BENEFITS[b]);

const ANDROID_PACKAGE = Constants.expoConfig?.android?.package ?? "ai.cleanway.app";

/** A store build (Google Play, the iPhone app): prices and purchases come from the store. */
const STORE = revenueCatStore(FREEMIUM.distribution);
const COPY = storeCopyKeys(BILLING_STORE);

/** A note under the button after an attempt: what happened, in words. */
type Note =
  | null | "store_soon" | "restore_none" | "restore_none_signed_out" | "restore_failed" | "web_opened" | "processing"
  | "restored" | "restore_here";

// Literal keys, so scripts/check-mobile-i18n.py can see every one (the
// store-named one is literal in utils/store-billing.ts storeCopyKeys).
const NOTE_KEYS: Record<Exclude<Note, null>, string> = {
  store_soon: "mobile.paywall.note_store_soon",
  restore_none: COPY.restoreNone,
  // The iPhone app signed out: nothing on this Apple ID — sign in if paying on another device.
  restore_none_signed_out: "mobile.paywall.note_restore_none_signed_out_appstore",
  restore_failed: "mobile.paywall.note_restore_failed",
  web_opened: "mobile.paywall.note_web_opened",
  processing: "mobile.paywall.note_processing",
  restored: "mobile.paywall.note_restored",
  // Signed in on the iPhone, and the plan bought here signed out did not follow the account.
  restore_here: "mobile.paywall.note_restore_here_appstore",
};

interface Account {
  signedIn: boolean;
  paid: boolean;
  ent: EntitlementResponse | null;
}

/**
 * An iPhone build without App Store billing went to App Review as having no
 * in-app purchases: no plan, no price, no "coming soon". Every entry point is
 * hidden there; this catches a deep link (or /upgrade) that still arrives.
 */
export default function PaywallRoute() {
  if (!PAID_PLANS_OFFERED) return <Redirect href="/(tabs)" />;
  return <PaywallScreen />;
}

function PaywallScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { t, i18n } = useTranslation();
  const params = useLocalSearchParams<{ from?: string }>();
  // One state for all three, set at once: the purchase that continues after
  // sign-in must never see "signed in" before it knows whether it is paid.
  const [acct, setAcct] = useState<Account | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<Note>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [plans, setPlans] = useState<StorePlansState>({ kind: "loading" });
  const [selected, setSelected] = useState<PlanPeriod>("month");
  /** The iPhone app signed out: someone signed in on this phone before (storeHadAccount). */
  const [hadAccount, setHadAccount] = useState(false);
  /** Sent to sign in from the button: buy when back. */
  const continueAfterSignIn = useRef(false);

  const storeOn = STORE && storeBillingOn();
  const market = marketFor(i18n.language, Localization.getLocales()[0]?.regionCode);
  const price = priceDisplay(market, FREEMIUM.distribution);
  const devices = PRICES[market].devices;
  const signedIn = acct?.signedIn === true;
  const paid = acct?.paid === true;
  const action = purchaseAction({ signedIn, market, distribution: FREEMIUM.distribution });
  const showStorePlans = STORE && storeOn && action !== "soon";

  const close = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

  /**
   * Who is here and whether the plan is paid now — after sign-in, a
   * checkout, a restore. In the iPhone app this phone's own App Store plan
   * counts too, signed out or not (devicePlanPaid; false everywhere else).
   */
  const reload = useCallback(async (): Promise<Account> => {
    const st = await getSessionState();
    if (st.kind === "none") {
      setHadAccount(await storeHadAccount());
      const next = { signedIn: false, paid: await devicePlanPaid(true), ent: null };
      setAcct(next);
      return next;
    }
    const { data } = await getEntitlement();
    const next = data
      ? { signedIn: true, paid: (await applyEntitlement(data)) || (await devicePlanPaid(true)), ent: data }
      : { signedIn: true, paid: await isPaid(false), ent: null };
    setAcct(next);
    // The phone may still count the plan it paid for (paid) while the
    // account does not have it: Restore moves it there.
    if (!isPaidEntitlement(next.ent) && (await storeRestoreSuggested())) setNote((n) => n ?? "restore_here");
    return next;
  }, []);

  const loadPlans = useCallback(async () => {
    setPlans({ kind: "loading" });
    const r = await loadStorePlans();
    setPlans(r);
    if (r.kind === "ok" && !r.plans.some((p) => p.period === "month")) setSelected(r.plans[0].period);
  }, []);

  // Back from the sign-in screen: the button becomes the purchase.
  useFocusEffect(useCallback(() => {
    void reload();
  }, [reload]));

  // Back from the browser's checkout or Google Play.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (next) => {
      if (next === "active") void reload();
    });
    return () => sub.remove();
  }, [reload]);

  useEffect(() => {
    if (showStorePlans) void loadPlans();
  }, [showStorePlans, loadPlans]);

  function showStoreError(kind: Parameters<typeof storeErrorNoteKey>[0]): void {
    setErrorKey(storeErrorNoteKey(kind, BILLING_STORE));
  }

  /**
   * Signed out in the iPhone app, where someone signed in before
   * (warnBeforeWithoutAccount): buying or restoring without an account
   * would move a subscription this Apple ID pays in that account to this
   * phone only (RevenueCat "Transfer to new App User ID"). Signing in is
   * offered first; going on stays possible (App Review 5.1.1). True: go on.
   */
  function goOnWithoutAccount(then: "buy" | "restore"): Promise<boolean> {
    if (!warnBeforeWithoutAccount({ withoutAccount: STORE_PURCHASE_WITHOUT_ACCOUNT, signedIn, hadAccount })) {
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      Alert.alert(
        t("mobile.paywall.without_account_title"),
        t("mobile.paywall.without_account_body"),
        [
          { text: t("mobile.settings.clear_cancel"), style: "cancel", onPress: () => resolve(false) },
          {
            text: t("mobile.settings.sign_in"),
            onPress: () => {
              // Back signed in: a purchase carries on (unless the account pays already).
              continueAfterSignIn.current = then === "buy";
              router.push("/auth");
              resolve(false);
            },
          },
          { text: t("mobile.paywall.without_account_continue"), onPress: () => resolve(true) },
        ],
        { cancelable: true, onDismiss: () => resolve(false) },
      );
    });
  }

  async function buyFromStore(): Promise<void> {
    if (!storeOn) {
      setNote("store_soon");
      return;
    }
    const plan = plans.kind === "ok" ? plans.plans.find((p) => p.period === selected) ?? plans.plans[0] : null;
    if (!plan) {
      void loadPlans();
      return;
    }
    setBusy(true);
    try {
      const r = await startStorePurchase(plan);
      switch (r.kind) {
        case "purchased":
          await reload();
          break;
        case "processing":
          setNote("processing");
          break;
        case "pending":
          setErrorKey(storeErrorNoteKey("pending", BILLING_STORE));
          break;
        case "signed_out":
          continueAfterSignIn.current = true;
          router.push("/auth");
          break;
        case "unavailable":
          setNote("store_soon");
          break;
        case "error":
          showStoreError(r.error);
          break;
        case "cancelled":
          break;
      }
    } finally {
      setBusy(false);
    }
  }

  async function buy(): Promise<void> {
    setNote(null);
    setErrorKey(null);
    if (action === "sign_in") {
      continueAfterSignIn.current = true;
      router.push("/auth");
      return;
    }
    if (action === "web_checkout") {
      // Belt and braces: a store build never opens the web checkout.
      if (!webCheckoutAllowed(FREEMIUM.distribution)) return;
      await Linking.openURL(WEB_CHECKOUT_URL).catch(() => undefined);
      setNote("web_opened");
      return;
    }
    if (action === "store" && (await goOnWithoutAccount("buy"))) await buyFromStore();
  }

  // Signed in on the way here from the button: carry on with the purchase —
  // unless the account turned out to be paid already (then the sheet says so).
  // Google Play still shows its own confirmation sheet before charging.
  useEffect(() => {
    if (!continueAfterSignIn.current || !acct?.signedIn) return;
    if (acct.paid || action === "soon") {
      continueAfterSignIn.current = false;
      return;
    }
    if (action === "store" && storeOn && plans.kind === "loading") return; // wait for prices
    continueAfterSignIn.current = false;
    if (action === "store" && storeOn && plans.kind !== "ok") return;
    void buy();
    // Deliberately keyed on the state it waits for only (buy reads the rest).
  }, [acct, plans, action, storeOn]);

  async function restore(): Promise<void> {
    setNote(null);
    setErrorKey(null);
    // The iPhone app restores signed out too (App Review 3.1.1 / 5.1.1).
    if (!signedIn && !STORE_PURCHASE_WITHOUT_ACCOUNT) {
      router.push("/auth");
      return;
    }
    if (!(await goOnWithoutAccount("restore"))) return;
    setBusy(true);
    try {
      if (storeOn) {
        const r = await restoreStorePurchases();
        if (r.kind === "restored") {
          await reload();
          setNote("restored");
        } else if (r.kind === "processing") setNote("processing");
        else if (r.kind === "none") setNote(signedIn ? "restore_none" : "restore_none_signed_out");
        else if (r.kind === "signed_out") router.push("/auth");
        else if (r.kind === "error") showStoreError(r.error);
        else setNote("restore_failed");
        return;
      }
      const now = await reload();
      if (!now.paid) setNote("restore_none");
    } catch {
      setNote("restore_failed");
    } finally {
      setBusy(false);
    }
  }

  const soonCta = STORE ? "mobile.paywall.cta_soon_play" : "mobile.paywall.cta_soon_ru";
  const soonFine = STORE ? "mobile.paywall.fine_soon_play" : "mobile.paywall.fine_soon";
  // A build that cannot take a payment — RuStore, or a store build made
  // without its RevenueCat key: say so up front, no dead button — and do not
  // send a signed-out person to sign in for a purchase that cannot happen yet.
  const saleOff = paywallSaleOff({ action, distribution: FREEMIUM.distribution, storeBillingOn: storeOn });
  const ctaKey =
    saleOff ? "mobile.paywall.cta_store"
    : action === "sign_in" ? "mobile.paywall.cta_sign_in"
    : action === "web_checkout" ? "mobile.paywall.cta_web"
    : action === "store" ? "mobile.paywall.cta_store"
    : soonCta;
  const storeNotReady = action === "store" && storeOn && plans.kind !== "ok";
  const ctaDisabled = action === "soon" || busy || acct === null || storeNotReady || saleOff;
  const fineKey =
    action === "soon" ? soonFine
    : saleOff ? "mobile.paywall.note_store_soon"
    : STORE ? COPY.fine
    : "mobile.paywall.fine_cancel";
  // Paid by this iPhone's own App Store plan alone (signed out, or the account
  // not caught up yet): say so, and link Apple's page where it is cancelled.
  const paidOnThisPhone = paid && STORE_PURCHASE_WITHOUT_ACCOUNT && !isPaidEntitlement(acct?.ent);
  const manageUrl = paidOnThisPhone
    ? APP_STORE_SUBSCRIPTIONS_URL
    : manageSubscriptionUrl(acct?.ent, FREEMIUM.distribution, ANDROID_PACKAGE);
  const paidSource = paidOnThisPhone ? sourceKey("app_store") : sourceKey(acct?.ent?.source);
  // Signing in is offered after the purchase, never required before it.
  const offerSignIn = paidOnThisPhone && !signedIn;
  // Before paying, signed out in the iPhone app: an account paid on another
  // device signs in instead of buying twice (5.1.1 forbids requiring it, not offering it).
  const offerSignInFirst = STORE_PURCHASE_WITHOUT_ACCOUNT && !signedIn && acct !== null;
  const leadKey = params.from === "upgrade" ? "mobile.paywall.lead_upgrade" : "mobile.paywall.lead";

  return (
    // iOS shows this as a page sheet below the status bar: no top inset there.
    <View style={[s.root, { paddingTop: Platform.OS === "ios" ? 0 : insets.top }]}>
      <View style={s.topBar}>
        <Pressable
          onPress={close}
          style={s.close}
          hitSlop={8}
          accessibilityRole="button"
          accessibilityLabel={t("mobile.paywall.close")}
        >
          <Ionicons name="close" size={26} color={colors.textSecondary} />
        </Pressable>
      </View>

      <ScrollView contentContainerStyle={[s.content, { paddingBottom: insets.bottom + space.xxl }]}>
        <View style={s.badge}>
          <Ionicons name="shield-checkmark" size={36} color={colors.green} />
        </View>
        <Text style={s.title} accessibilityRole="header">{t("mobile.paywall.title")}</Text>
        <Text style={s.lead}>{t(leadKey, { n: devices })}</Text>

        {paid ? (
          <View style={s.paidCard} accessibilityLiveRegion="polite">
            <Ionicons name="checkmark-circle" size={24} color={colors.green} />
            <View style={s.paidTextBox}>
              <Text style={s.paidText}>{t("mobile.paywall.paid_done")}</Text>
              {paidSource && <Text style={s.paidSource}>{t(paidSource)}</Text>}
            </View>
          </View>
        ) : showStorePlans ? (
          <StorePlans state={plans} selected={selected} onSelect={setSelected} onRetry={() => void loadPlans()} devices={devices} />
        ) : STORE ? null : (
          // The site APK and RuStore: the plan's published price. The Play
          // build shows only what Google Play itself quotes (above).
          <PublishedPrice price={price} devices={devices} />
        )}

        <View style={s.benefits}>
          {SHOWN_BENEFITS.map((b) => (
            <View key={b.key} style={s.benefitRow}>
              <Ionicons name={b.icon} size={22} color={colors.green} />
              <Text style={s.benefitText}>{t(b.key, { n: devices })}</Text>
            </View>
          ))}
        </View>

        {paid ? (
          <>
            <Pressable style={({ pressed }) => [s.cta, pressed && s.ctaPressed]} onPress={close} accessibilityRole="button">
              <Text style={s.ctaLabel}>{t("mobile.paywall.done")}</Text>
            </Pressable>
            {note && <Text style={s.fine} accessibilityLiveRegion="polite">{t(NOTE_KEYS[note])}</Text>}
            {offerSignIn && (
              // Optional, after the purchase (App Review 5.1.1): an account
              // only adds the other platforms and the device list.
              <>
                <Text style={s.fine}>
                  {/* Signed in here before: the plan may have just left that account. */}
                  {hadAccount ? t("mobile.paywall.sync_offer_back") : t("mobile.paywall.sync_offer", { n: devices })}
                </Text>
                <Pressable onPress={() => router.push("/auth")} style={s.restore} accessibilityRole="button">
                  <Text style={s.restoreLabel}>{t("mobile.settings.sign_in")}</Text>
                </Pressable>
              </>
            )}
            {manageUrl && (
              <Pressable
                onPress={() => void Linking.openURL(manageUrl).catch(() => undefined)}
                style={s.restore}
                accessibilityRole="link"
              >
                <Text style={s.restoreLabel}>{t("mobile.paywall.manage")}</Text>
              </Pressable>
            )}
          </>
        ) : (
          <>
            <Pressable
              style={({ pressed }) => [s.cta, pressed && !ctaDisabled && s.ctaPressed, ctaDisabled && s.ctaDisabled]}
              onPress={() => void buy()}
              disabled={ctaDisabled}
              accessibilityRole="button"
              accessibilityState={{ disabled: ctaDisabled, busy }}
              android_ripple={ctaDisabled ? undefined : { color: "#FFFFFF22" }}
            >
              {busy ? <ActivityIndicator color="#FFFFFF" /> : <Text style={s.ctaLabel}>{t(ctaKey)}</Text>}
            </Pressable>

            <Text style={s.fine} accessibilityLiveRegion="polite">
              {errorKey ? t(errorKey) : note ? t(NOTE_KEYS[note]) : t(fineKey)}
            </Text>

            <Pressable onPress={() => void restore()} style={s.restore} disabled={busy} accessibilityRole="button">
              <Text style={s.restoreLabel}>
                {t(signedIn || STORE_PURCHASE_WITHOUT_ACCOUNT ? "mobile.paywall.restore" : "mobile.paywall.restore_sign_in")}
              </Text>
            </Pressable>
            {offerSignInFirst && (
              <Pressable onPress={() => router.push("/auth")} style={s.restore} disabled={busy} accessibilityRole="button">
                <Text style={s.restoreLabel}>{t("mobile.paywall.sign_in_account")}</Text>
              </Pressable>
            )}
          </>
        )}

        <View style={s.privacyRow}>
          <Ionicons name="shield-outline" size={14} color={colors.textSecondary} />
          <Text style={s.privacy}>{t("mobile.paywall.always_free")}</Text>
        </View>

        {STORE && (
          // A store subscription sheet must link its Terms of Use and Privacy
          // Policy (App Store Review 3.1.2; Google Play asks the same).
          <View style={s.legalRow}>
            <Pressable onPress={() => void Linking.openURL(TERMS_URL).catch(() => undefined)} style={s.legal} accessibilityRole="link">
              <Text style={s.legalLabel}>{t("mobile.settings.terms")}</Text>
            </Pressable>
            <Pressable onPress={() => void Linking.openURL(PRIVACY_POLICY_URL).catch(() => undefined)} style={s.legal} accessibilityRole="link">
              <Text style={s.legalLabel}>{t("mobile.settings.privacy_policy")}</Text>
            </Pressable>
          </View>
        )}
      </ScrollView>
    </View>
  );
}

const s = StyleSheet.create({
  root: { flex: 1, backgroundColor: colors.bg },
  topBar: { flexDirection: "row", justifyContent: "flex-end", paddingHorizontal: space.md, paddingTop: space.sm },
  close: { width: 44, height: 44, borderRadius: 22, alignItems: "center", justifyContent: "center" },
  content: { paddingHorizontal: space.xl },

  badge: {
    alignSelf: "center", width: 72, height: 72, borderRadius: 36,
    backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke,
    alignItems: "center", justifyContent: "center",
  },
  title: { ...typo.title1, color: colors.textPrimary, textAlign: "center", marginTop: space.lg },
  lead: { fontSize: 17, lineHeight: 24, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },

  paidCard: {
    flexDirection: "row", alignItems: "center", gap: space.md, marginTop: space.xxl,
    backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke,
    borderRadius: radius.card, padding: space.lg,
  },
  paidTextBox: { flex: 1 },
  paidText: { fontSize: 17, lineHeight: 24, color: colors.textPrimary },
  paidSource: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: 2 },

  benefits: {
    marginTop: space.xxl, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, paddingHorizontal: space.lg, paddingVertical: space.sm,
  },
  benefitRow: { flexDirection: "row", alignItems: "center", gap: space.md, paddingVertical: space.md },
  benefitText: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, flex: 1 },

  cta: {
    minHeight: 56, backgroundColor: colors.blueFill, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.xxl,
  },
  ctaPressed: { backgroundColor: colors.bluePressed },
  ctaDisabled: { opacity: 0.5 },
  ctaLabel: { fontSize: 18, fontWeight: "700", color: "#FFFFFF", textAlign: "center" },
  fine: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, textAlign: "center", marginTop: space.md },
  restore: { alignSelf: "center", minHeight: 44, justifyContent: "center", paddingHorizontal: space.lg, marginTop: space.sm },
  restoreLabel: { fontSize: 15, fontWeight: "600", color: colors.blue, textAlign: "center" },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, marginTop: space.xl, paddingHorizontal: space.md,
  },
  privacy: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, textAlign: "center", flexShrink: 1 },
  legalRow: { flexDirection: "row", justifyContent: "center", flexWrap: "wrap", gap: space.md, marginTop: space.md },
  legal: { minHeight: 44, justifyContent: "center", paddingHorizontal: space.sm },
  legalLabel: { fontSize: 14, lineHeight: 20, color: colors.textSecondary, textDecorationLine: "underline" },
});
