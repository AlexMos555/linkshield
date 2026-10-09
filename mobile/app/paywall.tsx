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
 *   • not signed in → sign in first (a plan belongs to an account), then
 *     the purchase continues by itself on return;
 *   • the APK from our site → the site's checkout, in the browser;
 *   • the Google Play build → Google Play billing (src/services/store-billing.ts):
 *     monthly / yearly with the store's own prices, then our server confirms;
 *     never a link to the web checkout, never a price typed into the app;
 *   • the iPhone app → the App Store, the same way (App Review 3.1.1: no
 *     web checkout, no other store); Terms of Use and Privacy Policy links
 *     under the button (3.1.2); without EXPO_PUBLIC_REVENUECAT_IOS_KEY it
 *     says "paying in the app is coming soon";
 *   • RuStore → not built yet: "coming soon";
 *   • Russia → phone-balance billing is not merged yet: "coming soon" (the
 *     Play build does not mention other ways to pay).
 * Coming back to the sheet re-reads the plan; once it is paid, it says so,
 * where it was paid, and (store plans) offers "Manage subscription".
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, Pressable, Linking, AppState, ActivityIndicator, Platform,
} from "react-native";
import { useFocusEffect, useLocalSearchParams, useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Localization from "expo-localization";
import Constants from "expo-constants";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../src/utils/theme";
import { getSessionState } from "../src/services/auth";
import { getEntitlement, type EntitlementResponse } from "../src/services/api";
import { FREEMIUM, applyEntitlement, isPaid } from "../src/services/freemium";
import {
  BILLING_STORE, loadStorePlans, restoreStorePurchases, startStorePurchase, storeBillingOn,
} from "../src/services/store-billing";
import {
  PRICES, WEB_CHECKOUT_URL, marketFor, paywallBenefits, priceDisplay, purchaseAction, revenueCatStore,
  webCheckoutAllowed, type PaywallBenefit,
} from "../src/utils/freemium";
import {
  manageSubscriptionUrl, storeCopyKeys, storeErrorNoteKey, type PlanPeriod,
} from "../src/utils/store-billing";
import { sourceKey } from "../src/utils/account-session";
import { StorePlans, type StorePlansState } from "../src/components/paywall/StorePlans";
import { PublishedPrice } from "../src/components/paywall/PublishedPrice";

type IconName = keyof typeof Ionicons.glyphMap;

const BENEFITS: Record<PaywallBenefit, { icon: IconName; key: string }> = {
  unlimited: { icon: "infinite-outline", key: "mobile.paywall.benefit_unlimited" },
  sms: { icon: "chatbox-ellipses-outline", key: "mobile.paywall.benefit_sms" },
  text_model: { icon: "document-text-outline", key: "mobile.paywall.benefit_text_model" },
  calls: { icon: "call-outline", key: "mobile.paywall.benefit_calls" },
  devices: { icon: "phone-portrait-outline", key: "mobile.paywall.benefit_devices" },
};
// Only what this build can do: the site and Play APKs cannot read SMS, and
// the iPhone app has no message analyzer or call guard (paywallBenefits).
const SHOWN_BENEFITS = paywallBenefits(FREEMIUM.distribution).map((b) => BENEFITS[b]);

const TERMS_URL = "https://cleanway.ai/terms";
const PRIVACY_URL = "https://cleanway.ai/privacy-policy";
const ANDROID_PACKAGE = Constants.expoConfig?.android?.package ?? "ai.cleanway.app";

/** A store build (Google Play, the iPhone app): prices and purchases come from the store. */
const STORE = revenueCatStore(FREEMIUM.distribution);
const COPY = storeCopyKeys(BILLING_STORE);

/** A note under the button after an attempt: what happened, in words. */
type Note = null | "store_soon" | "restore_none" | "restore_failed" | "web_opened" | "processing" | "restored";

// Literal keys, so scripts/check-mobile-i18n.py can see every one.
const NOTE_KEYS: Record<Exclude<Note, null>, string> = {
  store_soon: "mobile.paywall.note_store_soon",
  restore_none: "mobile.paywall.note_restore_none",
  restore_failed: "mobile.paywall.note_restore_failed",
  web_opened: "mobile.paywall.note_web_opened",
  processing: "mobile.paywall.note_processing",
  restored: "mobile.paywall.note_restored",
};

interface Account {
  signedIn: boolean;
  paid: boolean;
  ent: EntitlementResponse | null;
}

export default function PaywallScreen() {
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

  /** Who is here and whether the plan is paid now — after sign-in, a checkout, a restore. */
  const reload = useCallback(async (): Promise<Account> => {
    const st = await getSessionState();
    if (st.kind === "none") {
      const next = { signedIn: false, paid: false, ent: null };
      setAcct(next);
      return next;
    }
    const { data } = await getEntitlement();
    const next = data
      ? { signedIn: true, paid: await applyEntitlement(data), ent: data }
      : { signedIn: true, paid: await isPaid(false), ent: null };
    setAcct(next);
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
    if (action === "store") await buyFromStore();
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
    if (!signedIn) {
      router.push("/auth");
      return;
    }
    setBusy(true);
    try {
      if (storeOn) {
        const r = await restoreStorePurchases();
        if (r.kind === "restored") {
          await reload();
          setNote("restored");
        } else if (r.kind === "processing") setNote("processing");
        else if (r.kind === "none") setNote("restore_none");
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
  // A store build made without its RevenueCat key: say so up front, no dead
  // button — and do not send a signed-out person to sign in for a purchase
  // that cannot happen yet.
  const playOff = STORE && !storeOn && (action === "store" || action === "sign_in");
  const ctaKey =
    playOff ? "mobile.paywall.cta_store"
    : action === "sign_in" ? "mobile.paywall.cta_sign_in"
    : action === "web_checkout" ? "mobile.paywall.cta_web"
    : action === "store" ? "mobile.paywall.cta_store"
    : soonCta;
  const storeNotReady = action === "store" && storeOn && plans.kind !== "ok";
  const ctaDisabled = action === "soon" || busy || acct === null || storeNotReady || playOff;
  const fineKey =
    action === "soon" ? soonFine
    : playOff ? "mobile.paywall.note_store_soon"
    : STORE ? COPY.fine
    : "mobile.paywall.fine_cancel";
  const manageUrl = manageSubscriptionUrl(acct?.ent, FREEMIUM.distribution, ANDROID_PACKAGE);
  const paidSource = sourceKey(acct?.ent?.source);
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
                {t(signedIn ? "mobile.paywall.restore" : "mobile.paywall.restore_sign_in")}
              </Text>
            </Pressable>
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
            <Pressable onPress={() => void Linking.openURL(PRIVACY_URL).catch(() => undefined)} style={s.legal} accessibilityRole="link">
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
    minHeight: 56, backgroundColor: colors.blue, borderRadius: radius.control,
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
