/**
 * The paywall — one sheet, opened where the free plan's daily limit stopped
 * a check (by itself once a day, or from the "detailed analysis is in the
 * subscription" card). docs/ACCOUNTS_BILLING_PLAN.md §5.
 *
 * Price large, one primary button, a plain list of what the plan adds, a
 * small "already paying" link and a close button. It never says protection
 * stops: sites on the scam list are blocked paid or not.
 *
 * Paying (src/utils/freemium.ts purchaseAction):
 *   • not signed in → sign in first (a plan belongs to an account);
 *   • the APK from our site → the site's checkout, in the browser;
 *   • a store build (EXPO_PUBLIC_DISTRIBUTION=play|rustore) → the store's
 *     billing (startStorePurchase, TODO) — never a link to the web checkout;
 *   • Russia → phone-balance billing is not merged yet: "coming soon".
 * Coming back to the sheet re-reads the plan; once it is paid, it says so.
 */
import { useCallback, useEffect, useState } from "react";
import { View, Text, StyleSheet, ScrollView, Pressable, Linking, AppState, ActivityIndicator } from "react-native";
import { useFocusEffect, useRouter } from "expo-router";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import * as Localization from "expo-localization";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";

import { colors, type as typo, space, radius } from "../src/utils/theme";
import { getSessionState } from "../src/services/auth";
import { FREEMIUM, isPaid, startStorePurchase } from "../src/services/freemium";
import {
  PRICES, WEB_CHECKOUT_URL, marketFor, priceDisplay, purchaseAction, webCheckoutAllowed,
} from "../src/utils/freemium";

type IconName = keyof typeof Ionicons.glyphMap;

const BENEFITS: ReadonlyArray<{ icon: IconName; key: string }> = [
  { icon: "infinite-outline", key: "mobile.paywall.benefit_unlimited" },
  { icon: "chatbox-ellipses-outline", key: "mobile.paywall.benefit_sms" },
  { icon: "document-text-outline", key: "mobile.paywall.benefit_text_model" },
  { icon: "call-outline", key: "mobile.paywall.benefit_calls" },
  { icon: "phone-portrait-outline", key: "mobile.paywall.benefit_devices" },
];

/** A note under the button after an attempt: what happened, in words. */
type Note = null | "store_soon" | "restore_none" | "restore_failed" | "web_opened";

// Literal keys, so scripts/check-mobile-i18n.py can see every one.
const NOTE_KEYS: Record<Exclude<Note, null>, string> = {
  store_soon: "mobile.paywall.note_store_soon",
  restore_none: "mobile.paywall.note_restore_none",
  restore_failed: "mobile.paywall.note_restore_failed",
  web_opened: "mobile.paywall.note_web_opened",
};

export default function PaywallScreen() {
  const router = useRouter();
  const insets = useSafeAreaInsets();
  const { t, i18n } = useTranslation();
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [paid, setPaid] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<Note>(null);

  const market = marketFor(i18n.language, Localization.getLocales()[0]?.regionCode);
  const price = priceDisplay(market, FREEMIUM.distribution);
  const devices = PRICES[market].devices;

  const close = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);

  /** Who is here and whether the plan is paid now — after sign-in, a checkout, a restore. */
  const reload = useCallback(async (force: boolean) => {
    const st = await getSessionState();
    const inNow = st.kind !== "none";
    setSignedIn(inNow);
    if (!inNow) return false;
    const nowPaid = await isPaid(force);
    setPaid(nowPaid);
    return nowPaid;
  }, []);

  // Back from the sign-in screen: the button becomes the purchase.
  useFocusEffect(useCallback(() => {
    void reload(true);
  }, [reload]));

  // Back from the browser's checkout.
  useEffect(() => {
    const sub = AppState.addEventListener("change", (next) => {
      if (next === "active") void reload(true);
    });
    return () => sub.remove();
  }, [reload]);

  const action = purchaseAction({ signedIn: signedIn === true, market, distribution: FREEMIUM.distribution });

  async function buy(): Promise<void> {
    setNote(null);
    if (action === "sign_in") {
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
    if (action === "store") {
      setBusy(true);
      try {
        const r = await startStorePurchase();
        if (r.kind === "purchased") await reload(true);
        else if (r.kind === "unavailable") setNote("store_soon");
      } finally {
        setBusy(false);
      }
    }
  }

  async function restore(): Promise<void> {
    setNote(null);
    if (!signedIn) {
      router.push("/auth");
      return;
    }
    setBusy(true);
    try {
      const nowPaid = await reload(true);
      if (!nowPaid) setNote("restore_none");
    } catch {
      setNote("restore_failed");
    } finally {
      setBusy(false);
    }
  }

  const ctaKey =
    action === "sign_in" ? "mobile.paywall.cta_sign_in"
    : action === "web_checkout" ? "mobile.paywall.cta_web"
    : action === "store" ? "mobile.paywall.cta_store"
    : "mobile.paywall.cta_soon_ru";
  const ctaDisabled = action === "soon" || busy || signedIn === null;

  return (
    <View style={[s.root, { paddingTop: insets.top }]}>
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
        <Text style={s.lead}>{t("mobile.paywall.lead")}</Text>

        {paid ? (
          <View style={s.paidCard} accessibilityLiveRegion="polite">
            <Ionicons name="checkmark-circle" size={24} color={colors.green} />
            <Text style={s.paidText}>{t("mobile.paywall.paid_done")}</Text>
          </View>
        ) : (
          <View
            style={s.priceBlock}
            accessible
            accessibilityLabel={[
              t(price.period === "year" ? "mobile.paywall.per_year" : "mobile.paywall.per_month", { price: price.price }),
              t("mobile.paywall.devices_note", { n: devices }),
            ].join(". ")}
          >
            <View style={s.priceRow}>
              <Text style={s.price}>{price.price}</Text>
              <Text style={s.period}>{t(price.period === "year" ? "mobile.paywall.period_year" : "mobile.paywall.period_month")}</Text>
            </View>
            <Text style={s.priceSub}>{t("mobile.paywall.devices_note", { n: devices })}</Text>
            {price.alt && (
              <Text style={s.priceAlt}>
                {t(price.alt.period === "year" ? "mobile.paywall.alt_year" : "mobile.paywall.alt_month", { price: price.alt.price })}
              </Text>
            )}
          </View>
        )}

        <View style={s.benefits}>
          {BENEFITS.map((b) => (
            <View key={b.key} style={s.benefitRow}>
              <Ionicons name={b.icon} size={22} color={colors.green} />
              <Text style={s.benefitText}>{t(b.key, { n: devices })}</Text>
            </View>
          ))}
        </View>

        {paid ? (
          <Pressable style={({ pressed }) => [s.cta, pressed && s.ctaPressed]} onPress={close} accessibilityRole="button">
            <Text style={s.ctaLabel}>{t("mobile.paywall.done")}</Text>
          </Pressable>
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
              {note ? t(NOTE_KEYS[note]) : t(action === "soon" ? "mobile.paywall.fine_soon" : "mobile.paywall.fine_cancel")}
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

  priceBlock: { alignItems: "center", marginTop: space.xxl },
  priceRow: { flexDirection: "row", alignItems: "baseline", gap: space.xs },
  price: { fontSize: 48, lineHeight: 56, fontWeight: "800", color: colors.textPrimary },
  period: { fontSize: 20, lineHeight: 26, fontWeight: "600", color: colors.textSecondary },
  priceSub: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, marginTop: space.xs, textAlign: "center" },
  priceAlt: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: space.xs, textAlign: "center" },

  paidCard: {
    flexDirection: "row", alignItems: "center", gap: space.md, marginTop: space.xxl,
    backgroundColor: colors.greenWash, borderWidth: 1, borderColor: colors.greenStroke,
    borderRadius: radius.card, padding: space.lg,
  },
  paidText: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, flex: 1 },

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
});
