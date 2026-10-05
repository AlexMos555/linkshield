/**
 * The confirmation screen (billing plan §2.5 screen 5; consent text ru/v1).
 *
 * Shown BEFORE the operator's SMS: what is being bought, the price, the number
 * that pays, how to cancel — the same words whose hash the server stores in
 * its consent journal with the price shown. The phone number goes to the
 * server once, in the checkout body, and is never kept on the phone.
 */
import { useState } from "react";
import { Alert, Linking, StyleSheet, Text, TextInput, View } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Card, CardBody, CardTitle, Hint, Screen } from "../../src/components/billing/Ui";
import { useBilling } from "../../src/hooks/useBilling";
import { billing } from "../../src/services/billing";
import { errorCopyKey, formatPhone, maskPhone, normalizeRuPhone, planLabel } from "../../src/utils/billing-copy";
import { colors, radius, space } from "../../src/utils/theme";

/** Providers that grant without a charge are not offered to a person; the first chargeable one is used. */
const GRANT_PROVIDERS: ReadonlySet<string> = new Set(["promo", "t2_option"]);

/** The same pages Settings → About opens. */
const TERMS_URL = "https://cleanway.ai/terms";
const PRIVACY_URL = "https://cleanway.ai/privacy-policy";

export default function CheckoutScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const { plan } = useLocalSearchParams<{ plan?: string }>();
  const b = useBilling();
  const [phone, setPhone] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);

  const info = billing.plan(plan ?? null);
  const e164 = normalizeRuPhone(phone);
  const provider = (b.plans?.providers ?? []).find((p) => !GRANT_PROVIDERS.has(p)) ?? null;

  if (!info) {
    return (
      <Screen>
        <Hint icon="alert-circle-outline">{t("mobile.billing.plans_failed")}</Hint>
        <BigButton kind="secondary" label={t("mobile.billing.retry")} onPress={() => router.back()} />
      </Screen>
    );
  }

  async function getSms() {
    setTouched(true);
    if (!e164 || !info) return;
    if (!provider) {
      Alert.alert(t("mobile.billing.checkout_failed_title"), t("mobile.billing.checkout_provider_unavailable"));
      return;
    }
    setBusy(true);
    const result = await billing.buy(info.code, e164, provider);
    setBusy(false);
    if (!result.data) {
      const key = errorCopyKey(result.error.code);
      Alert.alert(t("mobile.billing.checkout_failed_title"), key ? t(key) : t("mobile.billing.error_generic", { code: result.error.code }));
      return;
    }
    // Some providers confirm on a page of their own; the SMS screen still polls the result.
    if (result.data.kind === "redirect" && result.data.url) void Linking.openURL(result.data.url);
    router.replace({ pathname: "/subscription/sms", params: { phone: maskPhone(e164), provider } });
  }

  return (
    <Screen>
      <Card>
        <CardTitle>{t("mobile.billing.consent_you_connect", { plan: planLabel(t, info.code) })}</CardTitle>
        <CardBody>{t("mobile.billing.consent_price", { price: info.price_rub })}</CardBody>
        <CardBody>{t("mobile.billing.consent_charge_from", { phone: e164 ? formatPhone(e164) : "—" })}</CardBody>
        <Hint>{t("mobile.billing.consent_seller")}</Hint>
        <Hint icon="close-circle-outline">{t("mobile.billing.consent_cancel_how")}</Hint>
        <Hint icon="shield-checkmark-outline">{t("mobile.billing.consent_rules")}</Hint>
      </Card>

      <View>
        <Text style={s.label} nativeID="phone-label">{t("mobile.billing.checkout_phone_label")}</Text>
        <TextInput
          style={[s.input, touched && !e164 && s.inputBad]}
          value={phone}
          onChangeText={setPhone}
          onBlur={() => setTouched(true)}
          keyboardType="phone-pad"
          textContentType="telephoneNumber"
          autoComplete="tel"
          placeholder={t("mobile.billing.checkout_phone_placeholder")}
          placeholderTextColor={colors.textMuted}
          accessibilityLabel={t("mobile.billing.checkout_phone_label")}
          accessibilityLabelledBy="phone-label"
        />
        {touched && !e164 ? <Text style={s.error}>{t("mobile.billing.checkout_phone_invalid")}</Text> : null}
      </View>

      <BigButton label={t("mobile.billing.consent_get_sms")} onPress={() => void getSms()} busy={busy} disabled={touched && !e164} icon="chatbox-ellipses-outline" />

      <View style={s.links}>
        <BigButton kind="text" label={t("mobile.billing.consent_terms")} onPress={() => void Linking.openURL(TERMS_URL)} />
        <BigButton kind="text" label={t("mobile.billing.consent_privacy")} onPress={() => void Linking.openURL(PRIVACY_URL)} />
      </View>
    </Screen>
  );
}

const s = StyleSheet.create({
  label: { fontSize: 16, lineHeight: 22, color: colors.textSecondary, marginBottom: space.sm },
  input: {
    minHeight: 60, borderRadius: radius.control, borderWidth: 1, borderColor: colors.stroke, backgroundColor: colors.bgInput,
    color: colors.textPrimary, fontSize: 24, letterSpacing: 1, paddingHorizontal: space.lg,
  },
  inputBad: { borderColor: colors.danger },
  error: { fontSize: 15, color: colors.danger, marginTop: space.xs },
  links: { gap: 0 },
});
