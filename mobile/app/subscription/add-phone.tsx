/**
 * "Add a relative's phone" (billing plan §2.4): a one-time 6-digit code, the
 * same code as a QR for the phone across the table, and a ready message for
 * the phone across town — install link, the button to press, the code, how
 * long it lasts. Only the payer gets here (the hub hides the button
 * otherwise, and the server refuses anyway).
 */
import { useCallback, useEffect, useState } from "react";
import { Alert, Share, StyleSheet, Text, View } from "react-native";
import * as Clipboard from "expo-clipboard";
import { useTranslation } from "react-i18next";

import { QrCode } from "../../src/components/billing/QrCode";
import { BigButton, Card, CardBody, Hint, Screen, Spinner } from "../../src/components/billing/Ui";
import type { ClaimCodeAnswer } from "../../src/lib/billing-api";
import { billing } from "../../src/services/billing";
import { errorCopyKey } from "../../src/utils/billing-copy";
import { clockTime } from "../../src/utils/relative-time";
import { colors, space } from "../../src/utils/theme";

export default function AddPhoneScreen() {
  const { t, i18n } = useTranslation();
  const [code, setCode] = useState<ClaimCodeAnswer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const make = useCallback(async () => {
    setBusy(true);
    const result = await billing.createClaimCode();
    setBusy(false);
    if (result.data) {
      setCode(result.data);
      setError(null);
    } else {
      setError(result.error.code);
    }
  }, []);

  useEffect(() => {
    void make();
  }, [make]);

  async function share() {
    if (!code) return;
    try {
      await Share.share({ message: t("mobile.billing.add_share_text", { install: code.install_url, code: code.code }) });
    } catch {
      // The share sheet was dismissed, or no app could take it: nothing to say.
    }
  }

  async function copy() {
    if (!code) return;
    await Clipboard.setStringAsync(code.code);
    Alert.alert(t("mobile.billing.add_copied"));
  }

  if (!code && busy) return <Screen><Spinner /></Screen>;

  if (!code) {
    const key = errorCopyKey(error);
    return (
      <Screen>
        <Hint icon="alert-circle-outline">{key ? t(key) : t("mobile.billing.add_failed")}</Hint>
        <BigButton label={t("mobile.billing.retry")} onPress={() => void make()} />
      </Screen>
    );
  }

  const spaced = `${code.code.slice(0, 3)} ${code.code.slice(3)}`;

  return (
    <Screen>
      <Text style={s.body}>{t("mobile.billing.add_body")}</Text>
      <Card>
        <Text style={s.codeLabel}>{t("mobile.billing.add_code_label")}</Text>
        <Text style={s.code} accessibilityLabel={`${t("mobile.billing.add_code_label")}: ${code.code.split("").join(" ")}`}>{spaced}</Text>
        <View style={s.qr}>
          <QrCode value={code.qr_payload} label={t("mobile.billing.add_qr_a11y", { code: code.code })} />
        </View>
        <CardBody>{t("mobile.billing.add_expires", { time: clockTime(code.expires_at * 1000, i18n.language) })}</CardBody>
        <Hint>{t("mobile.billing.active_seats", { used: code.seats_used, total: code.seats_total })}</Hint>
      </Card>
      <BigButton label={t("mobile.billing.add_share")} onPress={() => void share()} icon="paper-plane-outline" />
      <BigButton kind="secondary" label={t("mobile.billing.add_copy")} onPress={() => void copy()} icon="copy-outline" />
      <BigButton kind="text" label={t("mobile.billing.add_new_code")} onPress={() => void make()} busy={busy} />
    </Screen>
  );
}

const s = StyleSheet.create({
  body: { fontSize: 17, lineHeight: 24, color: colors.textSecondary },
  codeLabel: { fontSize: 13, fontWeight: "600", textTransform: "uppercase", letterSpacing: 0.6, color: colors.textMuted, textAlign: "center" },
  code: { fontSize: 44, lineHeight: 52, fontWeight: "800", letterSpacing: 6, color: colors.textPrimary, textAlign: "center" },
  qr: { alignItems: "center", marginVertical: space.md },
});
