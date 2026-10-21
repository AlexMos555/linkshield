/**
 * Waiting for the operator (billing plan §2.5 screens 6–8). The confirmation
 * itself is the operator's SMS, outside the app; this screen polls the
 * checkout and names the outcome in the operator's own terms — no money,
 * payments barred, passport, a corporate number, declined, no answer — and
 * says every time that nothing was charged. With the Fake provider the
 * answer arrives by itself; the screen says that it is a test.
 */
import { useEffect, useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { BigButton, Card, CardBody, CardTitle, Hint, Screen } from "../../src/components/billing/Ui";
import { billing } from "../../src/services/billing";
import { failureCopyKey } from "../../src/utils/billing-copy";
import { colors, space } from "../../src/utils/theme";

const POLL_MS = 3_000;
/** Five minutes of polling, then the honest "no answer" (the server's own pending timeout is 30 min). */
const MAX_POLLS = 100;

type Outcome = { kind: "waiting" } | { kind: "done" } | { kind: "failed"; reason: string | null };

export default function SmsScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const { phone, provider } = useLocalSearchParams<{ phone?: string; provider?: string }>();
  const [outcome, setOutcome] = useState<Outcome>({ kind: "waiting" });

  useEffect(() => {
    let alive = true;
    let polls = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const tick = async () => {
      const state = await billing.pollCheckout();
      if (!alive) return;
      if (state && state.status === "active") setOutcome({ kind: "done" });
      else if (state && state.status !== "pending") setOutcome({ kind: "failed", reason: state.failure_reason });
      else if (++polls < MAX_POLLS) timer = setTimeout(() => void tick(), POLL_MS);
      else setOutcome({ kind: "failed", reason: "timeout" });
    };
    timer = setTimeout(() => void tick(), POLL_MS);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, []);

  if (outcome.kind === "done") {
    return (
      <Screen>
        <Card tone="green">
          <CardTitle tone="green">{t("mobile.billing.sms_done_title")}</CardTitle>
          <CardBody>{t("mobile.billing.sms_done_body")}</CardBody>
        </Card>
        <BigButton label={t("mobile.billing.done")} onPress={() => router.replace("/subscription")} />
      </Screen>
    );
  }

  if (outcome.kind === "failed") {
    return (
      <Screen>
        <Card tone="amber">
          <CardTitle tone="amber">{t("mobile.billing.sms_failed_title")}</CardTitle>
          <CardBody>{t(failureCopyKey(outcome.reason))}</CardBody>
        </Card>
        <BigButton label={t("mobile.billing.sms_try_again")} onPress={() => router.replace("/subscription/plans")} />
        <BigButton
          kind="secondary"
          label={t("mobile.billing.sms_cancel")}
          onPress={() => { void billing.forgetCheckout(); router.replace("/subscription"); }}
        />
      </Screen>
    );
  }

  return (
    <Screen>
      <Card>
        <CardTitle>{t("mobile.billing.sms_title")}</CardTitle>
        <CardBody>{t("mobile.billing.sms_body", { phone: phone || "—" })}</CardBody>
        <View style={s.waitRow} accessibilityLiveRegion="polite">
          <ActivityIndicator color={colors.blue} />
          <Text style={s.wait}>{t("mobile.billing.sms_waiting")}</Text>
        </View>
        {provider === "fake" && <Hint icon="flask-outline">{t("mobile.billing.sms_test_mode")}</Hint>}
      </Card>
      <BigButton
        kind="secondary"
        label={t("mobile.billing.sms_cancel")}
        onPress={() => { void billing.forgetCheckout(); router.replace("/subscription"); }}
      />
    </Screen>
  );
}

const s = StyleSheet.create({
  waitRow: { flexDirection: "row", alignItems: "center", gap: space.md, marginTop: space.sm },
  wait: { fontSize: 17, color: colors.textSecondary },
});
