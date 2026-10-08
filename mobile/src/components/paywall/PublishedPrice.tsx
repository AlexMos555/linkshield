/**
 * The plan's published price, large (src/utils/freemium.ts priceDisplay) —
 * for the APK from our site and RuStore. The Google Play build never shows
 * it: there only Google Play's own quote is shown (StorePlans.tsx).
 */
import { View, Text, StyleSheet } from "react-native";
import { useTranslation } from "react-i18next";

import { colors, space } from "../../utils/theme";
import type { priceDisplay } from "../../utils/freemium";

export function PublishedPrice({ price, devices }: { price: ReturnType<typeof priceDisplay>; devices: number }) {
  const { t } = useTranslation();
  return (
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
  );
}

const s = StyleSheet.create({
  priceBlock: { alignItems: "center", marginTop: space.xxl },
  priceRow: { flexDirection: "row", alignItems: "baseline", gap: space.xs },
  price: { fontSize: 48, lineHeight: 56, fontWeight: "800", color: colors.textPrimary },
  period: { fontSize: 20, lineHeight: 26, fontWeight: "600", color: colors.textSecondary },
  priceSub: { fontSize: 17, lineHeight: 24, color: colors.textPrimary, marginTop: space.xs, textAlign: "center" },
  priceAlt: { fontSize: 15, lineHeight: 21, color: colors.textSecondary, marginTop: space.xs, textAlign: "center" },
});
