import { View, Text, StyleSheet, TouchableOpacity, ScrollView, Linking } from "react-native";
import { useRouter } from "expo-router";
import * as Haptics from "expo-haptics";
import { colors, spacing, fontSize } from "../src/utils/theme";

const plans = [
  {
    name: "Free",
    price: "$0",
    period: "forever",
    features: ["10 checks/day", "Local scoring", "Basic protection"],
    current: true,
  },
  {
    name: "Personal",
    price: "$4.99",
    period: "/month",
    features: ["Unlimited checks", "9 threat sources + ML", "Full Privacy Audit", "Weekly Report", "Security Score", "Breach monitoring"],
    popular: true,
  },
  {
    name: "Family",
    price: "$9.99",
    period: "/month",
    features: ["Everything in Personal", "Up to 6 devices", "Family Hub", "E2E encrypted alerts", "Parental mode"],
  },
];

export default function UpgradeScreen() {
  const router = useRouter();

  function handleUpgrade(plan: string) {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    Linking.openURL(`https://cleanway.ai/pricing?plan=${plan}`);
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Upgrade Protection</Text>
      <Text style={styles.subtitle}>Get unlimited checks and full threat intelligence</Text>

      {plans.map((plan, i) => (
        <View key={i} style={[styles.card, plan.popular && styles.cardPopular]}>
          {plan.popular && <Text style={styles.popular}>Most Popular</Text>}
          <Text style={styles.planName}>{plan.name}</Text>
          <View style={styles.priceRow}>
            <Text style={styles.price}>{plan.price}</Text>
            <Text style={styles.period}>{plan.period}</Text>
          </View>

          {plan.features.map((f, j) => (
            <View key={j} style={styles.featureRow}>
              <Text style={styles.check}>{"\u2713"}</Text>
              <Text style={styles.featureText}>{f}</Text>
            </View>
          ))}

          {plan.current ? (
            <View style={styles.currentBadge}>
              <Text style={styles.currentText}>Current Plan</Text>
            </View>
          ) : (
            <TouchableOpacity
              style={[styles.btn, plan.popular && styles.btnPopular]}
              onPress={() => handleUpgrade(plan.name.toLowerCase())}
            >
              <Text style={[styles.btnText, plan.popular && styles.btnTextPopular]}>
                Start Free Trial
              </Text>
            </TouchableOpacity>
          )}
        </View>
      ))}

      <Text style={styles.note}>14-day free trial. Cancel anytime. No credit card to start.</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: 100 },
  title: { fontSize: fontSize.xxl, fontWeight: "800", color: colors.white, textAlign: "center", marginBottom: spacing.xs },
  subtitle: { fontSize: fontSize.md, color: colors.textSecondary, textAlign: "center", marginBottom: spacing.xl },
  card: {
    backgroundColor: colors.bgCard, borderRadius: 16, padding: spacing.lg,
    marginBottom: spacing.md, borderWidth: 1, borderColor: colors.border,
  },
  cardPopular: { borderColor: colors.safe, borderWidth: 2 },
  popular: {
    position: "absolute", top: -12, alignSelf: "center",
    backgroundColor: colors.safe, color: colors.safeBg,
    paddingHorizontal: 16, paddingVertical: 4, borderRadius: 12,
    fontSize: fontSize.xs, fontWeight: "700", overflow: "hidden",
  },
  planName: { fontSize: fontSize.xl, fontWeight: "700", color: colors.white, marginBottom: spacing.sm },
  priceRow: { flexDirection: "row", alignItems: "baseline", marginBottom: spacing.lg },
  price: { fontSize: 36, fontWeight: "800", color: colors.white },
  period: { fontSize: fontSize.md, color: colors.textMuted, marginLeft: 4 },
  featureRow: { flexDirection: "row", alignItems: "center", gap: spacing.sm, paddingVertical: 4 },
  check: { color: colors.safe, fontSize: 16, fontWeight: "700" },
  featureText: { color: colors.textSecondary, fontSize: fontSize.md },
  btn: {
    marginTop: spacing.lg, borderRadius: 12, padding: 14,
    alignItems: "center", borderWidth: 1, borderColor: colors.border,
  },
  btnPopular: { backgroundColor: colors.safe, borderColor: colors.safe },
  btnText: { color: colors.textSecondary, fontWeight: "700", fontSize: fontSize.md },
  btnTextPopular: { color: colors.safeBg },
  currentBadge: {
    marginTop: spacing.lg, borderRadius: 12, padding: 14,
    alignItems: "center", backgroundColor: colors.bgInput,
  },
  currentText: { color: colors.textMuted, fontWeight: "600" },
  note: { textAlign: "center", color: colors.textMuted, fontSize: fontSize.sm, marginTop: spacing.md },
});
