import { useState, useEffect } from "react";
import { View, Text, StyleSheet, FlatList, TouchableOpacity, RefreshControl } from "react-native";
import { useRouter } from "expo-router";
import { colors, spacing, fontSize, levelColors } from "../../src/utils/theme";
import { getRecentChecks } from "../../src/services/database";

export default function HistoryScreen() {
  const router = useRouter();
  const [checks, setChecks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  function load() {
    getRecentChecks(100).then((data) => {
      setChecks(data);
      setLoading(false);
      setRefreshing(false);
    }).catch(() => { setLoading(false); setRefreshing(false); });
  }

  useEffect(() => { load(); }, []);

  const renderItem = ({ item }: { item: any }) => {
    const color = levelColors[item.level as keyof typeof levelColors] || colors.textMuted;
    const icons = { safe: "\u2713", caution: "\u26A0", dangerous: "\u2717" };
    const icon = icons[item.level as keyof typeof icons] || "?";

    return (
      <View style={styles.item}>
        <View style={[styles.dot, { backgroundColor: color }]}>
          <Text style={styles.dotText}>{icon}</Text>
        </View>
        <View style={styles.itemInfo}>
          <Text style={styles.domain} numberOfLines={1}>{item.domain}</Text>
          <Text style={styles.time}>
            {new Date(item.checked_at).toLocaleString()} &middot; Score: {item.score}
          </Text>
        </View>
        <Text style={[styles.score, { color }]}>{item.score}</Text>
      </View>
    );
  };

  if (loading) {
    return <View style={styles.container}><Text style={styles.empty}>Loading...</Text></View>;
  }

  return (
    <View style={styles.container}>
      {checks.length === 0 ? (
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyIcon}>{"\u{1F6E1}"}</Text>
          <Text style={styles.emptyTitle}>No checks yet</Text>
          <Text style={styles.empty}>Links you check will appear here.{"\n"}All data stays on your device.</Text>
          <TouchableOpacity style={styles.emptyBtn} onPress={() => {}}>
            <Text style={styles.emptyBtnText}>Check Your First Link</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <FlatList
          data={checks}
          keyExtractor={(item) => item.id.toString()}
          renderItem={renderItem}
          contentContainerStyle={{ padding: spacing.md }}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={() => { setRefreshing(true); load(); }} tintColor={colors.safe} />
          }
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  emptyContainer: { flex: 1, alignItems: "center", justifyContent: "center", padding: spacing.xl },
  emptyIcon: { fontSize: 48, marginBottom: spacing.md },
  emptyTitle: { color: colors.white, fontSize: fontSize.xl, fontWeight: "700", marginBottom: spacing.sm },
  empty: { color: colors.textMuted, fontSize: fontSize.md, textAlign: "center", lineHeight: 24 },
  emptyBtn: { backgroundColor: colors.accent, paddingHorizontal: 24, paddingVertical: 14, borderRadius: 12, marginTop: spacing.lg },
  emptyBtnText: { color: colors.safeBg, fontWeight: "700", fontSize: fontSize.md },
  item: {
    flexDirection: "row", alignItems: "center", gap: spacing.md,
    backgroundColor: colors.bgCard, borderRadius: 12, padding: spacing.md,
    marginBottom: spacing.sm,
  },
  dot: {
    width: 36, height: 36, borderRadius: 18,
    alignItems: "center", justifyContent: "center",
  },
  dotText: { color: colors.white, fontSize: 16, fontWeight: "700" },
  itemInfo: { flex: 1 },
  domain: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },
  time: { color: colors.textMuted, fontSize: fontSize.xs, marginTop: 2 },
  score: { fontSize: fontSize.xl, fontWeight: "800" },
});
