/**
 * Family Hub screen — mobile mirror of the extension's options-page
 * Family section. Single-file state machine: loading / signed-out /
 * no-family / active (with owner-only invite controls).
 *
 * Crypto + REST live in mobile/src/lib/family-{crypto,api}.ts.
 * Auth resolves via mobile/src/lib/supabase-client.ts (Expo SecureStore-
 * backed Supabase SDK session).
 */
import { useCallback, useEffect, useState } from "react";
import {
  View, Text, StyleSheet, ScrollView, TextInput, TouchableOpacity,
  Modal, Pressable, ActivityIndicator, Alert,
} from "react-native";
import * as Clipboard from "expo-clipboard";
import { useRouter } from "expo-router";

import { colors, spacing, fontSize } from "../src/utils/theme";
import { getSupabaseSDK, getAccessToken } from "../src/lib/supabase-client";
import {
  getOrCreateKeypair,
  decryptForMe,
  type AlertPayload,
} from "../src/lib/family-crypto";
import {
  listMyFamilies,
  createFamily,
  registerMyKey,
  listMembers,
  createInvite,
  acceptInvite,
  listAlerts,
  type MyFamily,
  type FamilyMemberRow,
  type InviteCreateResponse,
} from "../src/lib/family-api";

type Screen =
  | { kind: "loading" }
  | { kind: "signedOut" }
  | { kind: "noFamily" }
  | {
      kind: "active";
      family: MyFamily;
      members: FamilyMemberRow[];
      alerts: Array<AlertPayload & { _id: string; _at: string | null }>;
    };

export default function FamilyScreen() {
  const router = useRouter();
  const [screen, setScreen] = useState<Screen>({ kind: "loading" });
  const [joinOpen, setJoinOpen] = useState(false);
  const [joinCode, setJoinCode] = useState("");
  const [joinPin, setJoinPin] = useState("");
  const [joinError, setJoinError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Invite modal — code+PIN shown ONCE after generation
  const [invite, setInvite] = useState<InviteCreateResponse | null>(null);

  const refresh = useCallback(async () => {
    const sdk = getSupabaseSDK();
    if (!sdk) {
      setScreen({ kind: "signedOut" });
      return;
    }
    const token = await getAccessToken();
    if (!token) {
      setScreen({ kind: "signedOut" });
      return;
    }

    const mine = await listMyFamilies(token);
    if (!mine || mine.families.length === 0) {
      setScreen({ kind: "noFamily" });
      return;
    }

    // Single-family UX in v1; first family wins.
    const family = mine.families[0];

    // Make sure my keypair is registered server-side. Idempotent.
    const kp = await getOrCreateKeypair();
    if (kp) {
      await registerMyKey(token, family.family_id, kp.publicKeyB64);
    }

    const membersResp = await listMembers(token, family.family_id);
    const members = membersResp?.members ?? [];

    // Decrypt alerts client-side. Failures dropped silently.
    const alertsResp = await listAlerts(token, family.family_id);
    const decoded: Array<AlertPayload & { _id: string; _at: string | null }> = [];
    if (alertsResp && kp) {
      for (const env of alertsResp.alerts) {
        if (!env.ciphertext_b64 || !env.nonce_b64 || !env.sender_pubkey_b64) continue;
        const opened = decryptForMe(
          {
            ciphertext_b64: env.ciphertext_b64,
            nonce_b64: env.nonce_b64,
            sender_pubkey_b64: env.sender_pubkey_b64,
          },
          kp.secretKeyB64,
        );
        if (opened) decoded.push({ ...opened, _id: env.id, _at: env.created_at });
      }
    }

    setScreen({ kind: "active", family, members, alerts: decoded });
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleCreate = async () => {
    setBusy(true);
    try {
      const token = await getAccessToken();
      if (!token) return;
      const created = await createFamily(token, "My Family");
      if (!created) {
        Alert.alert("Couldn't create family", "Try again in a moment.");
        return;
      }
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const handleAccept = async () => {
    setJoinError(null);
    if (!joinCode.trim() || !/^\d{4}$/.test(joinPin.trim())) {
      setJoinError("Enter a code and 4-digit PIN.");
      return;
    }
    setBusy(true);
    try {
      const token = await getAccessToken();
      if (!token) return;
      const joined = await acceptInvite(token, joinCode.trim(), joinPin.trim());
      if (!joined) {
        setJoinError("Invalid or expired invite.");
        return;
      }
      setJoinOpen(false);
      setJoinCode("");
      setJoinPin("");
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const handleInvite = async () => {
    if (screen.kind !== "active") return;
    setBusy(true);
    try {
      const token = await getAccessToken();
      if (!token) return;
      const res = await createInvite(token, screen.family.family_id);
      if (!res) {
        Alert.alert("Couldn't create invite", "Try again in a moment.");
        return;
      }
      setInvite(res);
    } finally {
      setBusy(false);
    }
  };

  const handleCopyInvite = async () => {
    if (!invite) return;
    await Clipboard.setStringAsync(
      `Cleanway Family invite\nCode: ${invite.code}\nPIN: ${invite.pin}`,
    );
    Alert.alert("Copied", "Invite copied to clipboard.");
  };

  // ─── Render branches ────────────────────────────────────────────

  if (screen.kind === "loading") {
    return (
      <View style={[styles.container, styles.center]}>
        <ActivityIndicator color={colors.safe} />
      </View>
    );
  }

  if (screen.kind === "signedOut") {
    return (
      <View style={[styles.container, styles.center]}>
        <Text style={styles.h1}>Family Hub</Text>
        <Text style={styles.sub}>
          Sign in to set up Family Hub. End-to-end encrypted alerts when
          loved ones are blocked from a scam.
        </Text>
        <TouchableOpacity style={styles.btnPrimary} onPress={() => router.push("/auth")}>
          <Text style={styles.btnPrimaryText}>Sign in</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (screen.kind === "noFamily") {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <Text style={styles.h1}>Family Hub</Text>
        <Text style={styles.sub}>
          Get notified when scams are blocked on your loved ones&apos; devices.
          End-to-end encrypted — even Cleanway can&apos;t read the alerts.
        </Text>

        <View style={styles.row}>
          <TouchableOpacity
            style={styles.btnPrimary}
            disabled={busy}
            onPress={handleCreate}
          >
            <Text style={styles.btnPrimaryText}>{busy ? "Creating…" : "Create family"}</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.btnGhost}
            onPress={() => setJoinOpen(true)}
          >
            <Text style={styles.btnGhostText}>Join with code</Text>
          </TouchableOpacity>
        </View>

        {joinOpen && (
          <View style={styles.joinForm}>
            <Text style={styles.label}>Code</Text>
            <TextInput
              style={styles.input}
              value={joinCode}
              onChangeText={setJoinCode}
              autoCapitalize="characters"
              autoCorrect={false}
              placeholder="ABC123"
              placeholderTextColor={colors.textMuted}
            />
            <Text style={styles.label}>PIN</Text>
            <TextInput
              style={styles.input}
              value={joinPin}
              onChangeText={setJoinPin}
              keyboardType="number-pad"
              maxLength={4}
              placeholder="••••"
              placeholderTextColor={colors.textMuted}
            />
            {joinError && <Text style={styles.error}>{joinError}</Text>}
            <TouchableOpacity
              style={[styles.btnPrimary, { marginTop: spacing.md }]}
              disabled={busy}
              onPress={handleAccept}
            >
              <Text style={styles.btnPrimaryText}>{busy ? "Joining…" : "Join"}</Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>
    );
  }

  // Active family
  const { family, members, alerts } = screen;
  const isOwner = family.role === "owner";

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.h1}>{family.name}</Text>
      <Text style={styles.sub}>
        {members.length} {members.length === 1 ? "member" : "members"} ·{" "}
        <Text style={{ color: isOwner ? colors.safe : colors.textSecondary }}>
          {family.role}
        </Text>
      </Text>

      {/* Members */}
      <Text style={styles.sectionTitle}>Members</Text>
      <View style={styles.card}>
        {members.map((m) => (
          <View key={m.user_id} style={styles.memberRow}>
            <View
              style={[
                styles.memberDot,
                { backgroundColor: m.public_key_b64 ? colors.safe : colors.textMuted },
              ]}
            />
            <Text style={styles.memberId}>
              {m.user_id.slice(0, 8)}… ({m.role})
            </Text>
            {!m.public_key_b64 && <Text style={styles.memberPending}>no key yet</Text>}
          </View>
        ))}
      </View>

      {/* Owner-only: invite */}
      {isOwner && (
        <>
          <Text style={styles.sectionTitle}>Invite a family member</Text>
          <View style={styles.card}>
            <Text style={styles.cardDesc}>
              Generates a one-time code + PIN. Send by text, share on the spot,
              or scan in person. Both values appear once — keep them somewhere
              the recipient can read.
            </Text>
            <TouchableOpacity
              style={[styles.btnPrimary, { marginTop: spacing.md }]}
              disabled={busy}
              onPress={handleInvite}
            >
              <Text style={styles.btnPrimaryText}>
                {busy ? "Generating…" : "Generate invite"}
              </Text>
            </TouchableOpacity>
          </View>
        </>
      )}

      {/* Alerts */}
      <Text style={styles.sectionTitle}>Recent alerts</Text>
      {alerts.length === 0 ? (
        <View style={styles.card}>
          <Text style={styles.cardDesc}>
            No alerts yet — you&apos;ll see family blocks here as they happen.
          </Text>
        </View>
      ) : (
        alerts.map((a) => (
          <View key={a._id} style={styles.alertRow}>
            <Text style={styles.alertDomain}>{a.domain || "(unknown domain)"}</Text>
            <Text style={styles.alertMeta}>
              {a.level || "blocked"} ·{" "}
              {a._at ? new Date(a._at).toLocaleString() : ""}
            </Text>
          </View>
        ))
      )}

      {/* Invite modal */}
      <Modal
        visible={!!invite}
        transparent
        animationType="fade"
        onRequestClose={() => setInvite(null)}
      >
        <Pressable
          style={styles.modalBackdrop}
          onPress={() => setInvite(null)}
        >
          <Pressable
            style={styles.modalCard}
            onPress={(e) => e.stopPropagation()}
          >
            <Text style={styles.modalTitle}>Share this with your family member</Text>
            <Text style={styles.modalDesc}>
              Both values appear once. After this dialog closes, you can&apos;t
              see them again — generate another invite if needed.
            </Text>
            <View style={styles.codeBox}>
              <Text style={styles.codeLabel}>Code</Text>
              <Text style={styles.codeValue}>{invite?.code ?? ""}</Text>
            </View>
            <View style={styles.codeBox}>
              <Text style={styles.codeLabel}>PIN</Text>
              <Text style={styles.pinValue}>{invite?.pin ?? ""}</Text>
            </View>
            <View style={[styles.row, { marginTop: spacing.md }]}>
              <TouchableOpacity style={styles.btnGhost} onPress={handleCopyInvite}>
                <Text style={styles.btnGhostText}>Copy both</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.btnPrimary}
                onPress={() => setInvite(null)}
              >
                <Text style={styles.btnPrimaryText}>Done</Text>
              </TouchableOpacity>
            </View>
          </Pressable>
        </Pressable>
      </Modal>
    </ScrollView>
  );
}

// ─── Styles ────────────────────────────────────────────────────────

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  content: { padding: spacing.lg, paddingBottom: spacing.xxl },
  center: { justifyContent: "center", alignItems: "center", padding: spacing.lg },

  h1: { color: colors.white, fontSize: fontSize.xxl, fontWeight: "800", marginBottom: spacing.sm },
  sub: { color: colors.textSecondary, fontSize: fontSize.md, lineHeight: 22, marginBottom: spacing.lg },

  sectionTitle: {
    color: colors.textMuted,
    fontSize: fontSize.sm,
    fontWeight: "700",
    textTransform: "uppercase",
    letterSpacing: 0.5,
    marginTop: spacing.lg,
    marginBottom: spacing.sm,
  },

  card: {
    backgroundColor: colors.bgCard,
    borderRadius: 12,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
  },
  cardDesc: { color: colors.textSecondary, fontSize: fontSize.sm, lineHeight: 20 },

  row: { flexDirection: "row", gap: spacing.sm, marginTop: spacing.sm },
  btnPrimary: {
    flex: 1,
    backgroundColor: colors.safe,
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.lg,
    borderRadius: 10,
    alignItems: "center",
  },
  btnPrimaryText: { color: colors.safeBg, fontSize: fontSize.md, fontWeight: "700" },
  btnGhost: {
    flex: 1,
    backgroundColor: colors.bgCard,
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.lg,
    borderRadius: 10,
    alignItems: "center",
    borderWidth: 1,
    borderColor: colors.border,
  },
  btnGhostText: { color: colors.text, fontSize: fontSize.md, fontWeight: "600" },

  joinForm: {
    marginTop: spacing.md,
    padding: spacing.md,
    backgroundColor: colors.bgCard,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: colors.border,
  },
  label: { color: colors.textSecondary, fontSize: fontSize.sm, fontWeight: "600", marginBottom: spacing.xs, marginTop: spacing.sm },
  input: {
    backgroundColor: colors.bgInput,
    color: colors.text,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 8,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    fontSize: fontSize.md,
  },
  error: { color: colors.dangerous, fontSize: fontSize.sm, marginTop: spacing.sm },

  memberRow: { flexDirection: "row", alignItems: "center", paddingVertical: spacing.sm, gap: spacing.sm },
  memberDot: { width: 8, height: 8, borderRadius: 4 },
  memberId: { color: colors.text, fontSize: fontSize.md, flex: 1 },
  memberPending: { color: colors.caution, fontSize: fontSize.xs },

  alertRow: {
    backgroundColor: colors.bgCard,
    borderRadius: 8,
    padding: spacing.md,
    borderWidth: 1,
    borderColor: colors.border,
    marginBottom: spacing.sm,
  },
  alertDomain: { color: colors.white, fontWeight: "600", fontSize: fontSize.md },
  alertMeta: { color: colors.textMuted, fontSize: fontSize.xs, marginTop: 2 },

  modalBackdrop: {
    flex: 1,
    backgroundColor: "rgba(15, 23, 42, 0.85)",
    justifyContent: "center",
    alignItems: "center",
    padding: spacing.lg,
  },
  modalCard: {
    width: "100%",
    maxWidth: 420,
    backgroundColor: colors.bgCard,
    borderRadius: 16,
    padding: spacing.lg,
    borderWidth: 1,
    borderColor: colors.safe + "40",
  },
  modalTitle: { color: colors.white, fontSize: fontSize.lg, fontWeight: "700", marginBottom: spacing.sm },
  modalDesc: { color: colors.textSecondary, fontSize: fontSize.sm, lineHeight: 20, marginBottom: spacing.md },
  codeBox: { backgroundColor: colors.bgInput, borderRadius: 8, padding: spacing.md, marginBottom: spacing.sm },
  codeLabel: { color: colors.textMuted, fontSize: fontSize.xs, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 },
  codeValue: { color: colors.safe, fontSize: fontSize.lg, fontWeight: "700", letterSpacing: 1, fontFamily: "Courier" },
  pinValue: {
    color: colors.safe,
    fontSize: fontSize.xxl,
    fontWeight: "700",
    letterSpacing: 8,
    textAlign: "center",
    fontFamily: "Courier",
  },
});
