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
import { useTranslation } from "react-i18next";

import { colors, spacing, fontSize } from "../src/utils/theme";
// Session comes from services/auth — the store the sign-in screen actually
// writes to. This screen used to ask the Supabase SDK (lib/supabase-client),
// a parallel store that never saw the sign-in: the user signed in, came here,
// was told to sign in, signed in again... forever. One session store now.
import { restoreSession } from "../src/services/auth";
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
  // A failed request is its own state. It used to collapse into "noFamily",
  // which invited the worst possible recovery: a user with a flaky connection
  // saw "create a family", tapped it, and split their household in two.
  | { kind: "error" }
  | { kind: "noFamily" }
  | {
      kind: "active";
      family: MyFamily;
      /** null = the member list request failed (NOT an empty family). */
      members: FamilyMemberRow[] | null;
      /** null = the alerts request failed (NOT "no alerts yet"). */
      alerts: Array<AlertPayload & { _id: string; _at: string | null }> | null;
      /** Envelopes that arrived but could not be decrypted on this device. */
      undecryptable: number;
    };

export default function FamilyScreen() {
  const router = useRouter();
  const { t } = useTranslation();
  const [screen, setScreen] = useState<Screen>({ kind: "loading" });
  const [joinOpen, setJoinOpen] = useState(false);
  const [joinCode, setJoinCode] = useState("");
  const [joinPin, setJoinPin] = useState("");
  const [joinError, setJoinError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Invite modal — code+PIN shown ONCE after generation
  const [invite, setInvite] = useState<InviteCreateResponse | null>(null);

  const refresh = useCallback(async () => {
    const session = await restoreSession();
    if (!session) {
      setScreen({ kind: "signedOut" });
      return;
    }
    const token = session.accessToken;

    const mine = await listMyFamilies(token);
    // null means the request FAILED — offline, 5xx, timeout. Only a successful
    // response with zero families means the user has no family.
    if (!mine) {
      setScreen({ kind: "error" });
      return;
    }
    if (mine.families.length === 0) {
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

    // A failed member list stays null — the UI falls back to the count the
    // families response already carried, instead of asserting "0 members".
    const membersResp = await listMembers(token, family.family_id);
    const members = membersResp ? membersResp.members : null;

    // Decrypt alerts client-side. An envelope that will not open on this
    // device is counted, not dropped: "2 alerts could not be read" and
    // "no alerts yet" are different facts, and hiding the first behind the
    // second would mask a broken keypair forever.
    const alertsResp = await listAlerts(token, family.family_id);
    let alerts: Array<AlertPayload & { _id: string; _at: string | null }> | null = null;
    let undecryptable = 0;
    if (alertsResp) {
      const decoded: Array<AlertPayload & { _id: string; _at: string | null }> = [];
      for (const env of alertsResp.alerts) {
        if (!env.ciphertext_b64 || !env.nonce_b64 || !env.sender_pubkey_b64) {
          undecryptable += 1;
          continue;
        }
        const opened = kp
          ? decryptForMe(
              {
                ciphertext_b64: env.ciphertext_b64,
                nonce_b64: env.nonce_b64,
                sender_pubkey_b64: env.sender_pubkey_b64,
              },
              kp.secretKeyB64,
            )
          : null;
        if (opened) decoded.push({ ...opened, _id: env.id, _at: env.created_at });
        else undecryptable += 1;
      }
      alerts = decoded;
    }

    setScreen({ kind: "active", family, members, alerts, undecryptable });
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const token = async (): Promise<string | null> =>
    (await restoreSession())?.accessToken ?? null;

  const handleCreate = async () => {
    setBusy(true);
    try {
      const tk = await token();
      if (!tk) return;
      const created = await createFamily(tk, t("mobile.family.default_name"));
      if (!created) {
        Alert.alert(t("mobile.family.create_failed_title"), t("mobile.family.try_again"));
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
      setJoinError(t("mobile.family.join_validation"));
      return;
    }
    setBusy(true);
    try {
      const tk = await token();
      if (!tk) return;
      const joined = await acceptInvite(tk, joinCode.trim(), joinPin.trim());
      if (!joined) {
        setJoinError(t("mobile.family.join_invalid"));
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
      const tk = await token();
      if (!tk) return;
      const res = await createInvite(tk, screen.family.family_id);
      if (!res) {
        Alert.alert(t("mobile.family.invite_failed_title"), t("mobile.family.try_again"));
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
      `${t("mobile.family.invite_copy_header")}\n${t("mobile.family.code_label")}: ${invite.code}\n${t("mobile.family.pin_label")}: ${invite.pin}`,
    );
    Alert.alert(t("mobile.family.copied_title"), t("mobile.family.copied_body"));
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
        <Text style={styles.h1}>{t("mobile.family.title")}</Text>
        <Text style={styles.sub}>{t("mobile.family.signed_out_body")}</Text>
        <TouchableOpacity style={styles.btnPrimary} onPress={() => router.push("/auth")}>
          <Text style={styles.btnPrimaryText}>{t("mobile.family.sign_in")}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (screen.kind === "error") {
    return (
      <View style={[styles.container, styles.center]}>
        <Text style={styles.h1}>{t("mobile.family.title")}</Text>
        <Text style={styles.sub}>{t("mobile.family.load_failed_body")}</Text>
        <TouchableOpacity
          style={styles.btnPrimary}
          onPress={() => {
            setScreen({ kind: "loading" });
            void refresh();
          }}
        >
          <Text style={styles.btnPrimaryText}>{t("mobile.family.retry")}</Text>
        </TouchableOpacity>
      </View>
    );
  }

  if (screen.kind === "noFamily") {
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <Text style={styles.h1}>{t("mobile.family.title")}</Text>
        <Text style={styles.sub}>{t("mobile.family.no_family_body")}</Text>

        <View style={styles.row}>
          <TouchableOpacity
            style={styles.btnPrimary}
            disabled={busy}
            onPress={handleCreate}
          >
            <Text style={styles.btnPrimaryText}>
              {busy ? t("mobile.family.creating") : t("mobile.family.create")}
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={styles.btnGhost}
            onPress={() => setJoinOpen(true)}
          >
            <Text style={styles.btnGhostText}>{t("mobile.family.join_with_code")}</Text>
          </TouchableOpacity>
        </View>

        {joinOpen && (
          <View style={styles.joinForm}>
            <Text style={styles.label}>{t("mobile.family.code_label")}</Text>
            <TextInput
              style={styles.input}
              value={joinCode}
              onChangeText={setJoinCode}
              // Invite codes come from secrets.token_urlsafe() and the backend
              // hashes them without case normalization, so they are
              // CASE-SENSITIVE. autoCapitalize="characters" silently
              // uppercased whatever the user typed — every hand-typed code
              // failed with "invalid or expired", and only paste worked.
              autoCapitalize="none"
              autoCorrect={false}
              placeholder="aB3xY9…"
              placeholderTextColor={colors.textMuted}
            />
            <Text style={styles.label}>{t("mobile.family.pin_label")}</Text>
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
              <Text style={styles.btnPrimaryText}>
                {busy ? t("mobile.family.joining") : t("mobile.family.join")}
              </Text>
            </TouchableOpacity>
          </View>
        )}
      </ScrollView>
    );
  }

  // Active family
  const { family, members, alerts, undecryptable } = screen;
  const isOwner = family.role === "owner";
  // When the member list failed to load, fall back to the count the families
  // response already carried instead of asserting zero.
  const memberCount = members ? members.length : family.member_count;
  const roleLabel = t(
    isOwner ? "mobile.family.role_owner" : "mobile.family.role_member",
  );

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.h1}>{family.name}</Text>
      <Text style={styles.sub}>
        {t("mobile.family.members_count", { n: memberCount })} ·{" "}
        <Text style={{ color: isOwner ? colors.safe : colors.textSecondary }}>
          {roleLabel}
        </Text>
      </Text>

      {/* Members */}
      <Text style={styles.sectionTitle}>{t("mobile.family.members_title")}</Text>
      <View style={styles.card}>
        {members === null ? (
          <Text style={styles.cardDesc}>{t("mobile.family.members_load_failed")}</Text>
        ) : (
          members.map((m) => (
            <View key={m.user_id} style={styles.memberRow}>
              <View
                style={[
                  styles.memberDot,
                  { backgroundColor: m.public_key_b64 ? colors.safe : colors.textMuted },
                ]}
              />
              <Text style={styles.memberId}>
                {m.user_id.slice(0, 8)}… ({m.role === "owner" ? t("mobile.family.role_owner") : t("mobile.family.role_member")})
              </Text>
              {!m.public_key_b64 && (
                <Text style={styles.memberPending}>{t("mobile.family.no_key_yet")}</Text>
              )}
            </View>
          ))
        )}
      </View>

      {/* Owner-only: invite */}
      {isOwner && (
        <>
          <Text style={styles.sectionTitle}>{t("mobile.family.invite_title")}</Text>
          <View style={styles.card}>
            {/* Copy no longer offers "scan in person" — no QR is generated
                anywhere and the scanner cannot read invites. */}
            <Text style={styles.cardDesc}>{t("mobile.family.invite_desc")}</Text>
            <TouchableOpacity
              style={[styles.btnPrimary, { marginTop: spacing.md }]}
              disabled={busy}
              onPress={handleInvite}
            >
              <Text style={styles.btnPrimaryText}>
                {busy ? t("mobile.family.generating") : t("mobile.family.generate_invite")}
              </Text>
            </TouchableOpacity>
          </View>
        </>
      )}

      {/* Alerts. Three different facts, three different sentences: the
          request failed / nothing arrived / N arrived but won't open here. */}
      <Text style={styles.sectionTitle}>{t("mobile.family.alerts_title")}</Text>
      {alerts === null ? (
        <View style={styles.card}>
          <Text style={styles.cardDesc}>{t("mobile.family.alerts_load_failed")}</Text>
        </View>
      ) : (
        <>
          {alerts.length === 0 && (
            <View style={styles.card}>
              <Text style={styles.cardDesc}>{t("mobile.family.alerts_empty")}</Text>
            </View>
          )}
          {alerts.map((a) => (
            <View key={a._id} style={styles.alertRow}>
              <Text style={styles.alertDomain}>
                {a.domain || t("mobile.family.unknown_domain")}
              </Text>
              <Text style={styles.alertMeta}>
                {a.level || t("mobile.family.level_blocked")} ·{" "}
                {a._at ? new Date(a._at).toLocaleString() : ""}
              </Text>
            </View>
          ))}
          {undecryptable > 0 && (
            <View style={styles.card}>
              <Text style={styles.cardDesc}>
                {t("mobile.family.alerts_undecryptable", { n: undecryptable })}
              </Text>
            </View>
          )}
        </>
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
            <Text style={styles.modalTitle}>{t("mobile.family.modal_title")}</Text>
            <Text style={styles.modalDesc}>{t("mobile.family.modal_desc")}</Text>
            <View style={styles.codeBox}>
              <Text style={styles.codeLabel}>{t("mobile.family.code_label")}</Text>
              <Text style={styles.codeValue}>{invite?.code ?? ""}</Text>
            </View>
            <View style={styles.codeBox}>
              <Text style={styles.codeLabel}>{t("mobile.family.pin_label")}</Text>
              <Text style={styles.pinValue}>{invite?.pin ?? ""}</Text>
            </View>
            <View style={[styles.row, { marginTop: spacing.md }]}>
              <TouchableOpacity style={styles.btnGhost} onPress={handleCopyInvite}>
                <Text style={styles.btnGhostText}>{t("mobile.family.copy_both")}</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.btnPrimary}
                onPress={() => setInvite(null)}
              >
                <Text style={styles.btnPrimaryText}>{t("mobile.family.done")}</Text>
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
