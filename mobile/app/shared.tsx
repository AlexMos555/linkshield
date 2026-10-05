/**
 * Shared URL screen — opens when user shares a link TO Cleanway
 * from any app (Safari, Chrome, Messages, WhatsApp, etc.), and when the link
 * guard stops a tapped link that is on the on-device list (via=guard).
 *
 * Flow:
 *   User in Safari → Share → Cleanway → instant result
 *   User in WhatsApp → long press link → Share → Cleanway → alert if dangerous
 *
 * A site on the on-device list is "Dangerous" from the first frame; the
 * server's score and reasons fill in when they arrive and never downgrade it
 * (src/hooks/useDomainCheck.ts).
 */

import { useState, useCallback } from "react";
import {
  View, Text, StyleSheet, ScrollView, ActivityIndicator, TouchableOpacity,
} from "react-native";
import { useLocalSearchParams, useRouter } from "expo-router";
import { Ionicons } from "@expo/vector-icons";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import {
  colors, type as typo, space, radius, sectionHeader,
  levelColors, levelStrokes,
} from "../src/utils/theme";
import type { ApiError } from "../src/services/api";
import { reasonLabel } from "../src/utils/reason-label";
import { openInBrowser } from "../modules/cleanway-vpn";
import { toCheckableHost } from "../src/utils/host";
import { useDomainCheck } from "../src/hooks/useDomainCheck";
import {
  isNotFound, reasonsToShow, serverLevel, showScore, shownLevel, type ServerAnswer,
} from "../src/utils/check-verdict";
import { ListedMark, NotFoundCard, ServerDetailsNote } from "../src/components/check/CheckStates";
import { useCallGuard } from "../src/components/call/CallGuardProvider";

type Level = keyof typeof levelColors;

// Status is never colour-only (design spec §6): every verdict pairs its hue
// with an icon and a written label.
const VERDICT_ICONS: Record<Level, keyof typeof Ionicons.glyphMap> = {
  safe: "shield-checkmark-outline",
  caution: "alert-circle-outline",
  dangerous: "warning-outline",
};

/** The error body for a check that failed — a slow server is not "check your connection". */
function errorBodyKey(error: ApiError["kind"] | null): string {
  if (error === "rate_limited") return "mobile.result.error_rate_limited";
  if (error === "http_5xx") return "mobile.result.error_server";
  if (error === "timeout") return "mobile.result.error_slow";
  return "mobile.shared.check_failed_body";
}

export default function SharedScreen() {

  const router = useRouter();

  // /shared is PUSHED by the share-intent router on every share, so replacing
  // the route with "/(tabs)" stacked a fresh tabs navigator EACH time — two
  // shares meant three mounted home screens, each with its own shield probe and
  // AppState listener, growing for the whole session. Go back instead.
  const leaveShared = useCallback(() => {
    if (router.canGoBack()) router.back();
    else router.replace("/(tabs)");
  }, [router]);
  const { t } = useTranslation();
  const { url, via } = useLocalSearchParams<{ url: string; via?: string }>();
  // "Open anyway" on a stopped site during or right after a phone call is
  // the scam's last step: the stop screen comes first (CallGuardProvider).
  const callGuard = useCallGuard();
  // openInBrowser returns false when Cleanway is the only browser on the
  // phone. Closing the screen anyway made "Open anyway" a silent no-op.
  const [noBrowser, setNoBrowser] = useState(false);

  // One shared parser — see src/utils/host.ts for why the old split("/")
  // version leaked query strings and never punycoded IDN hosts. It returns
  // null for junk, which is what finally makes the "No link found" screen
  // below reachable.
  const domain = toCheckableHost(url || "");

  // A link-guard hand-off is not a check the person made: the guard already
  // recorded the stop in the block log (History, "Blocked"). Saving it here
  // too counted every stopped link twice.
  const { listed, result, error, pending, retry } = useDomainCheck(domain, via !== "guard");

  if (!domain) {
    return (
      <CenteredMessage
        icon="link-outline"
        title={t("mobile.shared.no_url_title")}
        body={t("mobile.shared.no_url_body")}
        action={t("mobile.shared.go_home")}
        onAction={leaveShared}
      />
    );
  }

  // Waiting — but never for the server when the list already knows the site.
  if (listed === undefined || (!listed && pending)) {
    return (
      <View style={s.center}>
        <ActivityIndicator size="large" color={colors.blue} />
        <Text style={s.centerTitle}>{t("mobile.result.loading", { domain })}</Text>
        <Text style={s.centerSub}>{t("mobile.result.loading_sub")}</Text>
      </View>
    );
  }

  if (!listed && isNotFound(result)) {
    return (
      <ScrollView style={s.container} contentContainerStyle={s.content}>
        <Text style={s.eyebrow}>{t("mobile.shared.eyebrow")}</Text>
        <NotFoundCard domain={domain} />
        <DoneButton label={t("mobile.shared.done")} onPress={leaveShared} />
      </ScrollView>
    );
  }

  const level = shownLevel(listed, result);
  if (!level) {
    return (
      <CenteredMessage
        icon="cloud-offline-outline"
        title={t("mobile.result.error_title")}
        body={t(errorBodyKey(error))}
        action={t("mobile.shared.go_home")}
        onAction={leaveShared}
      />
    );
  }

  const color = levelColors[level];
  const label = listed ? t("mobile.result.listed_title") : t(`mobile.result.verdict_${level}`);
  const score = showScore(listed, result) ? result?.score : undefined;
  const reasons = signalLines(listed, result, t);
  const shown = reasons.slice(0, 3);
  const hidden = reasons.length - shown.length;
  const safe = level === "safe";

  return (
    <ScrollView style={s.container} contentContainerStyle={s.content}>
      <Text style={s.eyebrow}>{t("mobile.shared.eyebrow")}</Text>

      <View
        style={[s.verdictCard, { borderColor: levelStrokes[level] }]}
        accessibilityRole="summary"
        accessibilityLabel={
          score === undefined
            ? `${label}. ${domain}`
            : t("mobile.shared.a11y_verdict", { verdict: label, domain, score })
        }
      >
        {score === undefined ? (
          <ListedMark size={104} />
        ) : (
          <>
            <View style={[s.ring, { borderColor: color + "66" }]}>
              <Text style={[s.ringScore, { color }]}>{score}</Text>
              <Text style={s.ringMax}>/100</Text>
            </View>
            <Text style={s.scoreCaption}>{t("mobile.shared.score_caption")}</Text>
          </>
        )}

        <View style={s.verdictRow}>
          <Ionicons name={VERDICT_ICONS[level]} size={22} color={color} />
          <Text style={[s.verdictLabel, { color }]}>{label}</Text>
        </View>
        <Text style={s.domain}>{result?.domain ?? domain}</Text>
        <Text style={s.advice}>{t(`mobile.shared.advice_${level}`)}</Text>
        {!listed && result?.confidence === "low" && (
          <Text style={s.lowConf}>{t("mobile.result.low_confidence")}</Text>
        )}
        {listed && (
          <ServerDetailsNote
            pending={pending}
            failed={!pending && !result}
            calm={!!result && serverLevel(result) === "safe"}
            onRetry={retry}
          />
        )}
      </View>

      {shown.length > 0 && (
        <View style={s.card}>
          <Text style={s.cardTitle}>{t("mobile.result.signals")}</Text>
          {shown.map((line, i) => (
            <View key={i} style={[s.signalRow, i > 0 && s.signalBorder]}>
              <View style={[s.signalDot, { backgroundColor: color }]} />
              <Text style={s.signalText}>{line}</Text>
            </View>
          ))}
          {hidden > 0 && (
            <Text style={s.moreSignals}>{t("mobile.shared.more_signals", { n: hidden })}</Text>
          )}
        </View>
      )}

      {via === "guard" && url && (
        // Reached here by tapping a link (link guard), not by pasting. Let the
        // person continue to the real browser — muted "open anyway" when the
        // verdict is not safe, so it never nudges them toward a scam.
        <TouchableOpacity
          style={safe ? s.primaryBtn : s.secondaryBtn}
          onPress={() => {
            const open = () => {
              if (openInBrowser(url)) leaveShared();
              else setNoBrowser(true);
            };
            if (safe) open();
            else callGuard.guard("open_anyway", open);
          }}
          activeOpacity={0.85}
          accessibilityRole="button"
        >
          <Text style={safe ? s.primaryLabel : s.secondaryLabel}>
            {t(safe ? "mobile.shared.open_in_browser" : "mobile.shared.open_anyway")}
          </Text>
        </TouchableOpacity>
      )}

      {noBrowser && (
        <Text style={s.noBrowserNote}>{t("mobile.shared.no_browser")}</Text>
      )}

      <TouchableOpacity
        style={via === "guard" && safe ? s.secondaryBtn : s.primaryBtn}
        onPress={() => router.push({
          pathname: "/result",
          params: via === "guard" ? { domain, from: "guard" } : { domain },
        })}
        activeOpacity={0.85}
        accessibilityRole="button"
      >
        <Text style={via === "guard" && safe ? s.secondaryLabel : s.primaryLabel}>{t("mobile.shared.full_details")}</Text>
      </TouchableOpacity>

      <DoneButton label={t("mobile.shared.done")} onPress={leaveShared} />

      <View style={s.privacyRow}>
        <Ionicons name="lock-closed-outline" size={13} color={colors.textMuted} />
        {/* "Checked on our servers" only once the server has answered — a
            listed site's verdict is the phone's own until then. */}
        <Text style={s.privacy}>{t(result ? "mobile.result.privacy" : "mobile.result.privacy_listed")}</Text>
      </View>
    </ScrollView>
  );
}

/** The "why" lines: the list's own line first when it decided, then the server's. */
function signalLines(
  listed: string | null,
  result: ServerAnswer | null,
  t: TFunction,
): string[] {
  const server = reasonsToShow(listed, result).map((r) => reasonLabel(r, t));
  return listed ? [t("mobile.result.listed_reason"), ...server] : server;
}

function DoneButton({ label, onPress }: { label: string; onPress: () => void }) {
  return (
    <TouchableOpacity style={s.secondaryBtn} onPress={onPress} activeOpacity={0.85} accessibilityRole="button">
      <Text style={s.secondaryLabel}>{label}</Text>
    </TouchableOpacity>
  );
}

interface CenteredMessageProps {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  body: string;
  action: string;
  onAction: () => void;
}

function CenteredMessage({ icon, title, body, action, onAction }: CenteredMessageProps) {
  return (
    <View style={s.center}>
      <Ionicons name={icon} size={44} color={colors.amber} />
      <Text style={s.centerTitle}>{title}</Text>
      <Text style={s.centerBody}>{body}</Text>
      <TouchableOpacity style={s.primaryBtn} onPress={onAction} activeOpacity={0.85} accessibilityRole="button">
        <Text style={s.primaryLabel}>{action}</Text>
      </TouchableOpacity>
    </View>
  );
}



const s = StyleSheet.create({
  noBrowserNote: {
    color: colors.caution,
    fontSize: 14,
    textAlign: "center",
    marginTop: 10,
    paddingHorizontal: 16,
  },
  container: { flex: 1, backgroundColor: colors.bg },
  content: { paddingHorizontal: space.xl, paddingTop: space.sm, paddingBottom: 100 },
  center: {
    flex: 1, alignItems: "center", justifyContent: "center",
    backgroundColor: colors.bg, paddingHorizontal: space.xl, paddingBottom: 100,
  },
  centerTitle: { ...typo.headline, color: colors.textPrimary, marginTop: space.md, textAlign: "center" },
  centerSub: { ...typo.caption, color: colors.textMuted, marginTop: space.xs },
  centerBody: { ...typo.body, color: colors.textSecondary, textAlign: "center", marginTop: space.sm },

  eyebrow: { ...sectionHeader, marginBottom: space.sm },

  verdictCard: {
    backgroundColor: colors.surface, borderWidth: 1,
    borderRadius: radius.card, padding: space.lg,
    alignItems: "center", marginBottom: space.md,
  },
  ring: {
    width: 104, height: 104, borderRadius: radius.full, borderWidth: 8,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  ringScore: { ...typo.display },
  ringMax: { ...typo.caption, color: colors.textMuted, marginTop: -2 },
  scoreCaption: { ...typo.caption, color: colors.textMuted, marginTop: space.sm, textAlign: "center" },
  verdictRow: { flexDirection: "row", alignItems: "center", gap: space.sm, marginTop: space.lg },
  verdictLabel: { ...typo.title2 },
  domain: { ...typo.body, color: colors.textSecondary, marginTop: space.xs },
  advice: { ...typo.body, color: colors.textPrimary, textAlign: "center", marginTop: space.md },
  lowConf: { ...typo.caption, color: colors.amber, textAlign: "center", marginTop: space.sm },

  card: {
    backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.stroke,
    borderRadius: radius.card, padding: space.lg, marginBottom: space.md,
  },
  cardTitle: { ...typo.headline, color: colors.textPrimary, marginBottom: space.sm },
  signalRow: { flexDirection: "row", alignItems: "center", gap: space.sm, paddingVertical: 8 },
  signalBorder: { borderTopWidth: 1, borderTopColor: colors.hairline },
  signalDot: { width: 6, height: 6, borderRadius: 3 },
  signalText: { ...typo.body, color: colors.textSecondary, flex: 1 },
  moreSignals: { ...typo.caption, color: colors.textMuted, marginTop: space.sm },

  primaryBtn: {
    height: 50, backgroundColor: colors.blue, borderRadius: radius.control,
    paddingHorizontal: space.xxl,
    alignItems: "center", justifyContent: "center", marginTop: space.sm,
  },
  primaryLabel: { fontSize: 17, fontWeight: "600", color: "#FFFFFF" },
  secondaryBtn: {
    height: 50, backgroundColor: colors.surface,
    borderWidth: 1, borderColor: colors.stroke, borderRadius: radius.control,
    alignItems: "center", justifyContent: "center", marginTop: space.sm, marginBottom: space.lg,
  },
  secondaryLabel: { fontSize: 15, fontWeight: "600", color: colors.textPrimary },

  privacyRow: {
    flexDirection: "row", alignItems: "flex-start", justifyContent: "center",
    gap: 6, paddingHorizontal: space.md,
  },
  privacy: { ...typo.caption, color: colors.textMuted, textAlign: "center", flexShrink: 1 },
});
