/**
 * useUpdateCheck — offers a fresher build to sideloaded (Tele2 direct-APK)
 * users, and insists when the running build is below the security floor.
 *
 * Design notes:
 *  - Android only. iOS has no direct-APK funnel yet; when it launches it gets
 *    its own store-aware path, not this one.
 *  - Reads the running build's embedded version NAME (Constants.version), so
 *    no new native dependency and it works fully offline.
 *  - Persists the last server snapshot, so a known "you must update" verdict
 *    survives being offline and shows on every launch — a security floor you
 *    can dodge by turning off wifi is not a floor.
 *  - Network is throttled (once per CHECK_INTERVAL_MS); the decision itself is
 *    derived from the persisted snapshot every mount, instantly.
 *  - A network failure shows nothing. We never invent a scary "out of date".
 *  - An OPTIONAL nudge is dismissible per target version (dismiss once, we stay
 *    quiet until there's an even newer one). A REQUIRED gate is never
 *    dismissible.
 *  - A RuStore install (or the RuStore build, which checks incoming SMS) is
 *    never sent to the website APK — that would silently drop its SMS check.
 *    It is pointed at the RuStore listing when that is live, else left to
 *    RuStore's own updates (planUpdate).
 */
import { useCallback, useEffect, useState } from "react";
import { Platform } from "react-native";
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

import {
  fetchVersionInfo,
  planUpdate,
  type UpdateChannel,
  type UpdateDecision,
  type VersionInfo,
} from "../lib/update-check";
import { rustoreListingUrl } from "../config/stores";
import { RUSTORE_INSTALLER, installSource, smsAutoSupported } from "../../modules/cleanway-vpn";

const API_BASE = (
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_API_URL) ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://api.cleanway.ai"
).replace(/\/+$/, "");

const WEB_BASE = "https://cleanway.ai";
const CHECK_INTERVAL_MS = 20 * 60 * 60 * 1000; // ~daily, off launch cadence
// After a failed check (endpoint not deployed yet, offline, 5xx) wait this long
// instead of the full interval — but DO record the attempt, so a permanently
// 404ing endpoint isn't re-hit on every single cold start.
const RETRY_INTERVAL_MS = 60 * 60 * 1000;
const SNAPSHOT_KEY = "cleanway_update_snapshot";
const LAST_CHECK_KEY = "cleanway_update_last_check";
const DISMISSED_KEY = "cleanway_update_dismissed"; // the version name last dismissed

const RUNNING = Constants.expoConfig?.version ?? "0.0.0";

export interface UpdateStatus {
  decision: UpdateDecision; // "none" | "optional" | "required"
  latestVersionName: string;
  /**
   * Where "Update" leads: the server's signed APK URL, else the /android page;
   * for a RuStore install, the RuStore listing.
   */
  downloadUrl: string;
  /** The update comes from the store listing (the button says so). */
  viaStore: boolean;
  releaseNotes: string | null;
  dismiss: () => void;
}

const NONE: UpdateStatus = {
  decision: "none",
  latestVersionName: "",
  downloadUrl: `${WEB_BASE}/android`,
  viaStore: false,
  releaseNotes: null,
  dismiss: () => {},
};

/**
 * RuStore installed it, or it is the RuStore build (however it got here):
 * either way the website APK must not be offered. Read once — neither can
 * change while the app runs.
 */
function readChannel(): UpdateChannel {
  return smsAutoSupported() || installSource()?.installer === RUSTORE_INSTALLER ? "rustore" : "direct";
}

function downloadUrlFor(info: VersionInfo | null, lang: string): string {
  if (info?.apkUrl) return info.apkUrl;
  // Send RU-first users to the Russian download page; default locale is EN and
  // unprefixed under next-intl's "as-needed".
  const path = lang && lang !== "en" ? `/${lang}/android` : "/android";
  return `${WEB_BASE}${path}`;
}

/**
 * @param lang the app's current UI language (for the download-page fallback).
 */
export function useUpdateCheck(lang: string = "en"): UpdateStatus {
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [dismissedVersion, setDismissedVersion] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [channel] = useState<UpdateChannel>(readChannel);

  useEffect(() => {
    if (Platform.OS !== "android") return;
    let alive = true;

    (async () => {
      // 1. Load whatever we already know — instant, offline-safe.
      try {
        const [rawSnap, rawDismissed] = await Promise.all([
          SecureStore.getItemAsync(SNAPSHOT_KEY),
          SecureStore.getItemAsync(DISMISSED_KEY),
        ]);
        if (alive && rawSnap) setInfo(JSON.parse(rawSnap) as VersionInfo);
        if (alive && rawDismissed) setDismissedVersion(rawDismissed);
      } catch {
        // Corrupt/unavailable store → treat as no prior knowledge.
      }
      if (alive) setReady(true);

      // 2. Refresh from the network at most once per interval.
      try {
        const rawLast = await SecureStore.getItemAsync(LAST_CHECK_KEY);
        const last = rawLast ? parseInt(rawLast, 10) : 0;
        const now = Date.now();
        const elapsed = now - last;
        // `elapsed < 0` means the stored stamp is in the FUTURE — the phone's
        // clock was ahead when we last checked (common on cheap devices booting
        // without a network). Treating that as "checked recently" would disable
        // update checks forever, so a future stamp counts as stale.
        const fresh = Number.isFinite(last) && elapsed >= 0 && elapsed < CHECK_INTERVAL_MS;
        if (fresh) return;
      } catch {
        // fall through and check
      }
      const fetched = await fetchVersionInfo(API_BASE);
      if (!alive) return;
      if (!fetched) {
        // Record the failed attempt with a shorter backoff so a not-yet-deployed
        // endpoint doesn't get hit on every launch, but a transient outage still
        // resolves within the hour.
        try {
          await SecureStore.setItemAsync(
            LAST_CHECK_KEY,
            String(Date.now() - (CHECK_INTERVAL_MS - RETRY_INTERVAL_MS)),
          );
        } catch {
          // best effort
        }
        return;
      }
      setInfo(fetched);
      try {
        await SecureStore.setItemAsync(SNAPSHOT_KEY, JSON.stringify(fetched));
        await SecureStore.setItemAsync(LAST_CHECK_KEY, String(Date.now()));
      } catch {
        // Persisting is best-effort; the in-memory decision still holds.
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  const dismiss = useCallback(() => {
    if (!info) return;
    setDismissedVersion(info.latestVersionName);
    SecureStore.setItemAsync(DISMISSED_KEY, info.latestVersionName).catch(() => {});
  }, [info]);

  if (!ready || Platform.OS !== "android" || !info) return NONE;

  const plan = planUpdate(RUNNING, info, channel, downloadUrlFor(info, lang), rustoreListingUrl());
  // Required is never suppressible; an optional nudge the user already waved
  // away stays hidden until a newer version supersedes what they dismissed.
  const decision: UpdateDecision =
    plan.decision === "optional" && dismissedVersion === info.latestVersionName ? "none" : plan.decision;

  return {
    decision,
    latestVersionName: info.latestVersionName,
    downloadUrl: plan.url,
    viaStore: plan.viaStore,
    releaseNotes: info.releaseNotes,
    dismiss,
  };
}
