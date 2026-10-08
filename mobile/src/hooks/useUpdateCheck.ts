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
 *  - The same answer carries the server's switches for the on-phone checks
 *    (src/lib/remote-config.ts — the SMS text model's kill switch). They go
 *    straight to the native module, which keeps them for the Kotlin message
 *    check; an answer without them leaves the stored ones in force.
 *  - Asked on app start and, while the app stays open, about daily when it
 *    returns to the foreground — never more than once an hour (refreshDue),
 *    so a switch flipped on the server reaches a phone at its next launch.
 *    The decision itself is derived from the persisted snapshot every mount,
 *    instantly.
 *  - A network failure shows nothing. We never invent a scary "out of date".
 *  - An OPTIONAL nudge is dismissible per target version (dismiss once, we stay
 *    quiet until there's an even newer one). A REQUIRED gate is never
 *    dismissible.
 */
import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

import { setRemoteConfig } from "../../modules/cleanway-vpn";
import {
  decideUpdate,
  fetchVersionInfo,
  type UpdateDecision,
  type VersionInfo,
} from "../lib/update-check";
import { readStamp, refreshDue, remoteConfigWire, type RefreshTrigger } from "../lib/remote-config";

const API_BASE = (
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_API_URL) ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://api.cleanway.ai"
).replace(/\/+$/, "");

const WEB_BASE = "https://cleanway.ai";
const SNAPSHOT_KEY = "cleanway_update_snapshot";
// The last SUCCESSFUL check. (Before 1.0.4 a failure also wrote here, backdated
// to retry within the hour; such a stamp now simply reads as an older success.)
const LAST_CHECK_KEY = "cleanway_update_last_check";
// The last attempt, success or not: the hourly floor (remote-config.ts
// MIN_GAP_MS) that keeps a launch loop or a failing endpoint from hammering us.
const LAST_ATTEMPT_KEY = "cleanway_update_last_attempt";
const DISMISSED_KEY = "cleanway_update_dismissed"; // the version name last dismissed

const RUNNING = Constants.expoConfig?.version ?? "0.0.0";

export interface UpdateStatus {
  decision: UpdateDecision; // "none" | "optional" | "required"
  latestVersionName: string;
  /** Best download target: the server's signed APK URL, else the /android page. */
  downloadUrl: string;
  releaseNotes: string | null;
  dismiss: () => void;
}

const NONE: UpdateStatus = {
  decision: "none",
  latestVersionName: "",
  downloadUrl: `${WEB_BASE}/android`,
  releaseNotes: null,
  dismiss: () => {},
};

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

  useEffect(() => {
    if (Platform.OS !== "android") return;
    let alive = true;
    let inFlight = false;

    // Ask the server if it is time (refreshDue), and apply what comes back.
    const refresh = async (trigger: RefreshTrigger) => {
      if (inFlight) return;
      inFlight = true;
      try {
        let lastAttempt = 0;
        let lastSuccess = 0;
        try {
          const [rawAttempt, rawSuccess] = await Promise.all([
            SecureStore.getItemAsync(LAST_ATTEMPT_KEY),
            SecureStore.getItemAsync(LAST_CHECK_KEY),
          ]);
          lastAttempt = readStamp(rawAttempt);
          lastSuccess = readStamp(rawSuccess);
        } catch {
          // Unreadable stamps → treat as never checked.
        }
        const now = Date.now();
        if (!refreshDue(trigger, now, lastAttempt, lastSuccess)) return;
        try {
          await SecureStore.setItemAsync(LAST_ATTEMPT_KEY, String(now));
        } catch {
          // best effort
        }
        const fetched = await fetchVersionInfo(API_BASE);
        // A failed check changes nothing: the snapshot and the native switches
        // stay as they were, and the next try waits for the hourly floor.
        if (!fetched) return;
        // The switches first, and even if the screen has gone: the native
        // message check reads them, not this component.
        if (fetched.remoteConfig) setRemoteConfig(remoteConfigWire(fetched.remoteConfig));
        if (alive) setInfo(fetched);
        try {
          await SecureStore.setItemAsync(SNAPSHOT_KEY, JSON.stringify(fetched));
          await SecureStore.setItemAsync(LAST_CHECK_KEY, String(Date.now()));
        } catch {
          // Persisting is best-effort; the in-memory decision still holds.
        }
      } finally {
        inFlight = false;
      }
    };

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

      // 2. App start: ask the server (at most once an hour).
      await refresh("start");
    })();

    // 3. While the app stays open: about daily, when it comes back to the front.
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "active") void refresh("resume");
    });

    return () => {
      alive = false;
      sub.remove();
    };
  }, []);

  const dismiss = useCallback(() => {
    if (!info) return;
    setDismissedVersion(info.latestVersionName);
    SecureStore.setItemAsync(DISMISSED_KEY, info.latestVersionName).catch(() => {});
  }, [info]);

  if (!ready || Platform.OS !== "android" || !info) return NONE;

  // hasDownload=false when the server has no signed APK URL yet: we still tell
  // the user, but never as an undismissable demand they cannot satisfy.
  const raw = decideUpdate(
    RUNNING,
    info.latestVersionName,
    info.minSupportedVersionName,
    !!info.apkUrl,
  );
  // Required is never suppressible; an optional nudge the user already waved
  // away stays hidden until a newer version supersedes what they dismissed.
  const decision: UpdateDecision =
    raw === "optional" && dismissedVersion === info.latestVersionName ? "none" : raw;

  return {
    decision,
    latestVersionName: info.latestVersionName,
    downloadUrl: downloadUrlFor(info, lang),
    releaseNotes: info.releaseNotes,
    dismiss,
  };
}
