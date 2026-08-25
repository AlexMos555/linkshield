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
 */
import { useCallback, useEffect, useState } from "react";
import { Platform } from "react-native";
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";

import {
  decideUpdate,
  fetchVersionInfo,
  type UpdateDecision,
  type VersionInfo,
} from "../lib/update-check";

const API_BASE = (
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_API_URL) ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://api.cleanway.ai"
).replace(/\/+$/, "");

const WEB_BASE = "https://cleanway.ai";
const CHECK_INTERVAL_MS = 20 * 60 * 60 * 1000; // ~daily, off launch cadence
const SNAPSHOT_KEY = "cleanway_update_snapshot";
const LAST_CHECK_KEY = "cleanway_update_last_check";
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
        if (Number.isFinite(last) && Date.now() - last < CHECK_INTERVAL_MS) return;
      } catch {
        // fall through and check
      }
      const fresh = await fetchVersionInfo(API_BASE);
      if (!alive || !fresh) return;
      setInfo(fresh);
      try {
        await SecureStore.setItemAsync(SNAPSHOT_KEY, JSON.stringify(fresh));
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

  const raw = decideUpdate(RUNNING, info.latestVersionName, info.minSupportedVersionName);
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
