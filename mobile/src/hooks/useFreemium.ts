/**
 * The free plan, for screens. With EXPO_PUBLIC_FREEMIUM_ENABLED off both
 * hooks answer "unlimited" / "detailed" on the first render and never touch
 * storage — the screens behave exactly as before the flag existed.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { useFocusEffect, useRouter } from "expo-router";

import {
  FREEMIUM, beginDetailedCheck, currentAccess, freemiumEvents, notePaywallShown,
} from "../services/freemium";
import type { Access } from "../utils/freemium";

const OFF: Access = { kind: "unlimited", why: "off" };

/** What the next check gets, kept current on focus and whenever the counter moves. Null while reading. */
export function useAccess(): Access | null {
  const [access, setAccess] = useState<Access | null>(FREEMIUM.enabled ? null : OFF);

  const load = useCallback(() => {
    if (!FREEMIUM.enabled) return;
    void currentAccess().then(setAccess, () => setAccess(OFF));
  }, []);

  useFocusEffect(load);

  useEffect(() => {
    if (!FREEMIUM.enabled) return;
    freemiumEvents.on("changed", load);
    return () => {
      freemiumEvents.off("changed", load);
    };
  }, [load]);

  return access;
}

export interface DetailGate {
  /** The site the decision is about. */
  key: string | null;
  /** true: detailed check; false: the list's verdict only; null: still deciding. */
  deep: boolean | null;
  /** The limit stopped this check and the paywall has not opened by itself today. */
  autoPaywall: boolean;
}

/**
 * One decision per site shown by a link-check screen (the same screen can be
 * handed a second site — see useDomainCheck). Spends a free check when it
 * allows one; re-opening the same site today is free.
 */
export function useDetailGate(key: string | null): DetailGate {
  const [gate, setGate] = useState<DetailGate>(() => ({ key, deep: FREEMIUM.enabled ? null : true, autoPaywall: false }));

  useEffect(() => {
    if (!FREEMIUM.enabled || !key) return;
    let alive = true;
    void beginDetailedCheck(key).then((d) => {
      if (alive) setGate({ key, deep: d.detailed, autoPaywall: d.autoPaywall });
    });
    return () => {
      alive = false;
    };
  }, [key]);

  if (!FREEMIUM.enabled || !key) return { key, deep: true, autoPaywall: false };
  // A new site in the same screen: undecided until its own answer comes.
  return gate.key === key ? gate : { key, deep: null, autoPaywall: false };
}

/**
 * Open the paywall by itself where the limit stopped a check — once a day,
 * and never over a "dangerous" verdict: [dangerous] must be known (false)
 * first. Later stops show only the in-place card.
 */
export function useAutoPaywall(stopped: boolean, autoPaywall: boolean, dangerous: boolean | undefined, key: string | null): void {
  const router = useRouter();
  const opened = useRef<string | null>(null);
  const id = key ?? "";
  useEffect(() => {
    if (!stopped || !autoPaywall || dangerous !== false || opened.current === id) return;
    opened.current = id;
    void notePaywallShown();
    router.push("/paywall");
  }, [stopped, autoPaywall, dangerous, id, router]);
}
