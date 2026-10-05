/**
 * The paid-subscription switch for this build (billing plan §2, A.10).
 *
 * OFF (the default): no subscription screen, no card on the home screen, no
 * call to the billing API, no pass handed to the native shield — the app is
 * exactly what it was before this code existed. The founder flips it, per
 * build, with `EXPO_PUBLIC_BILLING_RU_ENABLED=1` (inlined at build time like
 * every EXPO_PUBLIC_* value) or `expo.extra.billingRuEnabled` in app.json.
 *
 * Prices are never written here: the app shows what `GET /billing/v1/plans`
 * answers, so a price change is a server setting, not an app release.
 */
import Constants from "expo-constants";

/** The billing role's base URL (ROLE=billing, the Russian host). */
const DEFAULT_BILLING_API = "https://billing.cleanway.ai";

/** The consent text version the checkout screen renders; the server accepts only its current one. */
export const CONSENT_DOC_VERSION = "ru/v1";

type Env = Record<string, string | undefined>;
type Extra = Record<string, unknown> | undefined;

function env(): Env {
  return typeof process !== "undefined" && process.env ? (process.env as Env) : {};
}

function extra(): Extra {
  return (Constants.expoConfig?.extra ?? undefined) as Extra;
}

/** Pure: is the paid flow on for [env] and [extra]? Only an explicit yes counts. */
export function billingFlagOn(e: Env, x: Extra): boolean {
  const raw = (e.EXPO_PUBLIC_BILLING_RU_ENABLED ?? "").trim().toLowerCase();
  if (raw === "1" || raw === "true") return true;
  return x?.billingRuEnabled === true;
}

export function billingEnabled(): boolean {
  return billingFlagOn(env(), extra());
}

/** Pure: the billing API base without a trailing slash. */
export function billingApiBaseFrom(e: Env, x: Extra): string {
  const raw = e.EXPO_PUBLIC_BILLING_API_URL || (typeof x?.billingApiUrl === "string" ? x.billingApiUrl : "");
  return (raw || DEFAULT_BILLING_API).replace(/\/+$/, "");
}

export function billingApiBase(): string {
  return billingApiBaseFrom(env(), extra());
}

/**
 * Pure: the Ed25519 public keys the pass is verified with, `{kid: base64}`
 * (BILLING_ENTITLEMENT_PUBLIC_KEYS on the server, the same JSON). Empty when
 * unset or unreadable — then no pass verifies and the app says so, rather
 * than trusting an unsigned one.
 */
export function passPublicKeysFrom(e: Env, x: Extra): Record<string, string> {
  const raw = e.EXPO_PUBLIC_BILLING_PASS_PUBLIC_KEYS ?? (typeof x?.billingPassPublicKeys === "string" ? x.billingPassPublicKeys : "");
  if (!raw || !raw.trim()) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [kid, key] of Object.entries(parsed as Record<string, unknown>)) {
      if (kid && typeof key === "string" && key.length > 0) out[kid] = key;
    }
    return out;
  } catch {
    return {};
  }
}

export function passPublicKeys(): Record<string, string> {
  return passPublicKeysFrom(env(), extra());
}
