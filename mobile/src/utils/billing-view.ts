/**
 * What the subscription screens show for a given entitlement — the
 * state → screen mapping of billing plan §2.5, as one pure function so the
 * table in scripts/test-billing-view.mjs can pin every row.
 *
 * Two inputs, one answer. `status` is the server's last word (richer: seats,
 * next charge, who pays); `claims` is the last verified pass, which keeps
 * telling the truth after that word is stale: a trial that ended while the
 * phone was offline is "ended" here, not "3 days left", because the pass's
 * own clock rule (`offlineMode`) outranks a snapshot.
 */
import {
  type EntitlementSource,
  type LapsePolicy,
  type PassClaims,
  type ProtectionMode,
  lapseMode,
  offlineMode,
} from "../lib/entitlement";

export type PlanCode = "solo" | "family3" | "family5";
export const PLAN_CODES: readonly PlanCode[] = ["solo", "family3", "family5"];
export const PLAN_SEATS: Readonly<Record<PlanCode, number>> = { solo: 1, family3: 3, family5: 5 };

export type SubscriptionState = "pending" | "active" | "grace" | "cancel_at_period_end" | "lapsed" | "refunded";

/** `status.subscription` of GET /billing/v1/entitlement (service/passes.py). */
export interface SubscriptionStatus {
  id: string;
  status: SubscriptionState;
  plan: string;
  seats_total: number;
  seats_used: number;
  price_kopecks: number;
  period_end: number | null;
  next_charge_at: number | null;
  grace_until: number | null;
  cancel_requested_at: number | null;
  is_payer: boolean;
  provider: string;
}

/** `status` of GET /billing/v1/entitlement. */
export interface EntitlementStatus {
  mode: ProtectionMode;
  source: EntitlementSource;
  plan: string | null;
  lapse_policy: LapsePolicy;
  until: number | null;
  grace_until: number | null;
  trial_ends_at: number | null;
  trial_used: boolean;
  subscription: SubscriptionStatus | null;
  notices: string[];
}

export interface BillingSnapshot {
  /** The build's switch (config/billing.ts). Off → nothing is shown. */
  enabled: boolean;
  status: EntitlementStatus | null;
  claims: PassClaims | null;
  /** This phone was once covered by a paid subscription (billing-store.ts). */
  hadSubscription: boolean;
  nowSec: number;
}

const DAY = 86_400;

export type BillingView =
  | { kind: "hidden" }
  /** The flag is on but the billing server has never answered: no trial can start, nothing to show but "retry". */
  | { kind: "unknown" }
  /** Registered, no trial yet — the trial starts by itself; this is the moment before. */
  | { kind: "no_trial" }
  | { kind: "trial"; endsAt: number; daysLeft: number; ending: boolean }
  | {
      kind: "active";
      source: "subscription" | "promo";
      plan: string | null;
      seatsUsed: number | null;
      seatsTotal: number | null;
      priceRub: number | null;
      nextChargeAt: number | null;
      periodEnd: number | null;
      isPayer: boolean;
    }
  | { kind: "grace"; plan: string | null; graceUntil: number; daysLeft: number; isPayer: boolean; priceRub: number | null }
  | { kind: "cancelled"; plan: string | null; periodEnd: number | null; isPayer: boolean }
  /** A checkout waits for the operator's SMS. */
  | { kind: "pending"; plan: string | null }
  /** Installed before the paid launch; protection stays as it was. */
  | { kind: "legacy" }
  | { kind: "lapsed"; after: "trial" | "subscription" | "none"; mode: ProtectionMode };

/** Whole days left until [endSec], never negative; the last day is 0 — "ends today". */
export function daysLeft(endSec: number, nowSec: number): number {
  return Math.max(0, Math.floor((endSec - nowSec) / DAY));
}

type Phase = "issued" | "grace" | "lapsed";

/** Where the pass's own clock rule puts this moment. */
function passPhase(claims: PassClaims, nowSec: number): Phase {
  const now = Math.max(Math.trunc(nowSec), claims.iat);
  if (claims.until === null || now < claims.until) return "issued";
  if (claims.grace_until !== null && now < claims.grace_until) return "grace";
  return "lapsed";
}

/** The protection mode this phone is entitled to right now; full until a pass says otherwise. */
export function effectiveMode(claims: PassClaims | null, nowSec: number): ProtectionMode {
  return claims ? offlineMode(claims, nowSec) : "full";
}

function priceRub(sub: SubscriptionStatus | null): number | null {
  return sub && Number.isFinite(sub.price_kopecks) ? Math.floor(sub.price_kopecks / 100) : null;
}

function lapsedAfter(s: BillingSnapshot): "trial" | "subscription" | "none" {
  if (s.hadSubscription) return "subscription";
  if (s.status?.trial_used || s.claims?.src === "trial") return "trial";
  return "none";
}

function fromSubscription(sub: SubscriptionStatus, s: BillingSnapshot): BillingView | null {
  const price = priceRub(sub);
  switch (sub.status) {
    case "pending":
      return { kind: "pending", plan: sub.plan };
    case "active":
      return {
        kind: "active", source: "subscription", plan: sub.plan, seatsUsed: sub.seats_used, seatsTotal: sub.seats_total,
        priceRub: price, nextChargeAt: sub.next_charge_at, periodEnd: sub.period_end, isPayer: sub.is_payer,
      };
    case "grace": {
      const graceUntil = sub.grace_until ?? s.status?.grace_until ?? s.claims?.grace_until ?? s.nowSec;
      return { kind: "grace", plan: sub.plan, graceUntil, daysLeft: daysLeft(graceUntil, s.nowSec), isPayer: sub.is_payer, priceRub: price };
    }
    case "cancel_at_period_end":
      return { kind: "cancelled", plan: sub.plan, periodEnd: sub.period_end, isPayer: sub.is_payer };
    default:
      return null;
  }
}

function fromStatus(status: EntitlementStatus, s: BillingSnapshot): BillingView {
  if (status.subscription) {
    const view = fromSubscription(status.subscription, s);
    if (view) return view;
  }
  switch (status.source) {
    case "legacy":
      return { kind: "legacy" };
    case "trial": {
      const endsAt = status.trial_ends_at ?? status.until ?? s.nowSec;
      const left = daysLeft(endsAt, s.nowSec);
      return { kind: "trial", endsAt, daysLeft: left, ending: left <= 3 };
    }
    case "promo":
    case "subscription":
      return {
        kind: "active", source: status.source === "promo" ? "promo" : "subscription", plan: status.plan,
        seatsUsed: null, seatsTotal: null, priceRub: null, nextChargeAt: null, periodEnd: status.until, isPayer: false,
      };
    default:
      if (!status.trial_used && !s.hadSubscription) return { kind: "no_trial" };
      return { kind: "lapsed", after: lapsedAfter(s), mode: lapseMode(status.lapse_policy) };
  }
}

/** Offline since the first pass: the pass alone, with what it knows. */
function fromClaims(claims: PassClaims, s: BillingSnapshot): BillingView {
  switch (claims.src) {
    case "legacy":
      return { kind: "legacy" };
    case "trial": {
      const endsAt = claims.until ?? s.nowSec;
      const left = daysLeft(endsAt, s.nowSec);
      return { kind: "trial", endsAt, daysLeft: left, ending: left <= 3 };
    }
    case "promo":
    case "subscription":
      return {
        kind: "active", source: claims.src, plan: claims.plan, seatsUsed: null, seatsTotal: null, priceRub: null,
        nextChargeAt: null, periodEnd: claims.until, isPayer: false,
      };
    default:
      return { kind: "lapsed", after: lapsedAfter(s), mode: lapseMode(claims.lapse_policy) };
  }
}

export function billingView(s: BillingSnapshot): BillingView {
  if (!s.enabled) return { kind: "hidden" };
  if (!s.status && !s.claims) return { kind: "unknown" };
  // The pass's clock rule first: a snapshot cannot outlive the period it describes.
  if (s.claims) {
    const phase = passPhase(s.claims, s.nowSec);
    if (phase === "lapsed") return { kind: "lapsed", after: lapsedAfter(s), mode: lapseMode(s.claims.lapse_policy) };
    if (phase === "grace") {
      const sub = s.status?.subscription ?? null;
      const graceUntil = s.claims.grace_until ?? s.nowSec;
      return {
        kind: "grace", plan: sub?.plan ?? s.claims.plan, graceUntil, daysLeft: daysLeft(graceUntil, s.nowSec),
        isPayer: sub?.is_payer ?? false, priceRub: priceRub(sub),
      };
    }
  }
  if (s.status) return fromStatus(s.status, s);
  return fromClaims(s.claims as PassClaims, s);
}

/**
 * What "cancel" means for protection, said plainly before the tap lands:
 * covered until [protectedUntil] (null: until the server confirms), then the
 * lapse policy — basic (list once a week, yellow shield) or off.
 */
export interface CancelOutcome {
  protectedUntil: number | null;
  then: ProtectionMode;
}

export function cancelOutcome(view: BillingView, policy: LapsePolicy): CancelOutcome {
  const then = lapseMode(policy);
  switch (view.kind) {
    case "active":
      return { protectedUntil: view.periodEnd, then };
    case "grace":
      return { protectedUntil: view.graceUntil, then };
    case "cancelled":
      return { protectedUntil: view.periodEnd, then };
    default:
      return { protectedUntil: null, then };
  }
}

/** The home screen's shield hold for a mode: none while full. */
export type ModeHold = "basic" | "off" | null;

export function modeHold(mode: ProtectionMode): ModeHold {
  return mode === "full" ? null : mode;
}

/** The view offers the payer the seat screens (add a phone, the device list). */
export function canManageSeats(view: BillingView): boolean {
  return (view.kind === "active" || view.kind === "grace" || view.kind === "cancelled") && view.isPayer;
}

/** The view has a subscription to cancel (one tap, with the confirmation). */
export function canCancel(view: BillingView): boolean {
  return (view.kind === "active" && view.source === "subscription" && view.isPayer) || (view.kind === "grace" && view.isPayer);
}

/** The view offers the plans (no live subscription to pay for). */
export function offersPlans(view: BillingView): boolean {
  return view.kind === "trial" || view.kind === "lapsed" || view.kind === "no_trial" || view.kind === "legacy";
}
