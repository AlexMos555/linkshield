/**
 * How people can reach us — and whether they actually can.
 *
 * support@cleanway.ai forwards to the founder's inbox (since 2026-10-13; since
 * the 2026-10 infra move through Cloudflare Email Routing, MX on cleanway.ai —
 * the privacy policy names Cloudflare for it), so pages show the address
 * by default. If the mailbox ever stops working, set
 * NEXT_PUBLIC_SUPPORT_EMAIL_LIVE=0 in the Vercel project and redeploy: every
 * page then says plainly that mail may not reach us and points at what the
 * person can do on their own. Next inlines NEXT_PUBLIC_* only when spelled out
 * literally, hence the direct lookup below.
 */
export const SUPPORT_EMAIL = "support@cleanway.ai";

const ON_VALUES: ReadonlySet<string> = new Set(["1", "true", "yes", "on"]);
const OFF_VALUES: ReadonlySet<string> = new Set(["0", "false", "no", "off"]);

export function isFlagOn(value: string | undefined | null): boolean {
  return ON_VALUES.has((value ?? "").trim().toLowerCase());
}

export function isFlagOff(value: string | undefined | null): boolean {
  return OFF_VALUES.has((value ?? "").trim().toLowerCase());
}

export const SUPPORT_EMAIL_LIVE: boolean = !isFlagOff(process.env.NEXT_PUBLIC_SUPPORT_EMAIL_LIVE);
