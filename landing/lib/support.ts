/**
 * How people can reach us — and whether they actually can yet.
 *
 * cleanway.ai has no MX record today, so mail to support@ bounces or vanishes.
 * A page that prints the address as "we read every message" promises a reply
 * nobody will send. Until the mailbox works, pages say so plainly and point at
 * what the person can do on their own.
 *
 * Once mail is set up (MX record + a mailbox or forwarding for support@),
 * set NEXT_PUBLIC_SUPPORT_EMAIL_LIVE=1 in the Vercel project and redeploy;
 * every page switches to showing the address. Next inlines NEXT_PUBLIC_*
 * only when spelled out literally, hence the direct lookup below.
 */
export const SUPPORT_EMAIL = "support@cleanway.ai";

const ON_VALUES: ReadonlySet<string> = new Set(["1", "true", "yes", "on"]);

export function isFlagOn(value: string | undefined | null): boolean {
  return ON_VALUES.has((value ?? "").trim().toLowerCase());
}

export const SUPPORT_EMAIL_LIVE: boolean = isFlagOn(process.env.NEXT_PUBLIC_SUPPORT_EMAIL_LIVE);
