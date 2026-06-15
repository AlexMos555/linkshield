/**
 * Magic-link callback handler.
 *
 * Supabase bounces the user back here with ?code=... after they click
 * the magic-link email. We exchange the code for a session, set the
 * cookie, and bounce them to wherever they were going (?next=...).
 *
 * This is a Route Handler (not a page) so it can write the cookie
 * before responding with a redirect — which is exactly what /api auth
 * patterns need.
 */
import { NextRequest, NextResponse } from "next/server";

import { routing, type Locale } from "@/i18n/routing";
import { getSupabaseServer } from "@/lib/supabase/server";

const DEFAULT_LOCALE: Locale = "en";

/**
 * Same-origin redirect guard.
 *
 * The naive `startsWith('/') && !startsWith('//')` check is unsafe:
 * `/\evil.com` passes both (single slash, not double) but Chromium
 * normalizes the backslash to a slash and treats it as `//evil.com`,
 * a protocol-relative URL that escapes the origin. Percent-encoded
 * variants (`/%2f%2fevil.com`) bypass startsWith too.
 *
 * Parse the candidate against our own origin and verify the resulting
 * URL is actually same-origin. That handles backslashes, percent
 * encoding, control characters, and any future parser quirk we
 * haven't yet seen.
 */
function safeRedirectPath(rawNext: string, origin: string, fallback = "/"): string {
  try {
    const candidate = new URL(rawNext, origin);
    if (candidate.origin !== origin) return fallback;
    return candidate.pathname + candidate.search + candidate.hash;
  } catch {
    return fallback;
  }
}

/**
 * Pull the locale segment from a path-only redirect target.
 *
 * Used so the soft-delete branch can route the user to
 * `/{locale}/account/restore` instead of always hitting the default
 * locale, which would silently flip a Russian / Arabic / Hindi user
 * to English mid-flow.
 *
 * Path must already be same-origin and start with "/" — see
 * safeRedirectPath above.
 */
function localeFromPath(path: string): Locale {
  const first = path.split("/")[1]; // "" for "/", "ru" for "/ru/pricing"
  if (first && (routing.locales as readonly string[]).includes(first)) {
    return first as Locale;
  }
  return DEFAULT_LOCALE;
}

/** Build "/account/restore?reason=locked" with the right locale prefix. */
function restorePath(locale: Locale): string {
  const base = locale === DEFAULT_LOCALE ? "" : `/${locale}`;
  return `${base}/account/restore?reason=locked`;
}

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const rawNext = searchParams.get("next") ?? "/";
  const next = safeRedirectPath(rawNext, origin);

  if (!code) {
    return NextResponse.redirect(`${origin}/signup?error=missing_code`);
  }

  const supabase = await getSupabaseServer();
  const { data, error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    // Don't echo Supabase's raw error message in the URL — those
    // strings sometimes contain operational details (provider names,
    // internal IDs, debugging hints) that the Referer header would
    // then leak to every third-party fetched by the /signup page.
    // Use a stable code instead; /signup maps it to user-friendly
    // copy. The real error is logged server-side for debugging.
    // (Audit landing-security LOW "Supabase auth error.message
    // reflected verbatim into URL query string, leaking internal
    // error details via Referer".)
    console.error("[auth/callback] exchangeCodeForSession failed:", error.message);
    return NextResponse.redirect(`${origin}/signup?error=exchange_failed`);
  }

  const accessToken = data.session?.access_token;
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

  if (accessToken) {
    // Critical-path latency: we need the soft-delete probe before
    // deciding where to redirect, but the welcome email is fire-and-
    // forget. Fan both out in parallel — total time is max(probe,
    // welcome) ≈ probe, instead of probe+welcome sequential.
    //
    // The welcome email is idempotent on the backend (deduped via
    // welcome_email_sent_at column), so a duplicate call from a
    // double-click on the magic link is a no-op.
    const welcomePromise = fetch(`${apiBase}/api/v1/user/welcome`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
    }).catch(() => {
      // Welcome email is a courtesy — never block sign-in on it.
    });

    // Soft-delete gate. If the user successfully completed magic-link
    // auth but their account is in the 30-day grace window, every
    // subsequent authed call will return 410 Gone. Catching that here
    // means we route them to /account/restore directly — in their
    // locale — instead of letting them land on /pricing or / and
    // bounce into generic error UX. /user/profile is cheap and only
    // requires read access; restore is the only operation a locked
    // account is allowed to do.
    let probeStatus: number | null = null;
    try {
      const probe = await fetch(`${apiBase}/api/v1/user/profile`, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` },
        // Short timeout — this is in the auth-callback critical path,
        // we don't want to hang on a slow API.
        signal: AbortSignal.timeout(3000),
      });
      probeStatus = probe.status;
    } catch {
      // Probe failed (timeout, network blip) — fail open and let the
      // user land normally. If their account really is locked, the
      // next API call from the destination page will catch the 410
      // and route them then.
    }

    // Don't leave the welcome request dangling — best-effort await
    // so the cookie isn't sealed before it finishes. .catch() above
    // already swallows errors so this can't throw.
    await welcomePromise;

    if (probeStatus === 410) {
      const locale = localeFromPath(next);
      return NextResponse.redirect(`${origin}${restorePath(locale)}`);
    }
  }

  // Cookie is now set; redirect to the originally-intended page.
  return NextResponse.redirect(`${origin}${next}`);
}
