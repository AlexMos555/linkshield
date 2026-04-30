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

import { getSupabaseServer } from "@/lib/supabase/server";

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const rawNext = searchParams.get("next") ?? "/";

  // Defense in depth: only allow same-origin redirects so an open-
  // redirect bug doesn't piggy-back off our auth flow.
  const next = rawNext.startsWith("/") && !rawNext.startsWith("//") ? rawNext : "/";

  if (!code) {
    return NextResponse.redirect(`${origin}/signup?error=missing_code`);
  }

  const supabase = await getSupabaseServer();
  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) {
    return NextResponse.redirect(`${origin}/signup?error=${encodeURIComponent(error.message)}`);
  }

  // Cookie is now set; redirect to the originally-intended page.
  return NextResponse.redirect(`${origin}${next}`);
}
