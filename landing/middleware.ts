import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  // Match all pathnames except:
  //  - /api/* (API routes)
  //  - /auth/* — lives OUTSIDE app/[locale]: the magic-link callback (a
  //    route handler) and the mobile captcha page, both locale-free. With
  //    them matched, next-intl rewrote /auth/callback to /en/auth/callback
  //    (404) and redirected non-EN browsers to /ru/auth/callback (also 404);
  //    verified with curl before adding this exclusion.
  //  - /_next/* (Next.js internals)
  //  - /_vercel/* (Vercel internals)
  //  - static files (anything with a dot like .png, .ico, .svg)
  matcher: [
    "/((?!api|auth/|_next|_vercel|.*\\..*).*)",
    // Dotted paths bypass the matcher above (the `.*\\..*` exclusion). Add
    // every dynamic-domain route here explicitly so unprefixed canonical
    // share-URLs (e.g. /check/google.com, /audit/google.com) get rewritten
    // to the default locale by next-intl instead of 404ing.
    "/check/(.*)",
    "/audit/(.*)",
  ],
};
