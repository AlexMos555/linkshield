import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  // Match all pathnames except:
  //  - /api/* (API routes)
  //  - /_next/* (Next.js internals)
  //  - /_vercel/* (Vercel internals)
  //  - static files (anything with a dot like .png, .ico, .svg)
  matcher: [
    "/((?!api|_next|_vercel|.*\\..*).*)",
    // Dotted paths bypass the matcher above (the `.*\\..*` exclusion). Add
    // every dynamic-domain route here explicitly so unprefixed canonical
    // share-URLs (e.g. /check/google.com, /audit/google.com) get rewritten
    // to the default locale by next-intl instead of 404ing.
    "/check/(.*)",
    "/audit/(.*)",
  ],
};
