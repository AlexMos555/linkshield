import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  // Match all pathnames except:
  //  - /api/* (API routes)
  //  - /_next/* (Next.js internals)
  //  - /_vercel/* (Vercel internals)
  //  - static files (anything with a dot like .png, .ico, .svg)
  matcher: "/((?!api|_next|_vercel|.*\\..*).*)",
};
