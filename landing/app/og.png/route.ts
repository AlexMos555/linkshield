/**
 * The site's share image (app/[locale]/opengraph-image.tsx) at a URL that
 * never redirects.
 *
 * Every page names it in og:image. At /opengraph-image it went through the
 * next-intl middleware, which picks a locale from cookies and Accept-Language:
 * a link-preview bot that sends "Accept-Language: ru" got a 307 to
 * /ru/opengraph-image, and the English pages' own file-convention URL,
 * /en/opengraph-image, is a 307 for everyone (English lives at the apex). A
 * path with a dot is outside the middleware matcher (middleware.ts), so this
 * one answers 200 in every language. Rendered once at build time.
 */
import OpenGraphImage from "../[locale]/opengraph-image";

export const dynamic = "force-static";

export function GET(): Response {
  return OpenGraphImage();
}
