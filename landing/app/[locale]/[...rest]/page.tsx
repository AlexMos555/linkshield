import { notFound } from "next/navigation";

/**
 * Any unknown path under a locale (/ru/whatever) lands here and 404s through
 * app/[locale]/not-found.tsx — inside the locale layout, so the page is in the
 * visitor's language. Without this catch-all Next falls through to the root
 * app/not-found.tsx, which only knows English.
 */
export default function CatchAllPage() {
  notFound();
}
