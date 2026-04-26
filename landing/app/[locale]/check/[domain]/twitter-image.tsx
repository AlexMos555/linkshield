/**
 * Twitter (X) card image — same content as the Open Graph image.
 *
 * Next.js requires `runtime` / `alt` / `size` / `contentType` to be
 * statically analyzable, so we declare them inline instead of re-exporting.
 * The render function itself is shared with opengraph-image.
 */
export { default } from "./opengraph-image";

export const runtime = "edge";
export const alt = "Cleanway safety check";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
