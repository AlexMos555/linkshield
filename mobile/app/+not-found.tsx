/**
 * A cleanway:// path this build has no screen for — a mistyped link, or one
 * made for a later version (the API already builds cleanway://activate and
 * cleanway://claim for flows that are not in the app yet). Without this file
 * expo-router showed its English "Unmatched Route" developer page with a link
 * to a sitemap of every route.
 */
import { UnknownLinkScreen } from "../src/components/AppFallbacks";

export default UnknownLinkScreen;
