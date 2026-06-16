/**
 * Sentry initialiser for the Cleanway mobile app.
 *
 * Activates only when EXPO_PUBLIC_SENTRY_DSN is set at build time. With
 * no DSN, init() is a no-op — Sentry stays dormant, zero network calls.
 * Matches the landing/api pattern: PII scrubbed before send, no
 * sensitive default PII.
 *
 * Wire from app/_layout.tsx with `import "../src/lib/sentry"` so the
 * SDK initialises before any screen mounts (matching the i18n
 * side-effect import we already do).
 */
import Constants from "expo-constants";
import * as Sentry from "@sentry/react-native";

import { beforeBreadcrumbScrub, beforeSendScrub } from "./sentry-scrub";

const dsn =
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_SENTRY_DSN) ||
  (Constants.expoConfig?.extra?.sentryDsn as string | undefined);

if (dsn) {
  Sentry.init({
    dsn,
    // Production / preview / development from EAS profile.
    environment:
      (typeof process !== "undefined" &&
        (process.env?.EXPO_PUBLIC_APP_ENV || process.env?.NODE_ENV)) ||
      "development",
    release: Constants.expoConfig?.version,
    tracesSampleRate: 0.1,
    sendDefaultPii: false,
    // Cast at the SDK boundary — the scrubber returns unknown by
    // design (see sentry-scrub.ts for why); RN Sentry's beforeSend
    // type expects the SDK's own Event shape, which the scrubbed
    // payload always is in practice.
    beforeSend: beforeSendScrub as unknown as Parameters<typeof Sentry.init>[0]["beforeSend"],
    beforeBreadcrumb: beforeBreadcrumbScrub as unknown as Parameters<typeof Sentry.init>[0]["beforeBreadcrumb"],
  });
}

export { Sentry };
