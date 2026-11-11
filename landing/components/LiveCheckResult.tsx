"use client";

import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";

import CheckResultCard from "@/components/CheckResultCard";
import { checkCardProps, type AdvisoryStrings, type ScanResult } from "@/lib/check-card";

/**
 * The /check verdict for a site on Google's lists, fetched by the browser.
 *
 * Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-04) allow one only while "the cached response
 * is still valid at the time a warning is shown. Under no other
 * circumstances". The page is cached and regenerated in the background — a
 * copy can be served at any age — so when its own render finds a verdict
 * resting on Google, it leaves the verdict out and hands the check to this
 * component: the browser asks the API (whose cache keeps such a verdict only
 * while Google's answer lives), shows the answer, and once the API's
 * `advisory_ttl` runs out takes it down and asks again. If Google no longer
 * lists the site, the fresh answer says so.
 *
 * Same request as the extension's and the app's: the site name only, no
 * cookies. Labels come in as props, so this adds no namespace to every
 * page's client bundle (lib/client-messages.ts); Check is already there.
 */
interface LiveCheckResultProps {
  /** The host the API is asked about. */
  readonly domain: string;
  /** The host as people read it (lib/display-host.ts). */
  readonly shownDomain: string;
  readonly canonical: string;
  readonly methodologyHref: string;
  /** The API as the browser reaches it. */
  readonly apiBase: string;
  /** The Reasons namespace. */
  readonly reasons: Readonly<Record<string, string>>;
  readonly advisory: AdvisoryStrings;
}

// setTimeout's ceiling; advisory_ttl is at most an hour anyway.
const MAX_TIMER_MS = 2_147_483_647;
// advisory_ttl 0: Google's answer was valid when the API replied, for how
// long nobody could read. Shown this long, then asked again — the extension
// does the same (packages/extension-core/src/background/google-verdict.js).
const ZERO_WINDOW_MS = 30_000;
// A site's first check runs the server's whole analysis (up to ~11 s in the
// field); past this the card says the check failed instead of waiting forever.
const FETCH_TIMEOUT_MS = 20_000;

export default function LiveCheckResult({
  domain,
  shownDomain,
  canonical,
  methodologyHref,
  apiBase,
  reasons,
  advisory,
}: LiveCheckResultProps) {
  const t = useTranslations("Check");
  // null: asking (the card says "Checking…"); {}: no answer.
  const [result, setResult] = useState<ScanResult | null>(null);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let inFlight: AbortController | undefined;
    const load = async () => {
      let answer: ScanResult = {};
      const abort = new AbortController();
      inFlight = abort;
      const giveUp = setTimeout(() => abort.abort(), FETCH_TIMEOUT_MS);
      try {
        const resp = await fetch(`${apiBase}/api/v1/public/check/${encodeURIComponent(domain)}`, {
          cache: "no-store",
          credentials: "omit",
          signal: abort.signal,
        });
        if (resp.ok) answer = (await resp.json()) as ScanResult;
      } catch {
        // Offline, blocked, timed out: the card says the check failed.
      } finally {
        clearTimeout(giveUp);
      }
      if (!alive) return;
      setResult(answer);
      const left = answer.advisory_ttl;
      if (typeof left === "number" && left >= 0) {
        timer = setTimeout(() => {
          setResult(null);
          void load();
        }, Math.min(left > 0 ? left * 1000 : ZERO_WINDOW_MS, MAX_TIMER_MS));
      }
    };
    void load();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
      inFlight?.abort();
    };
  }, [apiBase, domain]);

  const card = checkCardProps({
    result,
    shownDomain,
    canonical,
    methodologyHref,
    t: (key, values) => t(key, values),
    reason: (key) => reasons[key] ?? key,
    advisory,
  });
  return <CheckResultCard {...card} />;
}
