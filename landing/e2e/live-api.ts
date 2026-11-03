import type { Page } from "@playwright/test";

/**
 * A /check verdict resting on Google's lists is fetched live by the browser
 * (components/LiveCheckResult.tsx) from the API it knows, api.cleanway.ai —
 * the cached page never carries one (Web Risk allows a warning only while
 * Google's answer is valid). A test must never reach the production API, so
 * those requests are answered by e2e/mock-api.mjs, the server the page's own
 * render reads (playwright.config.ts). `answer` overrides the mock for a host.
 */
const MOCK_API_URL = `http://127.0.0.1:${Number(process.env.MOCK_API_PORT || 3999)}`;

export async function routeLiveChecks(
  page: Page,
  answer: Record<string, unknown> = {},
): Promise<string[]> {
  const seen: string[] = [];
  await page.route("https://api.cleanway.ai/**", async (route) => {
    const url = new URL(route.request().url());
    seen.push(url.pathname);
    const host = decodeURIComponent(url.pathname.split("/").pop() || "");
    const cors = { "access-control-allow-origin": "*" };
    if (host in answer) {
      await route.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify(answer[host]) });
      return;
    }
    const response = await route.fetch({ url: MOCK_API_URL + url.pathname });
    await route.fulfill({ response, headers: { ...response.headers(), ...cors } });
  });
  return seen;
}
