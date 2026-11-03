import { test, expect } from "@playwright/test";

import { routeLiveChecks } from "./live-api";

/**
 * Google Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-04): a verdict about a site Google lists carries
 * "Advisory provided by Google" linked to the Web Risk Advisory, and lets the
 * reader learn more about each threat type (antiphishing.org for phishing,
 * Google Search Central for malware, Google's policy for unwanted software).
 * A verdict built only on other sources must not carry Google's name. And a
 * warning may be shown only while Google's answer is valid: the cached page
 * never carries a Google verdict, the browser fetches it live.
 * The verdicts come from e2e/mock-api.mjs (through e2e/live-api.ts for the
 * browser's own request): google-flagged.example has Google's reason code
 * (safe_browsing), bank-verify-login.example does not.
 */

const ADVISORY = "https://docs.cloud.google.com/web-risk/docs/advisory";
const PHISHING = "https://www.antiphishing.org/";
const MALWARE = "https://developers.google.com/search/docs/advanced/security/malware";
const UNWANTED = "https://www.google.com/about/company/unwanted-software-policy.html";

test("a Google verdict on /check credits Google and links the advisory and learn-more pages", async ({ page }) => {
  const live = await routeLiveChecks(page);
  await page.goto("/check/google-flagged.example");
  const advisory = page.getByTestId("google-advisory");
  await expect(advisory).toBeVisible();
  await expect(advisory.getByRole("link", { name: "Advisory provided by Google" })).toHaveAttribute("href", ADVISORY);
  await expect(advisory.getByRole("link", { name: "phishing" })).toHaveAttribute("href", PHISHING);
  await expect(advisory.getByRole("link", { name: "malware" })).toHaveAttribute("href", MALWARE);
  await expect(advisory.getByRole("link", { name: "unwanted software" })).toHaveAttribute("href", UNWANTED);
  for (const link of await advisory.getByRole("link").all()) {
    await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  }
  // Google's own reason line is a suspicion, not a certainty.
  await expect(page.getByTestId("check-result")).toContainText("may be dangerous");
  expect(live).toContain("/api/v1/public/check/google-flagged.example");
});

test("the cached page carries no Google verdict: not in its HTML, not in its JSON-LD", async ({ request }) => {
  const html = await (await request.get("/check/google-flagged.example")).text();
  expect(html).not.toContain('data-testid="google-advisory"');
  expect(html).not.toContain('"@type":"Review"');
  // The other verdicts are rendered and described as before.
  const other = await (await request.get("/check/bank-verify-login.example")).text();
  expect(other).toContain('"@type":"Review"');
});

test("the live answer wins: once Google no longer lists the site, the page says what the API says now", async ({ page }) => {
  await routeLiveChecks(page, {
    "google-flagged.example": { domain: "google-flagged.example", level: "safe", score: 4, signals: [], reason_codes: [], confidence: "high", confidence_pct: 90, advisory_ttl: null },
  });
  await page.goto("/check/google-flagged.example");
  await expect(page.getByTestId("check-result")).toContainText("Looks safe");
  await expect(page.getByTestId("google-advisory")).toHaveCount(0);
});

test("the Russian page credits Google in Russian, with the same links", async ({ page }) => {
  await routeLiveChecks(page);
  await page.goto("/ru/check/google-flagged.example");
  const advisory = page.getByTestId("google-advisory");
  await expect(advisory).toContainText("Google");
  await expect(advisory.getByRole("link").first()).toHaveAttribute("href", ADVISORY);
  await expect(advisory).not.toContainText("Advisory provided by Google");
});

test("a verdict on other sources carries no Google credit", async ({ page }) => {
  await page.goto("/check/bank-verify-login.example");
  await expect(page.getByTestId("check-result")).toBeVisible();
  await expect(page.getByTestId("google-advisory")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("Advisory provided by Google");
});
