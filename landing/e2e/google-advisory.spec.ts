import { test, expect } from "@playwright/test";

/**
 * Google Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-03): a verdict about a site Google lists carries
 * "Advisory provided by Google" linked to the Web Risk Advisory, and lets the
 * reader learn more (antiphishing.org for phishing, Google Search Central for
 * malware). A verdict built only on other sources must not carry Google's
 * name. The verdicts come from e2e/mock-api.mjs: google-flagged.example has
 * Google's reason code (safe_browsing), bank-verify-login.example does not.
 */

const ADVISORY = "https://docs.cloud.google.com/web-risk/docs/advisory";
const PHISHING = "https://www.antiphishing.org/";
const MALWARE = "https://developers.google.com/search/docs/advanced/security/malware";

test("a Google verdict on /check credits Google and links the advisory and learn-more pages", async ({ page }) => {
  await page.goto("/check/google-flagged.example");
  const advisory = page.getByTestId("google-advisory");
  await expect(advisory).toBeVisible();
  await expect(advisory.getByRole("link", { name: "Advisory provided by Google" })).toHaveAttribute("href", ADVISORY);
  await expect(advisory.getByRole("link", { name: "phishing" })).toHaveAttribute("href", PHISHING);
  await expect(advisory.getByRole("link", { name: "malware" })).toHaveAttribute("href", MALWARE);
  for (const link of await advisory.getByRole("link").all()) {
    await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  }
  // Google's own reason line is a suspicion, not a certainty.
  await expect(page.getByTestId("check-result")).toContainText("may be dangerous");
});

test("the Russian page credits Google in Russian, with the same links", async ({ page }) => {
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
