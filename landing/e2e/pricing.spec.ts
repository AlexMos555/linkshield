import { test, expect } from "@playwright/test";

/**
 * /pricing for the world (the Stripe variant): one device plan next to Free
 * (docs/ACCOUNTS_BILLING_PLAN.md §5). Prices come from the API; when it is
 * unreachable or still serves the pre-device-plan shape, the page shows the
 * base tier (lib/world-pricing.ts) — the same numbers a visitor without a
 * country gets from the API. Either way: $0.99 a month, $9.99 a year, +$0.49
 * a month per extra device. Same page in both billing-flag states.
 */

test("yearly is pre-selected and says how many months it saves", async ({ page }) => {
  await page.goto("/pricing");
  await expect(page.getByTestId("world-pricing")).toBeVisible();
  await expect(page.getByTestId("interval-yearly")).toHaveAttribute("aria-checked", "true");
  await expect(page.getByTestId("yearly-saving")).toHaveText("≈ 2 months free");
  const price = page.getByTestId("plan-price");
  await expect(price).toContainText("$9.99");
  await expect(price).toContainText("/year");
  await expect(page.getByTestId("plan-card-unlimited")).toContainText("≈ $0.83 a month, billed once a year");
  await expect(page.getByTestId("plan-extra-device")).toContainText("+$4.99 a year");
});

test("monthly shows the monthly price and the extra device per month", async ({ page }) => {
  await page.goto("/pricing");
  await page.getByTestId("interval-monthly").click();
  await expect(page.getByTestId("interval-monthly")).toHaveAttribute("aria-checked", "true");
  const price = page.getByTestId("plan-price");
  await expect(price).toContainText("$0.99");
  await expect(price).toContainText("/month");
  await expect(page.getByTestId("plan-extra-device")).toContainText("+$0.49 a month");
});

test("?interval=monthly after sign-up keeps the visitor's choice", async ({ page }) => {
  await page.goto("/pricing?plan=devices&interval=monthly");
  await expect(page.getByTestId("interval-monthly")).toHaveAttribute("aria-checked", "true");
});

test("the cards say what is free and what the plan adds — in devices", async ({ page }) => {
  await page.goto("/pricing");
  const free = page.getByTestId("plan-card-free");
  await expect(free).toContainText("Blocks known scam sites from our list — no limit");
  await expect(free).toContainText("3 detailed checks a day");
  await expect(free).toContainText("first 7 days after install");
  const plan = page.getByTestId("plan-card-unlimited");
  await expect(plan).toContainText("3 devices on one account");
  await expect(plan).toContainText("Get Unlimited");
});

test("the FAQ answers devices, unlinking, the free plan, refunds and cancelling", async ({ page }) => {
  await page.goto("/pricing");
  const faq = page.getByTestId("pricing-faq");
  for (const question of [
    "What counts as a device?",
    "How do I free up a device?",
    "What do I get without paying?",
    "Can I get my money back?",
    "Can I cancel at any time?",
  ]) {
    await expect(faq).toContainText(question);
  }
  // The tier was never detected from a Stripe billing country — the old FAQ said so.
  await expect(page.locator("body")).not.toContainText(/billing country/i);
});

test("the page is translated — /de/pricing has no English plan copy", async ({ page }) => {
  await page.goto("/de/pricing");
  await expect(page.getByTestId("world-pricing")).toBeVisible();
  await expect(page.getByTestId("plan-card-unlimited")).not.toContainText("Get Unlimited");
  await expect(page.getByTestId("pricing-faq")).not.toContainText("What counts as a device?");
});
