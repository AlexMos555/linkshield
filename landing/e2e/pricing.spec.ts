import { test, expect, type Page } from "@playwright/test";

import { STRIPE_LIVE } from "./billing-flag";

// The API the page calls from the browser.
const API = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

/**
 * /pricing for the world (the Stripe variant): one device plan next to Free
 * (docs/ACCOUNTS_BILLING_PLAN.md §5). Prices come from the API; when it is
 * unreachable or still serves the pre-device-plan shape, the page shows the
 * base tier (lib/world-pricing.ts) — the same numbers a visitor without a
 * country gets from the API. Either way: $0.99 a month, $9.99 a year, +$0.49
 * a month per extra device. Same page in both billing-flag states.
 *
 * Only while Stripe checkout is live (NEXT_PUBLIC_STRIPE_LIVE, inlined at build
 * time): until then the world gets the free page — no plan cards, no buy
 * button that would end in an error, no Offer for search engines.
 */

/** Every "@type" in the page's JSON-LD, nested ones included. */
async function jsonLdTypes(page: Page): Promise<string[]> {
  const blocks = await page.$$eval('script[type="application/ld+json"]', (scripts) =>
    scripts.map((s) => s.textContent ?? ""),
  );
  return blocks.flatMap((text) => [...text.matchAll(/"@type"\s*:\s*"([^"]+)"/g)].map((m) => m[1]));
}

test.describe("Stripe checkout not live — the free page", () => {
  test.skip(STRIPE_LIVE, "NEXT_PUBLIC_STRIPE_LIVE is on");

  for (const path of ["/pricing", "/de/pricing", "/pricing?cc=US"]) {
    test(`${path} sells nothing it cannot take payment for`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByTestId("free-pricing")).toBeVisible();
      await expect(page.getByTestId("world-pricing")).toHaveCount(0);
      await expect(page.getByTestId("operator-pricing")).toHaveCount(0);
      await expect(page.getByTestId("plan-checkout")).toHaveCount(0);
      await expect(page.locator("body")).not.toContainText(/\$\d/);
      expect(await jsonLdTypes(page)).not.toContain("Offer");
    });
  }
});

test.describe("Stripe checkout live — the device plan", () => {
  test.skip(!STRIPE_LIVE, "NEXT_PUBLIC_STRIPE_LIVE is off");

  test("search engines get the plan's Offers at the shown prices", async ({ page }) => {
    await page.goto("/pricing");
    const types = await jsonLdTypes(page);
    expect(types).toContain("AggregateOffer");
    expect(types).toContain("Offer");
  });

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

  test("signed out: Get Unlimited goes to sign-up with the plan, return URLs in the reader's language", async ({ page }) => {
    const sent: Array<Record<string, unknown>> = [];
    await page.route(`${API}/api/v1/payments/checkout`, async (route) => {
      const cors = {
        "access-control-allow-origin": new URL(page.url()).origin,
        "access-control-allow-credentials": "true",
        "access-control-allow-headers": "authorization, content-type",
        "access-control-allow-methods": "POST, OPTIONS",
      };
      if (route.request().method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers: cors, body: "" });
        return;
      }
      sent.push(route.request().postDataJSON() as Record<string, unknown>);
      await route.fulfill({ status: 401, headers: cors, contentType: "application/json", body: '{"detail":"sign in"}' });
    });
    await page.goto("/de/pricing");
    await page.getByTestId("plan-checkout").click();
    await page.waitForURL(/\/de\/signup\?/);
    const query = new URL(page.url()).searchParams;
    expect(query.get("plan")).toBe("devices");
    expect(query.get("interval")).toBe("yearly");
    await expect(page.getByTestId("signup-plan")).toBeVisible();
    // Bare success URL (the API adds ?session_id= once), both on the reader's locale.
    expect(sent[0]).toMatchObject({
      plan: "devices_yearly",
      success_url: "https://cleanway.ai/de/success",
      cancel_url: "https://cleanway.ai/de/pricing",
    });
  });
});

// /signup?plan=devices is where a signed-out buyer lands from /pricing; it used
// to drop "devices" (an unknown plan) and send the buyer to the home page after
// sign-in instead of back to checkout. Same page in every flag state.
test("/signup?plan=devices names the plan the buyer chose", async ({ page }) => {
  await page.goto("/signup?plan=devices&interval=monthly");
  await expect(page.getByTestId("signup-plan")).toContainText("Unlimited plan · monthly");
  await page.goto("/ru/signup?plan=devices&interval=yearly");
  await expect(page.getByTestId("signup-plan")).toContainText("Тариф Без ограничений · на год");
  await page.goto("/signup?plan=enterprise");
  await expect(page.getByTestId("signup-plan")).toHaveCount(0);
});
