import { test, expect } from "@playwright/test";

/**
 * Mobile-viewport smoke — verifies the nav collapses to the mobile "Install"
 * variant instead of the full desktop row, and that key sections still render
 * without horizontal scroll.
 */

test("mobile nav shows compact install button", async ({ page }) => {
  await page.goto("/en");
  // Target the mobile-only wrapper directly (``md:hidden``) so we don't race
  // with Tailwind breakpoint evaluation in headless browsers. The button
  // inside it renders the ``nav.install_short`` translation key.
  const mobileWrapper = page.locator("nav div.md\\:hidden").first();
  await expect(mobileWrapper).toBeVisible();
  await expect(mobileWrapper.getByText(/^Install$/)).toBeVisible();
});

test("mobile viewport does not horizontally scroll", async ({ page }) => {
  await page.goto("/en");
  // Check actual scrollability rather than intrinsic content width:
  // globals.css uses overflow-x: clip so users cannot scroll horizontally
  // even when a child element (e.g. a wide hero headline) intrinsically
  // reports scrollWidth > innerWidth. The user-facing guarantee is what
  // the test should assert.
  const canScrollHoriz = await page.evaluate(() => {
    const before = window.scrollX;
    window.scrollTo(2000, 0);
    const after = window.scrollX;
    window.scrollTo(0, 0);
    return after > before;
  });
  expect(canScrollHoriz).toBe(false);
});

test("mobile hero still renders", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator("h1")).toBeVisible();
});
