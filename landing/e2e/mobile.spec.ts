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
  // Catches real multi-hundred-px layout regressions on mobile widths while
  // tolerating sub-pixel rendering jitter that webkit's mobile-safari
  // emulation reports (globals.css uses overflow-x: clip, so users can't
  // visibly scroll either way — but scrollWidth still reports a few pixels
  // of intrinsic overflow from text rendering).
  const overflowPx = await page.evaluate(() => {
    return document.documentElement.scrollWidth - window.innerWidth;
  });
  expect(overflowPx).toBeLessThan(30);
});

test("mobile hero still renders", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator("h1")).toBeVisible();
});
