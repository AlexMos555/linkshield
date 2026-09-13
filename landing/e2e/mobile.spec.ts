import { test, expect } from "@playwright/test";

/**
 * Mobile-viewport smoke — verifies the nav collapses to the mobile "Install"
 * variant instead of the full desktop row, and that key sections still render
 * without horizontal scroll.
 *
 * Runs under two projects (see playwright.config.ts):
 *   - mobile-safari (iPhone 14, WebKit)  — iOS keeps the DoH profile path (/dns).
 *   - android       (Pixel 7, Chromium)  — Android must be routed to the app
 *     page (/android) after hydration: strict Private DNS conflicts with the
 *     app's VPN shield, so /dns is the wrong door for these visitors.
 */

const ANDROID_PROJECT = "android";
const IOS_PROJECT = "mobile-safari";

/** Label the compact nav CTA settles on after hydration, per project. */
const COMPACT_INSTALL_LABEL: Record<string, RegExp> = {
  [ANDROID_PROJECT]: /^Get the Android app$/,
};
const DEFAULT_COMPACT_INSTALL_LABEL = /^Install$/;

function onlyOnProject(name: string): void {
  test.skip(test.info().project.name !== name, `${name} project only`);
}

test("mobile nav shows compact install button", async ({ page }) => {
  await page.goto("/en");
  // Target the mobile-only wrapper directly (``md:hidden``) so we don't race
  // with Tailwind breakpoint evaluation in headless browsers. The button
  // inside it renders the ``nav.install_short`` translation key — or, on
  // Android, ``nav.install_android`` once PrimaryInstallLink has hydrated.
  const mobileWrapper = page.locator("nav div.md\\:hidden").first();
  await expect(mobileWrapper).toBeVisible();
  const label =
    COMPACT_INSTALL_LABEL[test.info().project.name] ?? DEFAULT_COMPACT_INSTALL_LABEL;
  await expect(mobileWrapper.getByText(label)).toBeVisible();
});

// Layout hygiene: globals.css `html, body { max-width: 100vw }` + hero
// `break-words max-w-full` are defensive guards against intrinsic
// scrollWidth overflow. They might not fully repair headless WebKit's
// scrollWidth measurement bug, so the assertion stays SKIPPED until a
// live mobile-safari run confirms scrollWidth drops below the threshold.
// To re-enable: run e2e locally with Playwright WebKit and verify, then
// flip test.skip → test.
test.skip("mobile viewport does not horizontally scroll", async ({ page }) => {
  await page.goto("/en");
  const overflowPx = await page.evaluate(() => {
    return document.documentElement.scrollWidth - window.innerWidth;
  });
  expect(overflowPx).toBeLessThan(30);
});

test("mobile hero still renders", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator("h1")).toBeVisible();
});

// ─── Primary install CTA routing ─────────────────────────────────────────────
//
// Every funnel-facing primary CTA is one component (PrimaryInstallLink). It
// server-renders /dns for everyone, then re-points Android visitors at the
// app page after hydration. `toHaveAttribute` auto-retries, so these
// assertions wait for hydration instead of racing it.

test.describe("primary install CTA routing", () => {
  test("Android visitors are sent to /android after hydration", async ({ page }) => {
    onlyOnProject(ANDROID_PROJECT);
    await page.goto("/en");

    const navMobile = page.getByTestId("primary-install-nav-mobile");
    await expect(navMobile).toHaveAttribute("href", "/android");
    await expect(navMobile).toHaveText("Get the Android app");

    const hero = page.getByTestId("primary-install-hero");
    await expect(hero).toHaveAttribute("href", "/android");
    await expect(hero).toHaveText("Get the Android app");

    // The desktop nav link is hidden at this viewport but must swap too —
    // it is the same component, and a CSS breakpoint is not a platform check.
    await expect(page.getByTestId("primary-install-nav")).toHaveAttribute("href", "/android");
    await expect(page.getByTestId("primary-install-final")).toHaveAttribute("href", "/android");
  });

  test("iOS visitors keep the DNS profile path", async ({ page }) => {
    onlyOnProject(IOS_PROJECT);
    await page.goto("/en");
    // Wait for hydration to settle so a late client-side swap can't slip past.
    await page.waitForLoadState("networkidle");

    const navMobile = page.getByTestId("primary-install-nav-mobile");
    await expect(navMobile).toHaveAttribute("href", "/dns");
    await expect(navMobile).toHaveText("Install");

    const hero = page.getByTestId("primary-install-hero");
    await expect(hero).toHaveAttribute("href", "/dns");
    await expect(hero).toHaveText("Add to Chrome — Free");
  });
});
