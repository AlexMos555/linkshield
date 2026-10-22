import { expect, test } from "@playwright/test";

/**
 * Guards for the launch pages' load performance (mobile LCP/INP).
 *
 * The Sentry browser SDK used to ship eagerly on every page — 171 KB gzip of
 * the 281 KB total — and the hero faded in from opacity 0, so the largest
 * paint waited for the animation. Both regressions are easy to reintroduce
 * with one import or one class name.
 */

// Compressed JavaScript fetched by the time the page has loaded. Today ≈ 120 KB
// for the home page; the old eager-Sentry build was ≈ 300 KB.
const JS_BUDGET_BYTES = 170_000;

for (const path of ["/", "/ru", "/ru/pricing", "/ru/check/google.com"]) {
  test(`${path}: JavaScript at load stays within ${JS_BUDGET_BYTES / 1000} KB compressed`, async ({ page }) => {
    await page.goto(path, { waitUntil: "load" });
    const scripts = await page.evaluate(() =>
      performance
        .getEntriesByType("resource")
        .filter((e) => (e as PerformanceResourceTiming).initiatorType === "script")
        .map((e) => ({ name: e.name, bytes: (e as PerformanceResourceTiming).encodedBodySize })),
    );
    const total = scripts.reduce((sum, s) => sum + s.bytes, 0);
    expect(total, JSON.stringify(scripts.map((s) => `${s.name.split("/").pop()}: ${s.bytes}`))).toBeLessThan(JS_BUDGET_BYTES);
  });
}

test("the hero is visible on first paint (no fade-in from opacity 0)", async ({ page }) => {
  await page.goto("/ru", { waitUntil: "commit" });
  const h1 = page.locator("h1").first();
  await h1.waitFor();
  const opacities = await h1.evaluate((el) => {
    const out: string[] = [];
    for (let node: Element | null = el; node; node = node.parentElement) out.push(getComputedStyle(node).opacity);
    return out;
  });
  expect(opacities.every((o) => o === "1"), opacities.join(",")).toBe(true);
});
