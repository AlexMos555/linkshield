import AxeBuilder from "@axe-core/playwright";
import { test, expect, type Page } from "@playwright/test";

/**
 * Accessibility: axe-core (WCAG 2.0/2.1/2.2 A + AA rules) on the pages people
 * land on. Many of our users are older and use large text, a screen reader or
 * the keyboard; a "serious" or "critical" axe finding there means a control
 * they cannot name, reach or read. Those fail the build. Lesser findings are
 * printed so they stay visible without blocking.
 *
 * /check/<domain> is answered by e2e/mock-api.mjs (see playwright.config.ts),
 * so the verdict pages render without calling the production API.
 */

const PAGES = [
  "/",
  "/ru",
  "/ar",
  "/check/example.com",
  "/check/bank-verify-login.example",
  "/ru/check/bank-verify-login.example",
  "/pricing",
  "/privacy-policy",
  "/signup",
  "/delete-account",
  "/support",
] as const;

const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const BLOCKING = new Set(["serious", "critical"]);

async function audit(page: Page) {
  return new AxeBuilder({ page })
    .withTags(WCAG_TAGS)
    // Next's dev-mode overlay is not part of the shipped page.
    .exclude("nextjs-portal")
    .analyze();
}

for (const path of PAGES) {
  test(`a11y: no serious or critical axe violations on ${path}`, async ({ page }) => {
    // Reduced motion: audit the settled page, not a fade-in mid-flight
    // (and it is how many of our users browse).
    await page.emulateMedia({ reducedMotion: "reduce" });
    const response = await page.goto(path);
    expect(response?.status(), `${path} did not load`).toBe(200);
    await page.waitForLoadState("networkidle");

    const { violations } = await audit(page);

    const minor = violations.filter((v) => !BLOCKING.has(v.impact ?? ""));
    if (minor.length) {
      console.log(
        `[a11y] ${path}: non-blocking — ` +
          minor.map((v) => `${v.id} (${v.impact}, ${v.nodes.length})`).join(", "),
      );
    }

    const blocking = violations
      .filter((v) => BLOCKING.has(v.impact ?? ""))
      .map((v) => ({
        rule: v.id,
        impact: v.impact,
        help: v.help,
        nodes: v.nodes.slice(0, 5).map((n) => `${n.target.join(" ")} — ${n.failureSummary ?? ""}`),
      }));
    expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
  });
}

test("a11y: pages declare their language (and Arabic is right-to-left)", async ({ page }) => {
  for (const [path, lang, dir] of [
    ["/", "en", "ltr"],
    ["/ru", "ru", "ltr"],
    ["/ar", "ar", "rtl"],
  ] as const) {
    await page.goto(path);
    const html = page.locator("html");
    await expect(html, path).toHaveAttribute("lang", lang);
    expect((await html.getAttribute("dir")) ?? "ltr", path).toBe(dir);
  }
});

test("a11y: keyboard users get a visible focus ring", async ({ page }) => {
  await page.goto("/");
  // Tab to the first focusable thing; whatever it is, it must show focus.
  await page.keyboard.press("Tab");
  const outline = await page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return null;
    const style = getComputedStyle(el);
    return { width: parseFloat(style.outlineWidth), style: style.outlineStyle, shadow: style.boxShadow };
  });
  expect(outline, "Tab did not focus anything").not.toBeNull();
  const visible =
    (outline!.style !== "none" && outline!.width > 0) || (outline!.shadow && outline!.shadow !== "none");
  expect(visible, `focused element has no visible focus style: ${JSON.stringify(outline)}`).toBeTruthy();
});
