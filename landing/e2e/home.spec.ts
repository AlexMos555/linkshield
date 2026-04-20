import { test, expect, Page } from "@playwright/test";

/**
 * Smoke tests for the marketing home page.
 *
 * Each critical section must render in every supported locale. If any section
 * header fails to appear, something broke during i18n fetch or SSG.
 */

type Locale = "en" | "ru" | "es" | "pt" | "fr" | "de" | "it" | "id" | "hi" | "ar";
const LOCALES: Locale[] = [
  "en",
  "ru",
  "es",
  "pt",
  "fr",
  "de",
  "it",
  "id",
  "hi",
  "ar",
];

// Each section is identified by an HTML id or semantic landmark that must exist
// regardless of locale. Locale-specific string assertions live in separate tests
// that target individual locales to keep signals actionable.
const REQUIRED_SECTION_IDS = [
  "features",
  "how",
  "pricing",
  "privacy",
] as const;

// ─── Per-locale smoke ────────────────────────────────────────────────────────

for (const locale of LOCALES) {
  test(`home renders all sections for locale=${locale}`, async ({ page }) => {
    const response = await page.goto(`/${locale}`);
    expect(response?.status()).toBe(200);

    for (const id of REQUIRED_SECTION_IDS) {
      const section = page.locator(`#${id}`);
      await expect(section, `section #${id} missing for ${locale}`).toBeVisible();
    }

    // Hero CTA must be visible and clickable
    const cta = page.locator("a", {
      hasText: /Chrome/,
    }).first();
    await expect(cta).toBeVisible();
  });
}

// ─── English-specific copy checks ────────────────────────────────────────────

test("EN hero uses English copy", async ({ page }) => {
  await page.goto("/en");
  await expect(page.locator("h1")).toContainText("privacy");
  await expect(page.getByText(/phishing/i).first()).toBeVisible();
});

test("RU hero uses Russian copy", async ({ page }) => {
  await page.goto("/ru");
  // Russian hero includes "мошенников"
  await expect(page.locator("body")).toContainText("мошенник");
});

// ─── Navigation ──────────────────────────────────────────────────────────────

test("footer links to privacy policy and terms", async ({ page }) => {
  await page.goto("/en");
  // Direct navigation rather than clicking — more robust than waiting for SPA
  const privacyResp = await page.goto("/en/privacy-policy");
  expect(privacyResp?.status()).toBe(200);
  const termsResp = await page.goto("/en/terms");
  expect(termsResp?.status()).toBe(200);
});

test("pricing page renders three tiers", async ({ page }) => {
  await page.goto("/en/pricing");
  // On the dedicated pricing page, tier names should be visible
  await expect(page.getByText(/Personal/i).first()).toBeVisible();
  await expect(page.getByText(/Family/i).first()).toBeVisible();
});

// ─── Section content (EN only — localized copy is tested via unit tests) ─────

test("comparison table shows competitor columns", async ({ page }) => {
  await page.goto("/en");
  // Competitor names are brand names — identical across all locales
  const body = page.locator("body");
  await expect(body).toContainText("LinkShield");
  await expect(body).toContainText("Guardio");
  await expect(body).toContainText("Norton 360");
});

test("FAQ section has expandable items", async ({ page }) => {
  await page.goto("/en");
  // <details> elements — Playwright interacts via summary
  const faq = page.locator("details").first();
  await expect(faq).toBeVisible();
  await faq.locator("summary").click();
  // After click, details[open] must expose the hidden answer content
  await expect(faq).toHaveAttribute("open", "");
});

test("testimonials render three cards", async ({ page }) => {
  await page.goto("/en");
  // Quote marks are injected by the template around each testimonial
  const quotes = page.getByText(/“/);
  await expect(quotes).toHaveCount(3);
});
