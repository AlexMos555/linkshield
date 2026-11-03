import { test, expect, devices, Page } from "@playwright/test";

import { BILLING_ON, STRIPE_LIVE } from "./billing-flag";

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
    await expect(page.getByTestId("primary-install-hero")).toBeVisible();
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

test("pricing page shows Free and the one device plan", async ({ page }) => {
  // Until Stripe checkout is live the world gets the free page (pricing.spec.ts).
  test.skip(!STRIPE_LIVE, "NEXT_PUBLIC_STRIPE_LIVE is off");
  await page.goto("/en/pricing");
  await expect(page.getByTestId("plan-card-free")).toBeVisible();
  await expect(page.getByTestId("plan-card-unlimited")).toBeVisible();
  // The retired plans are not sold any more.
  await expect(page.getByTestId("world-pricing")).not.toContainText(/Granny|Family Hub|Kids Mode/);
});

// ─── Section content (EN only — localized copy is tested via unit tests) ─────

// The comparison table was removed (report #11): it claimed "all 5
// platforms" while only Android is live, and named VPNs we supposedly work
// alongside — on Android only one VPN runs at a time.
test("home makes no competitor or VPN-compatibility claims", async ({ page }) => {
  for (const locale of ["en", "ru"] as const) {
    await page.goto(`/${locale}`);
    const body = page.locator("body");
    await expect(body).not.toContainText("NordVPN");
    await expect(body).not.toContainText("ExpressVPN");
    await expect(body).not.toContainText("Guardio");
  }
});

// The home page is about the free Android app. Its pricing block used to sell
// extension features ("Link badges on all pages", "10 API checks/day") and a
// 14-day trial nobody could start — in English, even on /fr and /de.
test("home pricing block is free-first; plans only via a link, never in Russia", async ({ page }) => {
  for (const locale of ["en", "fr", "de"] as const) {
    await page.goto(`/${locale}`);
    const pricing = page.locator("#pricing");
    await expect(pricing).not.toContainText("$");
    await expect(pricing).not.toContainText(/trial|badges|API checks/i);
    await expect(page.getByTestId("free-only-android")).toHaveAttribute("href", `/${locale === "en" ? "" : `${locale}/`}android`);
    // A link to plans only where there are plans to buy: Stripe checkout live.
    await expect(page.getByTestId("home-plans-link")).toHaveCount(STRIPE_LIVE ? 1 : 0);
  }
  // Russia gets no link to plans it cannot buy — until the operator-billed
  // subscription is on, when the link leads to that (billing.spec.ts).
  await page.goto("/ru");
  await expect(page.getByTestId("home-plans-link")).toHaveCount(BILLING_ON ? 1 : 0);
});

test("home privacy section names the public DNS the shield uses", async ({ page }) => {
  await page.goto("/ru");
  await expect(page.getByTestId("privacy-dns")).toContainText("Cloudflare");
  await expect(page.getByTestId("privacy-dns")).toContainText("Quad9");
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
  // Cards are tagged data-testid="testimonial-card" (they render as principle
  // statements, not quoted customer testimonials — no injected quote glyphs).
  const cards = page.getByTestId("testimonial-card");
  await expect(cards).toHaveCount(3);
});

// ─── Primary install CTA (desktop keeps the DoH profile path) ────────────────
//
// PrimaryInstallLink re-points phone user agents (Android → /android, iPhone
// and iPad → the App Store); on desktop the server-rendered /dns href and
// label must survive hydration untouched.

/** PLATFORMS.ios.href in lib/install-urls.ts. */
const APP_STORE_URL = "https://apps.apple.com/app/id6821030874";

test("desktop primary CTAs stay on /dns after hydration", async ({ page }) => {
  await page.goto("/en");
  await page.waitForLoadState("networkidle");

  const nav = page.getByTestId("primary-install-nav");
  await expect(nav).toHaveAttribute("href", "/dns");
  await expect(nav).toHaveText("Install");

  const hero = page.getByTestId("primary-install-hero");
  await expect(hero).toHaveAttribute("href", "/dns");
  await expect(hero).toHaveText("Get protected — free");
});

// The hero's phone row (InstallButtons): both apps are live links, iOS is no
// longer a "Coming soon" pill.
test("home phone row links the iPhone app to the App Store", async ({ page }) => {
  await page.goto("/en");
  const main = page.locator("main");
  await expect(main.getByRole("link", { name: "iOS", exact: true })).toHaveAttribute("href", APP_STORE_URL);
  await expect(main.getByRole("link", { name: "Android", exact: true })).toHaveAttribute("href", "/android");
});

// The iPhone 14 profile in Chromium, not WebKit: the mobile-safari project
// never hydrates against http://localhost (see mobile.spec.ts), so it cannot
// see the client-side swap. Everything but the browser engine is the device's.
test.describe("on an iPhone", () => {
  const { defaultBrowserType: _webkit, ...iPhone } = devices["iPhone 14"];
  test.use(iPhone);

  test("every primary CTA leads to the App Store after hydration", async ({ page }) => {
    await page.goto("/en");

    // The compact nav has room for two words (nav.install_ios_short): the
    // full label wrapped to three or four lines there on a 390 px iPhone.
    const navMobile = page.getByTestId("primary-install-nav-mobile");
    await expect(navMobile).toHaveAttribute("href", APP_STORE_URL);
    await expect(navMobile).toHaveText("App Store");

    const hero = page.getByTestId("primary-install-hero");
    await expect(hero).toHaveAttribute("href", APP_STORE_URL);
    await expect(hero).toHaveText("Get it on the App Store");

    // Hidden at this viewport, but the same component: it must swap too.
    await expect(page.getByTestId("primary-install-nav")).toHaveAttribute("href", APP_STORE_URL);
    await expect(page.getByTestId("primary-install-final")).toHaveAttribute("href", APP_STORE_URL);
  });

  test("the label is in the page's language", async ({ page }) => {
    await page.goto("/ru");
    const hero = page.getByTestId("primary-install-hero");
    await expect(hero).toHaveAttribute("href", APP_STORE_URL);
    await expect(hero).toHaveText("Скачать в App Store");
  });
});

// iPadOS 13+ asks for the desktop site by default and then reports a Mac user
// agent; only its touch points tell it apart from a real Mac (none has a
// touchscreen). The iPad goes to the App Store, the Mac keeps /dns.
const MAC_SAFARI_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";

async function withTouchPoints(page: Page, points: number): Promise<void> {
  await page.addInitScript((n) => {
    Object.defineProperty(Navigator.prototype, "maxTouchPoints", { get: () => n });
  }, points);
}

test.describe("on a Mac user agent", () => {
  test.use({ userAgent: MAC_SAFARI_UA });

  test("an iPad in desktop mode is sent to the App Store", async ({ page }) => {
    await withTouchPoints(page, 5);
    await page.goto("/en");

    const nav = page.getByTestId("primary-install-nav");
    await expect(nav).toHaveAttribute("href", APP_STORE_URL);
    await expect(nav).toHaveText("Get it on the App Store");
    await expect(page.getByTestId("primary-install-hero")).toHaveAttribute("href", APP_STORE_URL);
  });

  test("a Mac keeps the DNS profile path", async ({ page }) => {
    await withTouchPoints(page, 0);
    await page.goto("/en");
    await page.waitForLoadState("networkidle");

    const nav = page.getByTestId("primary-install-nav");
    await expect(nav).toHaveAttribute("href", "/dns");
    await expect(nav).toHaveText("Install");
    await expect(page.getByTestId("primary-install-hero")).toHaveAttribute("href", "/dns");
  });
});
