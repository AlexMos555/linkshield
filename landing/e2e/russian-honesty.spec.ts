import { test, expect } from "@playwright/test";

/**
 * The Russian pages a Tele2 subscriber actually lands on must be in Russian
 * and must not promise what the product doesn't do (report items #11–#13,
 * #15, #19 of the 2026-09-25 service check). String-level rules live in
 * scripts/check-landing-claims.py; these check the rendered pages.
 *
 * No test here renders /check/<domain>: that page calls the production API,
 * which is rate-limited per IP. The /check tests stop at the redirect or
 * answer the navigation themselves (page.route), so nothing reaches the API.
 */

/** Cloudflare's always-pass test sitekey — lib/turnstile.ts TURNSTILE_TEST_SITE_KEY. */
const TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA";
const PASTED_LINK = "bank-verify.ru/confirm?email=me@x.ru";

test("/ru/android walks through the scary warnings and links policy + support", async ({ page }) => {
  const response = await page.goto("/ru/android");
  expect(response?.status()).toBe(200);

  for (const slot of ["chrome-download-warning", "samsung-auto-blocker", "play-protect-warning"]) {
    await expect(page.getByTestId(`install-warning-${slot}`)).toBeVisible();
  }
  await expect(page.getByTestId("never-calls")).toContainText("никогда не присылает ссылки в SMS");
  await expect(page.locator('a[href="/ru/privacy-policy"]')).toBeVisible();
  await expect(page.locator('a[href="/ru/support"]')).toBeVisible();

  const body = page.locator("body");
  await expect(body).not.toContainText("ничего не узна");
  await expect(body).not.toContainText("RuStore и Google Play");
});

test("/ru/android link preview is Russian and has no Chrome button image", async ({ page }) => {
  await page.goto("/ru/android");
  const ogTitle = await page.locator('meta[property="og:title"]').getAttribute("content");
  const ogDescription = await page.locator('meta[property="og:description"]').getAttribute("content");
  expect(ogTitle).toContain("Cleanway для Android");
  expect(ogDescription).toMatch(/мошеннические/);
  expect(`${ogTitle} ${ogDescription}`).not.toMatch(/Chrome|your device/i);
});

test("/ru/pricing is free-only: no prices, no paid plans", async ({ page }) => {
  await page.goto("/ru/pricing");
  await expect(page.getByTestId("free-pricing")).toBeVisible();
  const body = page.locator("body");
  await expect(body).not.toContainText("$");
  await expect(body).not.toContainText("Personal");
});

test("/ru/transparency shows no hand-written numbers or raw placeholders", async ({ page }) => {
  await page.goto("/ru/transparency");
  const body = page.locator("body");
  for (const text of ["1 842 630", "1,842,630", "0,08", "$PERIOD$", "$DATE$", "$COUNT$", "аналитик"]) {
    await expect(body).not.toContainText(text);
  }
  await expect(page.getByTestId("transparency-fp")).toContainText("Пока не измеряли");
});

test("/ru/transparency/methodology is Russian and hides a too-small sample", async ({ page }) => {
  await page.goto("/ru/transparency/methodology");
  await expect(page.locator("h1")).toContainText("Как мы измеряем");
  await expect(page.getByTestId("methodology-not-publishable")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("$DATE$");
});

test("/ru/privacy-policy is Russian and describes only the released app", async ({ page }) => {
  await page.goto("/ru/privacy-policy");
  await expect(page.locator("h1")).toHaveText("Политика конфиденциальности");
  const body = page.locator("body");
  await expect(body).toContainText("1.1.1.1");
  await expect(body).toContainText("9.9.9.9");
  await expect(body).toContainText("1.0.1");
  await expect(body).not.toContainText("1.0.2");
  // Every service that receives a checked site's name is named.
  for (const service of ["rdap.org", "MalwareBazaar", "1.1.1.1 for Families"]) {
    await expect(body).toContainText(service);
  }
  await expect(body).not.toContainText("в открытом виде он не хранится");
  // The contact block is attached by section id, inside the last section.
  await expect(page.locator("section#contact [data-testid=privacy-contact-not-live]")).toBeVisible();
});

test("/ru/support does not promise an email reply while the mailbox is down", async ({ page }) => {
  await page.goto("/ru/support");
  await expect(page.getByTestId("support-email-not-live")).toBeVisible();
  await expect(page.locator('a[href="/ru/android"]')).toBeVisible();
});

test("/ru/support sends a wrongly blocked site to History, not to a block screen", async ({ page }) => {
  await page.goto("/ru/support");
  const body = page.locator("body");
  await expect(body).toContainText("вкладку «История»");
  await expect(body).toContainText("«Это не мошенники — разрешить»");
  await expect(body).not.toContainText("экране блокировки");
});

test("/ru/signup is Russian", async ({ page }) => {
  await page.goto("/ru/signup");
  await expect(page.locator("h1")).toHaveText("Создать аккаунт или войти");
});

test("/ru/signup shows no captcha test widget and no operator notice", async ({ page }) => {
  // The dev server shows the operator notice on purpose; this is about the build that ships.
  test.skip(!process.env.CI && !process.env.BASE_URL, "production build only");
  const testKeyRequests: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes(TURNSTILE_TEST_SITE_KEY)) testKeyRequests.push(req.url());
  });
  await page.goto("/ru/signup");
  await page.waitForLoadState("networkidle");
  const body = page.locator("body");
  await expect(body).not.toContainText("Turnstile");
  await expect(body).not.toContainText("NEXT_PUBLIC");
  await expect(page.locator(`iframe[src*="${TURNSTILE_TEST_SITE_KEY}"]`)).toHaveCount(0);
  expect(testKeyRequests).toEqual([]);
});

test("/pricing is free-only for a visitor from Russia, whatever the page language", async ({ page }) => {
  await page.setExtraHTTPHeaders({ "x-vercel-ip-country": "RU" });
  await page.goto("/pricing");
  await expect(page.getByTestId("free-pricing")).toBeVisible();
  await expect(page.locator("body")).not.toContainText("$4.99");
});

test("/de/pricing?cc=RU is free-only too", async ({ page }) => {
  await page.goto("/de/pricing?cc=RU");
  await expect(page.getByTestId("free-pricing")).toBeVisible();
});

test("/ru/check sends only the site name of a pasted link", async ({ page }) => {
  const requested: string[] = [];
  page.on("request", (req) => requested.push(req.url()));
  // Answer the scorecard navigation here, so the production API is never called.
  // Match the page path only: /_next/static/chunks/app/[locale]/check/... must load.
  await page.route(
    (url) => url.pathname.startsWith("/ru/check/"),
    (route) => route.fulfill({ status: 200, contentType: "text/plain", body: "" }),
  );
  await page.goto("/ru/check");
  await page.getByLabel("Сайт для проверки").fill(PASTED_LINK);
  await page.locator('form button[type="submit"]').click();
  await expect
    .poll(() => requested.some((url) => new URL(url).pathname === "/ru/check/bank-verify.ru"))
    .toBe(true);
  for (const url of requested) {
    expect(url, "the rest of the pasted link left the browser").not.toMatch(/confirm|email|me%40x|me@x/);
  }
});

test("before hydration the /ru/check form cannot submit the link natively", async ({ request }) => {
  // With a named input in a GET form, a tap before React loaded sent the whole
  // link as ?q= — reproduced here by a page whose scripts had not loaded.
  const html = await (await request.get("/ru/check")).text();
  expect(html).toMatch(/<button[^>]*type="submit"[^>]*disabled/);
  expect(html).not.toContain('name="q"');
});

test("/ru/check says plainly when the input is not a site name", async ({ page }) => {
  await page.goto("/ru/check");
  await page.getByLabel("Сайт для проверки").fill("привет");
  await page.locator('form button[type="submit"]').click();
  await expect(page.getByTestId("check-invalid")).toContainText("Это не похоже на имя сайта");
  expect(new URL(page.url()).pathname).toBe("/ru/check");
});

test("an old /ru/check?q=<link> URL redirects to the site name only", async ({ request }) => {
  const response = await request.get(`/ru/check?q=${encodeURIComponent(PASTED_LINK)}`, { maxRedirects: 0 });
  expect([303, 307, 308]).toContain(response.status());
  expect(response.headers()["location"]).toMatch(/\/ru\/check\/bank-verify\.ru$/);
});

test("the Android page does not carry the privacy policy to the browser", async ({ request }) => {
  const html = await (await request.get("/ru/android")).text();
  expect(html).not.toContain("Кто обрабатывает данные по нашему поручению");
  expect(html).not.toContain("Как мы измеряем собственную точность");
});

test("an unknown /ru page 404s in Russian", async ({ page }) => {
  const response = await page.goto("/ru/this-page-does-not-exist-xyz");
  expect(response?.status()).toBe(404);
  await expect(page.locator("h1")).toHaveText("Страница не найдена");
});

test("sitemap lists the Android and support pages", async ({ request }) => {
  const xml = await (await request.get("/sitemap.xml")).text();
  expect(xml).toContain("https://cleanway.ai/ru/android");
  expect(xml).toContain("https://cleanway.ai/ru/support");
});
