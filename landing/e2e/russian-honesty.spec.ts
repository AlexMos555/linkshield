import { test, expect } from "@playwright/test";

/**
 * The Russian pages a Tele2 subscriber actually lands on must be in Russian
 * and must not promise what the product doesn't do (report items #11–#13,
 * #15, #19 of the 2026-09-25 service check). String-level rules live in
 * scripts/check-landing-claims.py; these check the rendered pages.
 *
 * No test here opens /check/<domain>: that page calls the production API,
 * which is rate-limited per IP.
 */

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

test("/ru/privacy-policy is Russian and says where DNS lookups go", async ({ page }) => {
  await page.goto("/ru/privacy-policy");
  await expect(page.locator("h1")).toHaveText("Политика конфиденциальности");
  const body = page.locator("body");
  await expect(body).toContainText("1.1.1.1");
  await expect(body).toContainText("9.9.9.9");
  await expect(body).toContainText("1.0.2");
});

test("/ru/support does not promise an email reply while the mailbox is down", async ({ page }) => {
  await page.goto("/ru/support");
  await expect(page.getByTestId("support-email-not-live")).toBeVisible();
  await expect(page.locator('a[href="/ru/android"]')).toBeVisible();
});

test("/ru/signup is Russian", async ({ page }) => {
  await page.goto("/ru/signup");
  await expect(page.locator("h1")).toHaveText("Создать аккаунт или войти");
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
