import { test, expect } from "@playwright/test";

import { BILLING_ON } from "./billing-flag";

/**
 * Pages people reach from a link someone sent them, or from a step of a flow
 * (the 2026-10-22 sweep): each must speak the page's language, keep the
 * locale in its links, and say only what is true today.
 */

const DOH_URL = "https://dns.cleanway.ai/dns-query";

test("/ru/dns: Windows uses the browser's Secure DNS, never 1.1.1.1 with our template", async ({ page }) => {
  await page.goto("/ru/dns");
  const windows = page.getByTestId("dns-windows");
  await expect(windows).toContainText("в браузере");
  await expect(windows).toContainText(DOH_URL);
  for (const browser of ["Chrome", "Edge", "Firefox"]) await expect(windows).toContainText(browser);
  // The old steps paired Cloudflare's IP with our template: Windows then sent
  // our DoH request to 1.1.1.1, which answers 403.
  await expect(windows).not.toContainText("1.1.1.1");
  await expect(windows).toContainText("Автоматически (DHCP)");
});

test("/ru/dns is Russian top to bottom and keeps the locale in its links", async ({ page }) => {
  await page.goto("/ru/dns");
  const body = page.locator("body");
  for (const english of ["Where DNS fits", "DNS is the widest layer", "This is not a generic DNS filter", "&amp;"]) {
    await expect(body).not.toContainText(english);
  }
  await expect(page.getByRole("heading", { name: "Какое место DNS занимает в вашей защите" })).toBeVisible();
  // The deeper layer that ships today is the app; the extension is "coming soon".
  await expect(body).toContainText("скоро появится");
  await expect(page.locator('a[href="/#features"]')).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Скачать Cleanway для Android →" })).toHaveAttribute("href", "/ru/android");
  await expect(page.locator('a[href="/ru/transparency"]')).toBeVisible();
  await expect(page.locator('a[href="/ru/privacy-policy"]')).toBeVisible();
});

test("the home page's skip link and privacy heading are in the page's language", async ({ page }) => {
  await page.goto("/ru");
  await expect(page.locator("a.skip-link")).toHaveText("Перейти к основному содержанию");
  await page.goto("/de");
  await expect(page.locator("a.skip-link")).toHaveText("Zum Hauptinhalt springen");
  await expect(page.locator("#privacy h2").first()).not.toContainText("Privacy is not a feature");
});

test("/ru/business sells nothing /ru/pricing does not: no per-device price, no extension to install", async ({ page }) => {
  await page.goto("/ru/business");
  const main = page.locator("main");
  await expect(main).not.toContainText("Платный тариф");
  await expect(main).not.toContainText("Цена — за устройство");
  await expect(main).not.toContainText("или расширение в свой браузер");
  await expect(main).toContainText("расширение для браузера скоро появится");
  const pricing = page.getByTestId("business-pricing");
  await expect(pricing.getByRole("link")).toHaveAttribute("href", "/ru/pricing");
  if (BILLING_ON) {
    // The operator-billed subscription: the same one /ru/pricing then sells.
    await expect(pricing).toContainText("со счёта мобильного телефона");
    await expect(main).not.toContainText("бесплатн");
  } else {
    await expect(pricing).toContainText("Платных тарифов в России сейчас нет");
  }
});

test("/ru/android says the file comes through the button and lives on GitHub", async ({ page }) => {
  await page.goto("/ru/android");
  const neverCalls = page.getByTestId("never-calls");
  // The button downloads from github.com, which the browser shows as the
  // source: "only from this site" read as a lie at the very moment of download.
  await expect(neverCalls).not.toContainText("только с этого сайта");
  await expect(neverCalls).toContainText("кнопкой на этой странице");
  await expect(neverCalls).toContainText("GitHub");
});

test("/ru/ref/<code> is Russian and promises no trial, no ML, no 'zero data'", async ({ page }) => {
  await page.goto("/ru/ref/ABC123");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Друг приглашает вас в Cleanway");
  await expect(page.getByTestId("ref-code")).toContainText("ABC123");
  const main = page.locator("main");
  for (const stale of ["7 days", "ML-powered", "Data stored", "extension settings", "Your friend invited you"]) {
    await expect(main).not.toContainText(stale);
  }
  // The share preview is Russian too, with the locale-free share image.
  await expect(page.locator('meta[property="og:title"]')).toHaveAttribute("content", "Друг приглашает вас в Cleanway");
  await expect(page.locator('meta[property="og:image"]').first()).toHaveAttribute("content", "https://cleanway.ai/og.png");
});

test("/ref/<not a code> prints no URL text under the Cleanway name", async ({ page }) => {
  await page.goto("/ref/CALL-8-800-SUPPORT-NOW");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByTestId("ref-code")).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText("CALL-8-800");
});

test("/ru/family/join on a computer: Russian, the extension is 'coming soon', Android today", async ({ page }) => {
  await page.goto("/ru/family/join#code=ABCD1234&pin=4821");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Вас пригласили в семью в Cleanway");
  await expect(page.getByTestId("family-join-code")).toHaveText("ABCD1234");
  const steps = page.getByTestId("family-join-steps-desktop");
  await expect(steps).toContainText("скоро появится");
  await expect(steps.getByRole("link")).toHaveAttribute("href", "/ru/android");
  await expect(page.locator("main")).not.toContainText("Google Play");
  await expect(page.locator("main")).not.toContainText("Chrome");
});

test("/ru/family/join with a broken link says so in Russian", async ({ page }) => {
  await page.goto("/ru/family/join");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Ссылка-приглашение неполная");
  await expect(page.getByRole("link", { name: "Вернуться в Cleanway" })).toHaveAttribute("href", "/ru");
});

test.describe("on an Android phone", () => {
  test.use({ userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36" });

  test("/ru/family/join sends to /ru/android, never to Google Play, and names the app's own menu", async ({ page }) => {
    await page.goto("/ru/family/join#code=ABCD1234&pin=4821");
    const steps = page.getByTestId("family-join-steps-android");
    await expect(steps.getByRole("link")).toHaveAttribute("href", "/ru/android");
    await expect(steps).toContainText("Настройки → Семейный центр");
    await expect(steps).toContainText("Присоединиться по коду");
    await expect(steps).not.toContainText("Google Play");
  });
});

test("/ru/success shows what installs today, in Russian, and no dead anchor", async ({ page }) => {
  await page.goto("/ru/success");
  await expect(page.getByTestId("success-android")).toHaveAttribute("href", "/ru/android");
  await expect(page.getByTestId("success-dns")).toHaveAttribute("href", "/ru/dns");
  await expect(page.getByTestId("success-status")).toContainText("Скоро");
  const main = page.locator("main");
  await expect(main).not.toContainText("in store review");
  await expect(main).not.toContainText("Settings → Family Hub");
  await expect(page.locator('a[href*="#install"]')).toHaveCount(0);
});

test("/ru/audit pages are Russian and do not sell an extension nobody can install", async ({ page }) => {
  await page.goto("/ru/audit/example.com");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Аудит приватности: example.com");
  const teaser = page.locator("main");
  await expect(teaser).toContainText("скоро появится");
  for (const english of ["Install the extension", "Grade: Hidden", "Trackers", "runs 100%"]) {
    await expect(teaser).not.toContainText(english);
  }
  await page.goto("/ru/audit/example.com/grade/B");
  const grade = page.locator("main");
  await expect(grade).toContainText("Хорошая приватность");
  await expect(grade).toContainText("Как устроены оценки");
  for (const english of ["Good privacy", "Want to grade any site?", "Privacy Audit"]) {
    await expect(grade).not.toContainText(english);
  }
  await expect(page.locator('a[href="/ru/privacy-policy"]')).toBeVisible();
});

test("/business (world) still prices per device and links /pricing", async ({ page }) => {
  await page.goto("/business");
  await expect(page.getByTestId("business-pricing")).toContainText("per device");
  await expect(page.locator("main")).toContainText("the browser extension is coming soon");
});
