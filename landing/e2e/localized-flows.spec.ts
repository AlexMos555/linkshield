import { test, expect } from "@playwright/test";

import { BILLING_ON, STRIPE_LIVE } from "./billing-flag";

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

test("/dns promises every app only where it is true: iPhone, iPad and Mac, not Windows", async ({ page }) => {
  // The Windows section says only the browser is covered; the hero and the
  // benefits on the same page used to promise "every app" on a "laptop".
  // English first: after /ru the locale cookie sends /dns on to /ru/dns.
  await page.goto("/dns");
  const en = page.locator("body");
  await expect(en).not.toContainText("phone or laptop");
  await expect(en).not.toContainText("Works on every app, not just your browser");
  await expect(en).toContainText("Point your iPhone, iPad or Mac at it");
  await expect(en).toContainText("On iPhone, iPad and Mac it works in every app");
  await page.goto("/ru/dns");
  const ru = page.locator("body");
  await expect(ru).not.toContainText("телефон или ноутбук");
  await expect(ru).not.toContainText("Работает в любом приложении, не только в браузере");
  await expect(ru).toContainText("Направьте на него iPhone, iPad или Mac");
  await expect(ru).toContainText("На iPhone, iPad и Mac работает в любом приложении");
});

test("the privacy policy says Windows sends only the browser's lookups, not every DNS query", async ({ page }) => {
  await page.goto("/privacy-policy");
  await expect(page.locator("main")).not.toContainText("Mac or Windows computer, all of your device's DNS queries");
  await expect(page.locator("main")).toContainText("on a Windows computer, those of the browser you set it up in");
  await page.goto("/ru/privacy-policy");
  await expect(page.locator("main")).not.toContainText("на iPhone, Mac или компьютере с Windows, все DNS-запросы устройства");
  await expect(page.locator("main")).toContainText("на компьютере с Windows — запросы браузера, в котором вы его настроили");
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
  // The app sends no family alerts; only the extension (not out yet) will.
  await expect(page.locator("main")).not.toContainText("предупреждали друг друга");
  await expect(page.locator("main")).toContainText("будут приходить из расширения Cleanway для браузера");
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
  // An owner with no family sees "Create family" first; "Generate invite" comes after it.
  await expect(main).toContainText("Настройки → Семейный центр → «Создать семью», затем «Создать приглашение»");
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

test("/business from Russia, in any page language, sells only what /pricing sells there", async ({ page }) => {
  // /pricing reads Vercel's geo header; /business used to read the locale only,
  // so /business from Russia sold the device plan that /pricing then refused.
  await page.setExtraHTTPHeaders({ "x-vercel-ip-country": "RU" });
  await page.goto("/business");
  const en = page.getByTestId("business-pricing");
  await expect(en).not.toContainText("The price is per device");
  if (BILLING_ON) await expect(en).toContainText("billed to a mobile phone account");
  else await expect(en).toContainText("There are no paid plans in your country right now");
  await expect(en.getByRole("link")).toHaveAttribute("href", "/pricing");

  await page.goto("/de/business");
  const de = page.getByTestId("business-pricing");
  await expect(de).not.toContainText("Der Preis gilt pro Gerät");
  if (BILLING_ON) await expect(de).toContainText("bezahlt über ein Mobilfunkkonto");
  else await expect(de).toContainText("In Ihrem Land gibt es derzeit keine kostenpflichtigen Tarife");
  await expect(de.getByRole("link")).toHaveAttribute("href", "/de/pricing");
});

// The world /pricing sells the device plan only once Stripe checkout is live
// (NEXT_PUBLIC_STRIPE_LIVE); until then it is the free page, so /business must
// not talk about paying, nor send people to "the plan on the Pricing page".
test("/business (world) prices per device only while Stripe is live", async ({ page }) => {
  await page.goto("/business");
  const pricing = page.getByTestId("business-pricing");
  const main = page.locator("main");
  await expect(main).toContainText("the browser extension is coming soon");
  await expect(pricing.getByRole("link")).toHaveAttribute("href", "/pricing");
  if (STRIPE_LIVE) {
    await expect(pricing).toContainText("per device");
    await expect(pricing.getByRole("link")).toHaveText("See prices");
    return;
  }
  await expect(pricing).toContainText("There are no paid plans in your country right now");
  await expect(pricing.getByRole("link")).toHaveText("What is included");
  for (const paid of ["per device", "See prices", "the plan on the Pricing page", "invoice"]) {
    await expect(main).not.toContainText(paid);
  }
});
