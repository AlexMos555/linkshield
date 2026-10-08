import { test, expect } from "@playwright/test";

import { BILLING_ON, SUPPORT_LIVE } from "./billing-flag";

/**
 * The operator-billed subscription (docs/BILLING.md) on the landing, in both
 * flag states. NEXT_PUBLIC_BILLING_ENABLED is inlined at build time, so one
 * server is one state: the CI matrix in .github/workflows/e2e-landing.yml
 * builds and runs both, and each half here skips when the other is live.
 *
 * Flag OFF is today's site and must stay exactly that: the free-only
 * /ru/pricing, no /cancel, the current payment sections in the terms and the
 * policy, the free-only home teaser. Flag ON is what the founder's flip ships:
 * the device plan at the configured prices (99 ₽ a month for 3 devices, +29 ₽
 * for each one more by default — lib/billing.ts), basic protection with
 * nothing to pay, the first 7 days unlimited, the FAQ answers, the requisites
 * block, and copy that is true for a paid product (no "free forever", no
 * Stripe, no dollars).
 */
const PRICES_RUB = ["99", "29"];
const TODAYS_RU_TERMS_PAYMENTS = "В России платных тарифов нет";
const TODAYS_RU_TEASER = "Платных тарифов в России сейчас нет";

test.describe("billing flag off — today's site", () => {
  test.skip(BILLING_ON, "NEXT_PUBLIC_BILLING_ENABLED is on");

  test("/ru/pricing is still the free-only page with no subscription copy", async ({ page }) => {
    await page.goto("/ru/pricing");
    await expect(page.getByTestId("free-pricing")).toBeVisible();
    await expect(page.getByTestId("operator-pricing")).toHaveCount(0);
    const body = page.locator("body");
    await expect(body).not.toContainText("₽");
    await expect(body).not.toContainText("подписк");
    await expect(body).toContainText("Платных тарифов в России сейчас нет");
  });

  test("/ru/cancel does not exist", async ({ page }) => {
    const response = await page.goto("/ru/cancel");
    expect(response?.status()).toBe(404);
    await expect(page.locator("h1")).toHaveText("Страница не найдена");
  });

  test("the terms and the policy keep today's payment sections", async ({ page }) => {
    await page.goto("/ru/terms");
    await expect(page.locator("section#payments")).toContainText(TODAYS_RU_TERMS_PAYMENTS);
    await expect(page.locator("section#billing")).toHaveCount(0);
    await page.goto("/ru/privacy-policy");
    await expect(page.locator("section#payments")).toContainText("Stripe");
    await expect(page.locator("body")).not.toContainText("со счёта мобильного телефона");
  });

  test("the home teaser is free-only, with no plans link", async ({ page }) => {
    await page.goto("/ru");
    await expect(page.locator("#pricing")).toContainText(TODAYS_RU_TEASER);
    await expect(page.getByTestId("home-plans-link")).toHaveCount(0);
  });

  test("the sitemap has no cancel page", async ({ request }) => {
    const xml = await (await request.get("/sitemap.xml")).text();
    expect(xml).not.toContain("/cancel");
  });
});

test.describe("billing flag on — the operator-billed subscription", () => {
  test.skip(!BILLING_ON, "NEXT_PUBLIC_BILLING_ENABLED is off");

  test("/ru/pricing sells the subscription at the configured prices, in Russian", async ({ page }) => {
    await page.goto("/ru/pricing");
    await expect(page.getByTestId("operator-pricing")).toBeVisible();
    await expect(page.getByTestId("free-pricing")).toHaveCount(0);
    await expect(page.locator("h1")).toContainText("Защита от мошенников");

    const plan = page.getByTestId("plan-card-devices");
    await expect(plan).toContainText("99 ₽ в месяц");
    await expect(plan).toContainText("за 3 устройства в одном аккаунте");
    await expect(page.getByTestId("operator-extra-device")).toContainText("+29 ₽ в месяц");
    // Basic protection: list blocking with nothing to pay, 3 detailed checks a day.
    const basic = page.getByTestId("plan-card-basic");
    await expect(basic).toContainText("Без оплаты");
    await expect(basic).toContainText("3 подробные проверки в день");
    await expect(page.getByTestId("operator-trial")).toContainText("7 дней");
    // The retired one-, three- and five-phone plans are gone.
    await expect(page.getByTestId("plan-card-family5")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText("270 ₽");

    const body = page.locator("body");
    await expect(body).not.toContainText("$");
    await expect(body).not.toContainText("Stripe");
    await expect(body).not.toContainText("бесплатно навсегда");
    await expect(body).not.toContainText("Платных тарифов в России");
  });

  test("/ru/pricing answers the four questions, names the seller block and links the documents", async ({ page }) => {
    await page.goto("/ru/pricing");
    const faq = page.getByTestId("operator-faq");
    for (const question of [
      "Спишется ли что-нибудь само после первых дней?",
      "Что считается устройством?",
      "Как отменить подписку?",
      "Что будет, если на счёте нет денег?",
      "Работает ли по Wi-Fi и с другим оператором?",
    ]) {
      await expect(faq).toContainText(question);
    }
    // The default lapse policy ("basic") keeps list blocking after a failed payment.
    await expect(faq).toContainText("базовая блокировка");
    await expect(faq).toContainText("7 дней");

    // Requisites are not configured in CI: the block says so instead of printing blanks.
    await expect(page.getByTestId("requisites")).toBeVisible();
    await expect(page.getByTestId("requisites-pending")).toContainText("ИНН, ОГРНИП");
    await expect(page.getByTestId("operator-support")).toBeVisible();

    await expect(page.locator('a[href="/ru/cancel"]')).toBeVisible();
    await expect(page.locator('a[href="/ru/terms"]')).toBeVisible();
    await expect(page.locator('a[href="/ru/privacy-policy"]')).toBeVisible();
  });

  test("/ru/pricing link preview names the subscription and its prices", async ({ page }) => {
    await page.goto("/ru/pricing");
    const ogDescription = await page.locator('meta[property="og:description"]').getAttribute("content");
    for (const price of PRICES_RUB) expect(ogDescription).toContain(`${price} ₽`);
    expect(ogDescription).not.toMatch(/бесплат/);
  });

  test("/pricing for a visitor from Russia gets the subscription in the page's language", async ({ page }) => {
    await page.setExtraHTTPHeaders({ "x-vercel-ip-country": "RU" });
    await page.goto("/pricing");
    await expect(page.getByTestId("operator-pricing")).toBeVisible();
    await expect(page.getByTestId("plan-card-devices")).toContainText("99 ₽ a month");
    await expect(page.locator("body")).not.toContainText(/\$\d/);
  });

  test("/de/pricing without a Russian country stays on Stripe plans", async ({ page }) => {
    await page.goto("/de/pricing");
    await expect(page.getByTestId("operator-pricing")).toHaveCount(0);
    await expect(page.getByTestId("free-pricing")).toHaveCount(0);
    await expect(page.getByTestId("world-pricing")).toBeVisible();
  });

  test("/ru/cancel explains the four channels, what follows, and refunds", async ({ page }) => {
    const response = await page.goto("/ru/cancel");
    expect(response?.status()).toBe(200);
    await expect(page.locator("h1")).toHaveText("Отмена подписки и возврат денег");
    for (const way of ["app", "sms", "support", "operator"]) {
      await expect(page.getByTestId(`cancel-way-${way}`)).toBeVisible();
    }
    // No short number is configured in CI: the SMS channel says so, not a blank number.
    await expect(page.getByTestId("cancel-way-sms")).toContainText("появится здесь");
    await expect(page.getByTestId("cancel-after")).toContainText("Списаний больше нет");
    await expect(page.getByTestId("cancel-after")).toContainText("базовая блокировка");
    await expect(page.getByTestId("cancel-refund")).toContainText("вернём оплату за месяц");
    await expect(page.locator('a[href="/ru/pricing"]')).toBeVisible();
    await expect(page.locator("body")).not.toContainText("бесплат");
  });

  test("the terms and the policy describe the operator billing in place of today's payment sections", async ({ page }) => {
    await page.goto("/ru/terms");
    const terms = page.locator("section#billing");
    await expect(terms).toContainText("4. Подписка и оплата");
    await expect(terms).toContainText("со счёта мобильного телефона");
    await expect(terms).toContainText("базовая блокировка");
    await expect(page.locator("section#payments")).toHaveCount(0);
    await expect(page.locator("body")).not.toContainText(TODAYS_RU_TERMS_PAYMENTS);
    // The sections around it did not move.
    await expect(page.locator("section#privacy")).toContainText("7. Конфиденциальность");

    await page.goto("/ru/privacy-policy");
    const policy = page.locator("section#billing");
    await expect(policy).toContainText("12. Оплата подписки");
    await expect(policy).toContainText("отдельной базе данных на территории России");
    await expect(policy).toContainText("зашифрованном виде");
    await expect(page.locator("section#payments")).toHaveCount(0);
    await expect(page.locator("section#contact [data-testid=privacy-contact-not-live]")).toBeVisible();
  });

  test("terms outside Russia keep the Stripe payment section and no lapse policy", async ({ page }) => {
    for (const path of ["/terms", "/de/terms"]) {
      await page.goto(path);
      await expect(page.locator("section#payments")).toContainText("Stripe");
      await expect(page.locator("section#billing")).toHaveCount(0);
    }
    await expect(page.locator("section#payments")).toContainText("Das Blockieren von Betrugsseiten wird nie kostenpflichtig");
  });

  test("/terms for a visitor from Russia gets the subscription terms in the page's language", async ({ page }) => {
    await page.setExtraHTTPHeaders({ "x-vercel-ip-country": "RU" });
    await page.goto("/terms");
    await expect(page.locator("section#billing")).toBeVisible();
    await expect(page.locator("section#payments")).toHaveCount(0);
  });

  test("/ru/cancel does not offer support as a way to cancel while the mailbox is not live", async ({ page }) => {
    test.skip(SUPPORT_LIVE, "NEXT_PUBLIC_SUPPORT_EMAIL_LIVE is on");
    await page.goto("/ru/cancel");
    const support = page.getByTestId("cancel-way-support");
    await expect(support).toContainText("ещё настраивается");
    await expect(support).not.toContainText("в тот же рабочий день");
    await expect(page.getByTestId("cancel-way-sms")).not.toContainText("через поддержку");
    await expect(page.getByTestId("cancel-contact-pending")).toBeVisible();
  });

  test("the home teaser names the subscription and links /ru/pricing", async ({ page }) => {
    await page.goto("/ru");
    const teaser = page.locator("#pricing");
    await expect(teaser).toContainText("Подписка со счёта телефона");
    await expect(teaser).toContainText("99 ₽ в месяц за 3 устройства");
    await expect(teaser).not.toContainText(TODAYS_RU_TEASER);
    await expect(page.getByTestId("home-plans-link")).toHaveAttribute("href", "/ru/pricing");
  });

  test("the sitemap lists the cancel page in every language", async ({ request }) => {
    const xml = await (await request.get("/sitemap.xml")).text();
    expect(xml).toContain("https://cleanway.ai/ru/cancel");
    expect(xml).toContain("https://cleanway.ai/cancel");
  });
});
