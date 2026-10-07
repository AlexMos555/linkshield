import { test, expect } from "@playwright/test";

/**
 * /account — plan + linked devices. Without a session (CI has no Supabase
 * keys) the page must offer sign-in that comes BACK to /account, in the
 * reader's language, and must stay out of search engines.
 */

test("signed out: /account offers sign-in that returns to /account", async ({ page }) => {
  const response = await page.goto("/account");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Your account" })).toBeVisible();
  const signIn = page.getByRole("link", { name: "Sign in" });
  await expect(signIn).toBeVisible();
  await expect(signIn).toHaveAttribute("href", "/signup?next=/account");
});

test("signed out: /ru/account is Russian and keeps the locale", async ({ page }) => {
  await page.goto("/ru/account");
  await expect(page.getByRole("heading", { level: 1, name: "Ваш аккаунт" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Войти" })).toHaveAttribute("href", "/ru/signup?next=/ru/account");
});

test("/account is not indexed", async ({ page }) => {
  await page.goto("/account");
  const robots = await page.locator('meta[name="robots"]').getAttribute("content");
  expect(robots).toContain("noindex");
});
