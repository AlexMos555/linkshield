import { test, expect, type Page } from "@playwright/test";

/**
 * What a store reviewer opens (docs/STORES.md): the public delete-account
 * page Google Play asks for, account deletion that works signed in — even
 * when the plan and devices fail to load — the /business page without a
 * hand-written price, and the legal pages that now cover the browser
 * extension and purchases through the app stores.
 *
 * The signed-in cases write the @supabase/ssr session cookie themselves and
 * answer the fake Supabase project and the API with page.route, like
 * extension-connect.spec.ts. Nothing leaves the test machine.
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";
const API = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
const BASE = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const fakeJwt = (claims: Record<string, unknown>) => `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);

test.use({ serviceWorkers: "block" });

test("/delete-account explains the steps and links to the account page", async ({ page }) => {
  const response = await page.goto("/delete-account");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1, name: "Delete your Cleanway account" })).toBeVisible();
  await expect(page.getByTestId("delete-account-cta")).toHaveAttribute("href", "/account");
  await expect(page.getByRole("heading", { name: "What is deleted" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What is kept" })).toBeVisible();
  await expect(page.getByText(/Google Play or the App Store is not cancelled/)).toBeVisible();
  // Indexable: Play's reviewer and people searching must be able to reach it.
  const robots = await page.locator('meta[name="robots"]').getAttribute("content");
  expect(robots ?? "").not.toContain("noindex");
});

test("/ru/delete-account is Russian and keeps the locale", async ({ page }) => {
  await page.goto("/ru/delete-account");
  await expect(page.getByRole("heading", { level: 1, name: "Удалить аккаунт Cleanway" })).toBeVisible();
  await expect(page.getByTestId("delete-account-cta")).toHaveAttribute("href", "/ru/account");
});

test("/business has no hand-written price and sends people to /pricing", async ({ page }) => {
  const response = await page.goto("/business");
  expect(response?.status()).toBe(200);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  const text = await page.locator("main").innerText();
  expect(text).not.toMatch(/\$\s?\d/);
  expect(text).not.toMatch(/KnowBe4|14-day|SAML/);
  await expect(page.getByTestId("business-pricing").getByRole("link")).toHaveAttribute("href", "/pricing");
});

test("the privacy policy covers the browser extension and store purchases", async ({ page }) => {
  await page.goto("/privacy-policy");
  await expect(page.locator("section#extension")).toContainText("Scan emails I open in Gmail, Outlook and Yahoo for phishing");
  await expect(page.locator("section#extension")).toContainText("first 5 characters");
  await expect(page.locator("section#extension")).toContainText("Sign out");
  const payments = page.locator("section#payments, section#billing").first();
  await expect(payments).toBeVisible();
  await expect(page.locator("main")).toContainText("RevenueCat");
  await expect(page.locator("main")).toContainText("cleanway.ai/delete-account");
});

test("the terms cover store purchases and the refund rule", async ({ page }) => {
  await page.goto("/terms");
  const main = page.locator("main");
  await expect(main).toContainText("Google Play or the App Store");
  await expect(main).toContainText("charged after cancelling, or charged by mistake");
  await expect(main).toContainText("currently 3");
});

test.describe("signed in", () => {
  test.skip(!SUPABASE_URL || !ANON_KEY, "NEXT_PUBLIC_SUPABASE_* not set for this build");

  async function signIn(page: Page) {
    const ref = new URL(SUPABASE_URL).hostname.split(".")[0];
    const access = fakeJwt({ sub: "user-1", email: "ann@example.com", aud: "authenticated", exp: nowS() + 3600 });
    const session = {
      access_token: access,
      token_type: "bearer",
      expires_in: 3600,
      expires_at: nowS() + 3600,
      refresh_token: "website-refresh-token",
      user: { id: "user-1", aud: "authenticated", email: "ann@example.com", app_metadata: {}, user_metadata: {} },
    };
    await page.context().addCookies([{ name: `sb-${ref}-auth-token`, value: `base64-${b64url(session)}`, url: BASE }]);
    await page.route(`${SUPABASE_URL}/**`, (route) =>
      route.fulfill({ status: 204, headers: { "access-control-allow-origin": "*" }, body: "" }),
    );
  }

  const cors = {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type, x-device-id",
    "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
  };

  /** The account API: entitlement answered with `entitlementStatus`, DELETE recorded. */
  async function fakeAccountApi(page: Page, entitlementStatus: number) {
    const deletes: string[] = [];
    await page.route(`${API}/api/v1/**`, async (route) => {
      const req = route.request();
      if (req.method() === "OPTIONS") return route.fulfill({ status: 204, headers: cors, body: "" });
      const path = new URL(req.url()).pathname;
      if (path === "/api/v1/me/entitlement") {
        const ok = {
          plan: "free", status: null, source: null, period_end: null,
          device_limit: 2, devices_used: 0, devices: [],
        };
        return route.fulfill({
          status: entitlementStatus,
          headers: cors,
          contentType: "application/json",
          body: JSON.stringify(entitlementStatus === 200 ? ok : { detail: "unavailable" }),
        });
      }
      if (path === "/api/v1/user/account" && req.method() === "DELETE") {
        deletes.push(req.headers()["authorization"] ?? "");
        return route.fulfill({
          status: 200,
          headers: cors,
          contentType: "application/json",
          body: JSON.stringify({ deleted_at: "2026-10-08T00:00:00Z", grace_period_days: 30, restore_until: "2026-11-07T00:00:00Z" }),
        });
      }
      return route.fulfill({ status: 404, headers: cors, contentType: "application/json", body: "{}" });
    });
    return deletes;
  }

  for (const entitlementStatus of [200, 503]) {
    test(`deleting the account works (entitlement ${entitlementStatus})`, async ({ page }) => {
      await signIn(page);
      const deletes = await fakeAccountApi(page, entitlementStatus);
      page.on("dialog", (dialog) => void dialog.accept());
      await page.goto("/account");
      await page.getByTestId("account-delete").click();
      await expect(page.getByRole("status")).toContainText("Your account is deleted");
      expect(deletes).toHaveLength(1);
      expect(deletes[0]).toMatch(/^Bearer /);
    });
  }
});
