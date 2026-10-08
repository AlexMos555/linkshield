import { test, expect, type Page } from "@playwright/test";

/**
 * /extension/connect — where the browser extension's "Sign in" lands.
 *
 * The website session is a cookie this spec writes itself (the shape
 * @supabase/ssr reads), the fake Supabase project and the API are answered
 * by page.route, and the extension is a few lines that answer the page the
 * way content/connect-relay.js does. Nothing leaves the test machine.
 *
 * NEXT_PUBLIC_SUPABASE_* are inlined at build time; .github/workflows/
 * e2e-landing.yml builds with a fake project so these run in CI. Without them
 * (a local `npm run dev` with no .env) only the no-state case runs.
 */

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL ?? "";
const ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "";
const API = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
const BASE = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
const STATE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
const fakeJwt = (claims: Record<string, unknown>) => `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.sig`;

const nowS = () => Math.floor(Date.now() / 1000);
const WEB_ACCESS = fakeJwt({ sub: "user-1", email: "ann@example.com", aud: "authenticated", exp: nowS() + 3600 });
const MINTED = {
  access_token: fakeJwt({ sub: "user-1", email: "ann@example.com", aud: "authenticated", exp: nowS() + 3600, session_id: "ext" }),
  refresh_token: "extension-refresh-token",
  expires_at: nowS() + 3600,
};

// The service worker would answer fetches before page.route sees them.
test.use({ serviceWorkers: "block" });

test("without a state the page says to start from the extension", async ({ page }) => {
  await page.goto("/ru/extension/connect");
  await expect(page.getByTestId("connect-no-state")).toContainText("Начните из расширения");
  await expect(page.locator('meta[name="robots"]')).toHaveAttribute("content", /noindex/);
});

test.describe("with sign-in configured", () => {
  test.skip(!SUPABASE_URL || !ANON_KEY, "NEXT_PUBLIC_SUPABASE_* not set for this build");

  /** A signed-in website session, as @supabase/ssr stores it. */
  async function signIn(page: Page) {
    const ref = new URL(SUPABASE_URL).hostname.split(".")[0];
    const session = {
      access_token: WEB_ACCESS,
      token_type: "bearer",
      expires_in: 3600,
      expires_at: nowS() + 3600,
      refresh_token: "website-refresh-token",
      user: { id: "user-1", aud: "authenticated", email: "ann@example.com", app_metadata: {}, user_metadata: {} },
    };
    await page.context().addCookies([
      { name: `sb-${ref}-auth-token`, value: `base64-${b64url(session)}`, url: BASE },
    ]);
  }

  /** Every call to the fake Supabase project, answered locally. */
  async function fakeSupabase(page: Page) {
    const calls: string[] = [];
    await page.route(`${SUPABASE_URL}/**`, async (route) => {
      calls.push(route.request().url());
      await route.fulfill({ status: 204, headers: { "access-control-allow-origin": "*" }, body: "" });
    });
    return calls;
  }

  /** POST /api/v1/auth/extension-session, answered with `status`. */
  async function fakeApi(page: Page, status = 200) {
    const auth: string[] = [];
    await page.route(`${API}/api/v1/auth/extension-session`, async (route) => {
      const cors = {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "authorization, content-type",
        "access-control-allow-methods": "POST, OPTIONS",
      };
      if (route.request().method() === "OPTIONS") {
        await route.fulfill({ status: 204, headers: cors, body: "" });
        return;
      }
      auth.push(route.request().headers()["authorization"] ?? "");
      await route.fulfill({
        status,
        headers: cors,
        contentType: "application/json",
        body: JSON.stringify(status === 200 ? MINTED : { detail: "nope" }),
      });
    });
    return auth;
  }

  /** The extension's relay, as connect-relay.js answers. */
  async function fakeExtension(page: Page, reply: { ok: boolean; error: string | null }) {
    await page.addInitScript((answer) => {
      const w = window as unknown as { __handoffs: unknown[] };
      w.__handoffs = [];
      window.addEventListener("message", (event) => {
        if (event.source !== window) return;
        const data = event.data as { source?: string; type?: string } | null;
        if (!data || data.source !== "cleanway-web") return;
        const post = (msg: object) => window.postMessage({ source: "cleanway-extension", ...msg }, location.origin);
        if (data.type === "cleanway:hello") post({ type: "cleanway:extension-ready" });
        if (data.type === "cleanway:connect") {
          w.__handoffs.push(data);
          post({ type: "cleanway:connect-result", ...answer });
        }
      });
    }, reply);
  }

  test("not signed in: off to sign-in, which brings the reader back with the same state", async ({ page }) => {
    await fakeSupabase(page);
    await page.goto(`/ru/extension/connect?state=${STATE}`);
    await page.waitForURL(/\/ru\/signup\?/);
    const next = new URL(page.url()).searchParams.get("next");
    expect(next).toBe(`/ru/extension/connect?state=${STATE}`);
    await expect(page.locator("h1")).toBeVisible();
  });

  test("signed in: Connect hands the extension a session of its own", async ({ page }) => {
    await signIn(page);
    await fakeSupabase(page);
    const apiAuth = await fakeApi(page);
    await fakeExtension(page, { ok: true, error: null });

    await page.goto(`/extension/connect?state=${STATE}`);
    await expect(page.getByTestId("connect-email")).toContainText("ann@example.com");
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await expect(page.getByTestId("connect-done")).toContainText("This browser is connected");

    // The API was asked with the WEBSITE's token…
    expect(apiAuth).toEqual([`Bearer ${WEB_ACCESS}`]);
    // …and the extension got the NEW session, the state and the public key.
    const handoffs = await page.evaluate(() => (window as unknown as { __handoffs: unknown[] }).__handoffs);
    expect(handoffs).toEqual([
      {
        source: "cleanway-web",
        type: "cleanway:connect",
        state: STATE,
        session: { ...MINTED, anon_key: ANON_KEY },
      },
    ]);
    expect(JSON.stringify(handoffs)).not.toContain("website-refresh-token");
    // No token ever lands in the address bar.
    expect(page.url()).not.toContain(MINTED.refresh_token);
    expect(page.url()).not.toContain("access_token");
  });

  test("no extension in this browser: says so and opens no session", async ({ page }) => {
    await signIn(page);
    await fakeSupabase(page);
    const apiAuth = await fakeApi(page);

    await page.goto(`/extension/connect?state=${STATE}`);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await expect(page.getByTestId("connect-error")).toContainText("didn't answer");
    expect(apiAuth).toEqual([]);
  });

  test("the extension refuses an old state: the new session is ended at once", async ({ page }) => {
    await signIn(page);
    const supabaseCalls = await fakeSupabase(page);
    await fakeApi(page);
    await fakeExtension(page, { ok: false, error: "state_mismatch" });

    await page.goto(`/extension/connect?state=${STATE}`);
    await page.getByRole("button", { name: "Connect", exact: true }).click();
    await expect(page.getByTestId("connect-error")).toContainText("This sign-in request has expired");
    await expect.poll(() => supabaseCalls.some((u) => u.endsWith("/auth/v1/logout?scope=local"))).toBe(true);
  });

  test("every device seat is taken: says so and links to the device list", async ({ page }) => {
    await signIn(page);
    await fakeSupabase(page);
    await fakeApi(page);
    await fakeExtension(page, { ok: false, error: "device_limit_reached" });

    await page.goto(`/ru/extension/connect?state=${STATE}`);
    await page.getByRole("button", { name: "Подключить", exact: true }).click();
    const error = page.getByTestId("connect-error");
    await expect(error).toContainText("Все устройства тарифа заняты");
    await expect(page.getByTestId("connect-devices")).toHaveAttribute("href", "/ru/account");
  });

  test("account on hold: points to the restore page", async ({ page }) => {
    await signIn(page);
    await fakeSupabase(page);
    await fakeApi(page, 410);
    await fakeExtension(page, { ok: true, error: null });

    await page.goto(`/ru/extension/connect?state=${STATE}`);
    await page.getByRole("button", { name: "Подключить", exact: true }).click();
    const error = page.getByTestId("connect-error");
    await expect(error).toContainText("Аккаунт ожидает удаления");
    await expect(error.getByRole("link")).toHaveAttribute("href", "/ru/account/restore?reason=locked");
  });
});
