import { test, expect } from "@playwright/test";

/**
 * The Outlook add-in (email-plugin-outlook/, served from /outlook/ by the
 * prebuild copy). The 2026-10-22 sweep found it could not start: the site's
 * CSP blocked office.js and, with frame-ancestors 'none' plus
 * X-Frame-Options DENY, refused the Outlook frame. next.config.ts now gives
 * /outlook/* a policy of its own — and only /outlook/*.
 */

const PAGES = ["/outlook/taskpane/taskpane.html", "/outlook/commands/commands.html"];

for (const path of PAGES) {
  test(`${path}: office.js may load, Outlook may frame it, nothing else changes`, async ({ request }) => {
    const response = await request.get(path);
    expect(response.status()).toBe(200);
    const headers = response.headers();
    const csp = headers["content-security-policy"] ?? "";
    expect(csp).toContain("script-src 'self' https://appsforoffice.microsoft.com");
    expect(csp).not.toContain("unsafe-inline' https://js.stripe.com");
    expect(csp).toMatch(/connect-src [^;]*https:\/\/api\.cleanway\.ai/);
    expect(csp).toMatch(/frame-ancestors [^;]*https:\/\/outlook\.office\.com/);
    expect(csp).toMatch(/frame-ancestors [^;]*https:\/\/outlook\.live\.com/);
    expect(csp).not.toContain("frame-ancestors 'none'");
    expect(headers["x-frame-options"]).toBeUndefined();
    expect(headers["strict-transport-security"]).toContain("max-age=");
    expect(headers["x-content-type-options"]).toBe("nosniff");
  });
}

test("the rest of the site still refuses to be framed", async ({ request }) => {
  for (const path of ["/", "/ru/pricing", "/android"]) {
    const headers = (await request.get(path)).headers();
    expect(headers["x-frame-options"], path).toBe("DENY");
    expect(headers["content-security-policy"], path).toContain("frame-ancestors 'none'");
    expect(headers["content-security-policy"], path).not.toContain("appsforoffice");
  }
});

test("addin.cleanway.ai serves the add-in and sends everything else to the site", async ({ request }) => {
  const addin = { host: "addin.cleanway.ai" };
  const manifest = await request.get("/outlook/manifest.xml", { headers: addin, maxRedirects: 0 });
  expect(manifest.status()).toBe(200);
  for (const [path, location] of [["/ru/pricing", "https://cleanway.ai/ru/pricing"], ["/", "https://cleanway.ai/"]]) {
    const response = await request.get(path, { headers: addin, maxRedirects: 0 });
    expect(response.status(), path).toBe(308);
    expect(response.headers()["location"], path).toBe(location);
  }
});

test("the privacy policy says what the add-in sends and how long reports are kept", async ({ page }) => {
  await page.goto("/privacy-policy");
  const extension = page.locator("section#extension");
  await expect(extension).toContainText("add-in for Outlook");
  await expect(extension).toContainText("sends only the sender's domain");
  await expect(page.locator("main")).toContainText("reports of a wrong result or of a phishing email");
  await page.goto("/ru/privacy-policy");
  await expect(page.locator("section#extension")).toContainText("Надстройка Cleanway для Outlook");
});

test("every URL in the manifest is a file the site serves", async ({ request }) => {
  const xml = await (await request.get("/outlook/manifest.xml")).text();
  const urls = [...xml.matchAll(/DefaultValue="(https:\/\/addin\.cleanway\.ai\/[^"]+)"/g)].map((m) => m[1]);
  expect(urls.length).toBeGreaterThan(5);
  for (const url of urls) {
    const response = await request.get(new URL(url).pathname, { headers: { host: "addin.cleanway.ai" }, maxRedirects: 0 });
    expect(response.status(), url).toBe(200);
  }
});
