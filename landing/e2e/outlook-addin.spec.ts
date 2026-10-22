import { test, expect } from "@playwright/test";

/**
 * The Outlook add-in (email-plugin-outlook/, served from /outlook/ by the
 * prebuild copy). The 2026-10-22 sweep found it could not start: the site's
 * CSP blocked office.js and, with frame-ancestors 'none' plus
 * X-Frame-Options DENY, refused the Outlook frame; and its manifest named
 * addin.cleanway.ai, which has no DNS record. next.config.ts now gives
 * /outlook/* a policy of its own — and only /outlook/* — and the manifest
 * names these same files on cleanway.ai.
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

test("the privacy policy says what the add-in sends and how long reports are kept", async ({ page }) => {
  await page.goto("/privacy-policy");
  const extension = page.locator("section#extension");
  await expect(extension).toContainText("add-in for Outlook");
  await expect(extension).toContainText("sends only the sender's domain");
  await expect(page.locator("main")).toContainText("reports of a wrong result or of a phishing email");
  // And on what basis (GDPR Art. 13): both buttons, not only the webmail scan.
  await expect(page.locator("section#legal_bases")).toContainText("Outlook add-in's “Scan email” and “Report phishing”");
  await page.goto("/ru/privacy-policy");
  await expect(page.locator("section#extension")).toContainText("Надстройка Cleanway для Outlook");
  await expect(page.locator("section#legal_bases")).toContainText("«Scan email» и «Report phishing» в надстройке для Outlook");
});

test("every URL in the manifest is a file the site serves, without a redirect", async ({ request }) => {
  const xml = await (await request.get("/outlook/manifest.xml")).text();
  expect(xml).not.toContain("addin.cleanway.ai");
  const urls = [...xml.matchAll(/DefaultValue="(https:\/\/cleanway\.ai\/outlook\/[^"]+)"/g)].map((m) => m[1]);
  expect(urls.length).toBeGreaterThan(5);
  for (const url of urls) {
    const response = await request.get(new URL(url).pathname, { maxRedirects: 0 });
    expect(response.status(), url).toBe(200);
  }
});
