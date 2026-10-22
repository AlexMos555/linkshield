import { test, expect } from "@playwright/test";

/**
 * The [domain] / [letter] route segments come straight from the URL. A segment
 * that is not a site name must never reach the HTML raw — in particular it must
 * not close the JSON-LD <script> block (reflected XSS, 2026-10).
 *
 * The probe is harmless markup: if "</script><b>cwprobe" appears verbatim in
 * the response, the page let URL text out of its script tag.
 */
const PROBE = "%3C%2Fscript%3E%3Cb%3Ecwprobe";
const RAW = "</script><b>cwprobe";

const HOSTILE_PATHS = [
  `/audit/${PROBE}`,
  `/ru/audit/${PROBE}`,
  `/audit/${PROBE}/grade/A`,
  `/audit/example.com/grade/${PROBE}`,
  `/check/${PROBE}`,
];

for (const path of HOSTILE_PATHS) {
  test(`URL text never escapes into the HTML: ${path}`, async ({ request }) => {
    const response = await request.get(path, { maxRedirects: 0 });
    const body = await response.text();
    expect(body).not.toContain(RAW);
    // Not a site name: there is no page for it.
    expect(response.status()).toBe(404);
  });
}

test("a real site's audit page still renders, with its JSON-LD", async ({ request }) => {
  const response = await request.get("/audit/example.com");
  expect(response.status()).toBe(200);
  const body = await response.text();
  expect(body).toContain("application/ld+json");
  expect(body).toContain("example.com privacy audit");
});

test("a real site's grade page still renders", async ({ request }) => {
  const response = await request.get("/audit/example.com/grade/B");
  expect(response.status()).toBe(200);
  expect(await response.text()).toContain("application/ld+json");
});

test("a pasted link in the audit route is cut down to its host", async ({ request }) => {
  const response = await request.get("/audit/Example.COM%2Fpath%3Fq%3D1", { maxRedirects: 0 });
  expect([307, 308]).toContain(response.status());
  expect(response.headers()["location"]).toMatch(/\/audit\/example\.com$/);
});
