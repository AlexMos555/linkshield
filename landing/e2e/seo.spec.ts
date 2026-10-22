import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

/**
 * Technical SEO on the pages that carry the launch: canonical, hreflang,
 * share image, robots and the index policy for the infinite /check/<site>
 * URL space (lib/seo.ts, lib/seo-domains.ts).
 */
const SITE = "https://cleanway.ai";
const LOCALES = ["en", "es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id"];

function abs(locale: string, path: string): string {
  const rest = path === "/" ? "" : path;
  return locale === "en" ? `${SITE}${rest}` : `${SITE}/${locale}${rest}`;
}

function local(locale: string, path: string): string {
  if (locale === "en") return path;
  return path === "/" ? `/${locale}` : `/${locale}${path}`;
}

async function hreflangs(page: Page): Promise<Record<string, string>> {
  return page.$$eval('link[rel="alternate"][hreflang]', (links) =>
    Object.fromEntries(links.map((l) => [l.getAttribute("hreflang") ?? "", l.getAttribute("href") ?? ""])),
  );
}

const PAGES = ["/", "/pricing", "/check", "/android", "/support", "/check/google.com"];

for (const path of PAGES) {
  for (const locale of ["en", "ru", "ar"]) {
    test(`${local(locale, path)}: self canonical, full hreflang, title, description, share image`, async ({ page }) => {
      const response = await page.goto(local(locale, path));
      expect(response?.status()).toBe(200);

      await expect(page.locator('link[rel="canonical"]')).toHaveAttribute("href", abs(locale, path));

      const alternates = await hreflangs(page);
      for (const loc of LOCALES) expect(alternates[loc], `hreflang ${loc}`).toBe(abs(loc, path));
      expect(alternates["x-default"]).toBe(abs("en", path));
      // A trailing slash names a redirect (/ru/ → /ru), not the page.
      for (const href of Object.values(alternates)) expect(href.endsWith("/")).toBe(false);

      expect((await page.title()).trim().length).toBeGreaterThan(10);
      const description = await page.locator('meta[name="description"]').getAttribute("content");
      expect((description ?? "").trim().length).toBeGreaterThan(40);
      await expect(page.locator('meta[property="og:image"]').first()).toHaveAttribute("content", /^https:\/\/cleanway\.ai\//);

      await expect(page.locator("html")).toHaveAttribute("lang", locale);
      await expect(page.locator("html")).toHaveAttribute("dir", locale === "ar" ? "rtl" : "ltr");
    });
  }
}

/** `content` of a <meta property=…> in raw HTML, the way a link-preview bot reads it. */
function ogTag(head: string, property: string): string | undefined {
  return head.match(new RegExp(`<meta property="${property}" content="([^"]*)"`))?.[1];
}

// Pages people send each other ("here is how to delete it", "write to
// support"). Without their own openGraph block Telegram showed the generic
// site title, no og:url, and on English pages an og:image that answered 307.
for (const path of ["/support", "/signup", "/delete-account"]) {
  for (const locale of ["en", "ru"]) {
    test(`${local(locale, path)}: its own share preview, og:url and a share image that is not a redirect`, async ({ request }) => {
      const telegram = { "user-agent": "TelegramBot (like TwitterBot)" };
      const home = (await (await request.get(local(locale, "/"), { headers: telegram })).text()).split("</head>")[0];
      const head = (await (await request.get(local(locale, path), { headers: telegram })).text()).split("</head>")[0];

      const title = head.match(/<title>([^<]*)<\/title>/)?.[1];
      expect(ogTag(head, "og:title")).toBe(title);
      expect(ogTag(head, "og:title")).not.toBe(ogTag(home, "og:title"));
      expect(ogTag(head, "og:url")).toBe(abs(locale, path));
      expect(ogTag(head, "og:image")).toBe(`${SITE}/og.png`);
      expect(head).toContain('name="twitter:image"');
    });
  }
}

test("the share image answers 200 in every language, for a bot with no cookies", async ({ playwright, baseURL }) => {
  // /opengraph-image went through the locale middleware: "Accept-Language: ru"
  // got a 307 to /ru/opengraph-image. A preview bot does not follow it.
  for (const language of ["en", "ru-RU,ru;q=0.9", "ar"]) {
    const bot = await playwright.request.newContext({ baseURL });
    const image = await bot.get("/og.png", {
      maxRedirects: 0,
      headers: { "user-agent": "TelegramBot (like TwitterBot)", "accept-language": language },
    });
    expect(image.status(), language).toBe(200);
    expect(image.headers()["content-type"]).toBe("image/png");
    await bot.dispose();
  }
});

test("/check has its own title and description, not the home page's", async ({ page }) => {
  await page.goto("/ru");
  const homeDescription = await page.locator('meta[name="description"]').getAttribute("content");
  await page.goto("/ru/check");
  expect(await page.locator('meta[name="description"]').getAttribute("content")).not.toBe(homeDescription);
});

async function robotsOf(page: Page, path: string): Promise<string> {
  await page.goto(path);
  return (await page.locator('meta[name="robots"]').getAttribute("content")) ?? "";
}

test("a curated /check site is indexable", async ({ page }) => {
  expect(await robotsOf(page, "/ru/check/sberbank.ru")).not.toContain("noindex");
  expect(await robotsOf(page, "/check/google.com")).not.toContain("noindex");
});

test("any other /check site, /audit and personal links are noindex but followed", async ({ page }) => {
  for (const path of [
    "/check/some-random-site-xyz.com",
    "/ru/check/some-random-site-xyz.com",
    "/audit/google.com",
    "/ru/audit/google.com/grade/F",
    "/ref/ABC123",
  ]) {
    const robots = await robotsOf(page, path);
    expect(robots, path).toContain("noindex");
    expect(robots, path).not.toContain("nofollow");
  }
});

async function sitemapUrls(request: APIRequestContext): Promise<string[]> {
  const body = await (await request.get("/sitemap.xml")).text();
  return [...body.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
}

test("sitemap.xml: every locale, curated /check sites, no /audit, no redirecting URLs", async ({ request }) => {
  const urls = await sitemapUrls(request);
  for (const loc of LOCALES) {
    expect(urls).toContain(abs(loc, "/"));
    expect(urls).toContain(abs(loc, "/check/google.com"));
  }
  expect(urls).toContain(`${SITE}/ru/check/sberbank.ru`);
  expect(urls.some((u) => u.includes("/audit/"))).toBe(false);
  expect(urls.some((u) => u.includes("some-random-site"))).toBe(false);
  expect(urls.filter((u) => u.endsWith("/") && u !== `${SITE}/`)).toEqual([]);
});

test("robots.txt allows crawling and points at the sitemap", async ({ request }) => {
  const body = await (await request.get("/robots.txt")).text();
  expect(body).toMatch(/User-agent: \*\nAllow: \//);
  expect(body).toContain("Sitemap: https://cleanway.ai/sitemap.xml");
});

test("bots that only read raw HTML get the metadata in <head>", async ({ request }) => {
  // /check/<site> renders on demand, where Next streams metadata into <body>
  // for anything it does not know as an HTML-only bot (next.config.ts).
  for (const ua of ["Mozilla/5.0 (compatible; Mail.RU_Bot/2.0; +http://go.mail.ru/help/robots)", "TelegramBot (like TwitterBot)", "Mozilla/5.0 (compatible; YandexBot/3.0)"]) {
    const html = await (await request.get("/ru/check/google.com", { headers: { "user-agent": ua } })).text();
    const head = html.split("</head>")[0];
    expect(head, ua).toContain('<link rel="canonical" href="https://cleanway.ai/ru/check/google.com"');
    expect(head, ua).toContain('property="og:image"');
  }
});

test("www.cleanway.ai redirects permanently to the apex", async ({ request }) => {
  const response = await request.get("/ru/pricing", { headers: { host: "www.cleanway.ai" }, maxRedirects: 0 });
  expect(response.status()).toBe(308);
  expect(response.headers()["location"]).toBe("https://cleanway.ai/ru/pricing");
});

test("home JSON-LD: a crawlable logo and the Android app", async ({ page }) => {
  await page.goto("/ru");
  const graph = await page.$$eval('script[type="application/ld+json"]', (scripts) =>
    scripts.flatMap((s) => (JSON.parse(s.textContent ?? "{}")["@graph"] ?? []) as Array<Record<string, unknown>>),
  );
  const org = graph.find((n) => n["@type"] === "Organization");
  expect(org?.logo).toBe("https://cleanway.ai/icon-192.png");
  const app = graph.find((n) => n["@type"] === "MobileApplication");
  expect(app?.operatingSystem).toBe("Android");
  expect(app?.installUrl).toBe("https://cleanway.ai/ru/android");
  const logo = await page.request.get("/icon-192.png");
  expect(logo.status()).toBe(200);
});

test("Russian pages name what people search for (links, SMS, site check)", async ({ page }) => {
  await page.goto("/ru");
  expect(await page.title()).toBe("Защита от мошенников: проверка ссылок и SMS — Cleanway");
  expect(await page.locator('meta[name="description"]').getAttribute("content")).toMatch(/^Проверка ссылок и SMS на мошенничество\./);
  await expect(page.getByText("Как проверить ссылку из SMS на мошенничество?")).toBeVisible();
  const graph = await page.$$eval('script[type="application/ld+json"]', (scripts) =>
    scripts.flatMap((s) => (JSON.parse(s.textContent ?? "{}")["@graph"] ?? []) as Array<Record<string, unknown>>),
  );
  const questions = (graph.find((n) => n["@type"] === "FAQPage")?.mainEntity as Array<{ name: string }>).map((q) => q.name);
  expect(questions).toContain("Как проверить ссылку из SMS на мошенничество?");

  await page.goto("/ru/check");
  expect(await page.title()).toBe("Проверить сайт или ссылку на мошенничество и фишинг — Cleanway");
  await expect(page.locator("h1")).toHaveText("Проверка сайта на мошенничество");
});
