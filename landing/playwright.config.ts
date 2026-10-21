import { defineConfig, devices } from "@playwright/test";

/**
 * Cleanway landing E2E config.
 *
 * Runs against a local Next.js dev server by default. CI can override via
 * BASE_URL env var to point at staging/production.
 */
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const MOCK_API_PORT = Number(process.env.MOCK_API_PORT || 3999);
const MOCK_API_URL = `http://127.0.0.1:${MOCK_API_PORT}`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  // Fail the build on `test.only`
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [["github"], ["html"]] : [["list"], ["html"]],

  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      // Mobile-specific specs should NOT run on desktop viewport
      testIgnore: /mobile\.spec\.ts$/,
    },
    // Mobile viewport smoke — ensures the layout doesn't catastrophically break
    {
      name: "mobile-safari",
      use: { ...devices["iPhone 14"] },
      testMatch: /mobile\.spec\.ts$/,
    },
    // Android UA + viewport — the primary CTA must resolve to the app page
    // (/android), never /dns: strict Private DNS conflicts with the app's
    // VPN shield. Chromium-based, so no extra browser install.
    {
      name: "android",
      use: { ...devices["Pixel 7"] },
      testMatch: /mobile\.spec\.ts$/,
    },
  ],

  // Spin up the Next.js dev server automatically when running locally
  webServer: process.env.BASE_URL
    ? undefined
    : [
        // A stand-in for the API's public check endpoint, so /check/<domain>
        // renders (e2e/a11y.spec.ts audits it) without calling the production
        // API, which is rate-limited per IP. Only that page (and its share
        // image) reads API_URL on the server; client-side calls are untouched.
        {
          command: "node e2e/mock-api.mjs",
          url: `${MOCK_API_URL}/health`,
          env: { MOCK_API_PORT: String(MOCK_API_PORT) },
          reuseExistingServer: !process.env.CI,
          timeout: 10_000,
        },
        {
          // CI already ran `npm run build`: test the artifact that ships (prod
          // CSP, prod bundles) instead of the dev server. Locally, keep dev.
          command: process.env.CI ? "npm run start" : "npm run dev",
          url: BASE_URL,
          env: { API_URL: MOCK_API_URL },
          reuseExistingServer: !process.env.CI,
          timeout: 120_000,
        },
      ],
});
