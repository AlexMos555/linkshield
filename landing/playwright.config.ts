import { defineConfig, devices } from "@playwright/test";

/**
 * LinkShield landing E2E config.
 *
 * Runs against a local Next.js dev server by default. CI can override via
 * BASE_URL env var to point at staging/production.
 */
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

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
  ],

  // Spin up the Next.js dev server automatically when running locally
  webServer: process.env.BASE_URL
    ? undefined
    : {
        command: "npm run dev",
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
