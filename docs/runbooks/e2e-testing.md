# E2E Testing Runbook

Two surfaces, two stacks.

## Landing (Playwright)

- Config: `landing/playwright.config.ts`
- Specs:   `landing/e2e/*.spec.ts`
- Projects:
  - `chromium` (Desktop Chrome) — all `*.spec.ts` except `mobile.spec.ts`
  - `mobile-safari` (iPhone 14) — only `mobile.spec.ts`

### Local

```bash
cd landing
npm run e2e:install    # one-time — downloads chromium + webkit browsers
npm run e2e            # all tests, both projects
npm run e2e:headed     # watch the browser
npm run e2e:ui         # interactive UI mode
```

The config auto-starts `next dev` on port 3000 if nothing is listening.
Override the target with `BASE_URL`:

```bash
BASE_URL=https://staging.cleanway.ai npm run e2e
```

### CI

The workflow should:

1. `npm ci` in both root and `landing/`
2. `npx playwright install --with-deps chromium webkit` (cache `~/.cache/ms-playwright`)
3. Build the landing (`npm run build`)
4. Start the server (`npm start &`) or rely on `webServer` config
5. `cd landing && npm run e2e`
6. Upload `landing/playwright-report/` as a build artifact on failure

### Coverage

| Surface | Tests |
|---------|-------|
| Home, all 10 locales | `home renders all sections for locale=<locale>` |
| EN/RU copy sanity | `EN hero uses English copy`, `RU hero uses Russian copy` |
| Nav / footer links | `footer links to privacy policy and terms` |
| Pricing page | `pricing page renders three tiers` |
| Comparison table | `comparison table shows competitor columns` |
| FAQ expandable items | `FAQ section has expandable items` |
| Testimonials | `testimonials render three cards` |
| Mobile viewport | `mobile nav`, `no horizontal scroll`, `hero renders` |

**20 tests** across chromium + mobile-safari projects, ~40s runtime locally.

## Mobile (Expo / React Native)

E2E for the Expo app requires one of:

- **Detox** — real-device/simulator tests. Heavy setup: requires Xcode 15+,
  Android SDK, and a per-branch detox.config. Best for PR gating of
  critical flows.
- **Maestro** — YAML flows driven from the CLI. Lightweight; works with Expo
  Go and production builds. Best for smoke tests.

**Current status:** neither is wired up. The foundation (settings screen,
skill level picker, auth flow) is instead covered by:

1. `tsc --noEmit` in `mobile/` — blocks type regressions.
2. `npx expo export` in CI — catches bundler-level regressions.
3. Manual smoke on a physical device per release.

### Roadmap

When bandwidth allows, add Maestro flows in `mobile/.maestro/` for:

- First-run onboarding → auth skip → home tab visible
- Settings → Skill Level picker → switch to Granny → font scale persists
- URL check → result screen renders for safe / warning / danger
- Upgrade CTA → pricing screen opens

Maestro flows run in CI via `maestro cloud` (paid) or `maestro test`
against a local simulator. They do not require Xcode config in-repo,
which is why they're preferred over Detox for an Expo project.
