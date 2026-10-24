# Cleanway browser extension: store screenshots

Screenshots for the Chrome Web Store, Microsoft Edge Add-ons and Firefox AMO: 1280×800 PNG, 24-bit RGB with no alpha
channel, one set in English (`en/`) and one in Russian (`ru/`) with the same file names. Upload them in the order
given under "Upload order". They are taken in Chromium; the Edge, Firefox and Safari builds share the same
pages, styles and texts (`packages/extension-core`). They are made by
[`scripts/store-screenshots/extension.mjs`](../../scripts/store-screenshots/extension.mjs); this file is written by the
same run.

| File | What it shows |
|------|---------------|
| `01-block-page.png` | The block page for `parcel-redelivery-payment-verify.xyz`, opened from the red search result of 04: STOP, the site's name and the "Why we blocked this site" cards for the four signs the rules found. The tab was taken to the extension's own `src/blocked/blocked.html` when it opened that address, so the scam page never stays on screen. The page goes on below the 800 px window ("How scammers use sites like this", then "Go back to safety" and the "open anyway" button, captured after its 5-second countdown). |
| `02-popup-safe.png` | The toolbar popup on an ordinary recipe page (`recipes.example`): "This page is safe". The two Wikipedia links in the text carry green ticks. The welcome tip had been closed with its × button, as a person would. |
| `03-popup-caution.png` | The toolbar popup on a doubtful "pay the redelivery fee" page (`redelivery-payment-confirm.top`): the yellow "This site looks suspicious" state. Its second line names the site, says it shows some signs of a scam and advises against entering passwords or card details there. A caution verdict does not block the page. |
| `04-link-badges.png` | A search-results page (`search.example`) with a badge after every result: green ticks for Wikipedia and `help.parcel-service.example`, yellow marks for `redelivery-payment-confirm.top` and `track-parcel-update.xyz`, a red cross for `parcel-redelivery-payment-verify.xyz`. The red badge is hovered, so its tooltip shows the first three reasons. |
| `05-settings.png` | The top of the Settings page with its defaults: not signed in, the "Who uses this browser" choice, and email scanning off. |

## Upload order

| Listing | Upload, in this order |
|---------|-----------------------|
| `en/` | `01-block-page.png`, `02-popup-safe.png`, `03-popup-caution.png`, `04-link-badges.png`, `05-settings.png` |
| `ru/` | `01-block-page.png`, `02-popup-safe.png`, `03-popup-caution.png`, `04-link-badges.png`, `05-settings.png` |

## What is real and what is staged

- **The extension is the real build, unmodified.** `extension/` at version 0.2.2 (last changed in commit `f7925628`), loaded unpacked with `--load-extension` exactly as a person would load it. It is byte-identical to the store package `dist/store-artifacts/cleanway-0.2.2-chrome.zip`.
- **The pages are demo pages.** The script serves the search results, the recipe and the two parcel pages itself, on made-up hosts (`.example` for the ordinary sites, scam-shaped `.xyz`/`.top` names for the bad ones). No real brand is imitated; Wikipedia only appears as a link.
- **Every verdict comes from the extension's own rules.** The server is replaced by a stub inside the script, as in the browser test (`scripts/test-extension-sw.mjs`): it answers each site check with exactly the verdict the extension's offline rules (`src/utils/local-scorer.js`, read from the same build) give that host, and `GET /health` with 200 so the popup does not show its offline banner. With no server at all the extension shows the same badges and blocks the same page, because its content script scores every host itself first. Nothing the extension shows was invented by the script: no verdict, reason, count or score. The production server, which also uses blocklists, DNS, page checks and an ML model, may say more about real sites.
- **Not shown because the stub does not answer it:** the block page's "What kind of scam is this?" paragraph (`POST /api/v1/explain`). Without it the block page looks exactly as in 01, which is what a person sees when that answer does not arrive. The offline rules give no confidence figure, so no confidence chip appears either. The popup's statistics stay folded under "More".
- **The popup is the real toolbar popup**, opened with the DevTools command `Extensions.triggerAction`, which is what clicking the toolbar icon does (it also gives the popup `activeTab` for that tab). Chromium draws a popup outside the page, so its picture (full height, no scrollbar: it is under Chrome's 600 px popup limit) is placed at the top right of a screenshot of the same tab. That placing is the only composition; no browser toolbar or frame is drawn.
- **Nothing left the machine.** Chromium resolved every host name to nowhere (`--host-resolver-rules=MAP * ~NOTFOUND`), and every request was answered or refused by the script through DevTools `Fetch` interception. The extension's service worker was stopped once right after start-up, as Chrome stops idle MV3 workers, so that the fresh one started inside the interception.

## How they were captured

- **Date:** 2026-10-24
- **Browser:** Chrome/151.0.7922.34 (Chromium from Playwright 1.62.1), new headless mode, on macOS. Viewport 1280×800 at device scale factor 1.
- **Locale:** `en/`: Chromium UI language `en_US`; `ru/`: Chromium UI language `ru`. The extension has no language setting of its own: it follows the browser. The script refuses to capture if the extension's `@@ui_locale` does not match.
- **Persona:** the default (Regular), so badges show no risk numbers.

### Verdicts at capture time

| Host | Verdict | Offline reason codes | Where |
|------|---------|----------------------|-------|
| `search.example` | safe | none | 04 (the page) |
| `recipes.example` | safe | none | 02 (the page) |
| `help.parcel-service.example` | safe | none | 04 (green badge) |
| `parcel-redelivery-payment-verify.xyz` | dangerous | `risky_tld`, `suspicious_keyword`, `long_domain`, `many_hyphens`, `medium_entropy` | 01 (blocked), 04 (red badge) |
| `redelivery-payment-confirm.top` | caution | `risky_tld`, `suspicious_keyword`, `long_domain`, `medium_entropy` | 03 (the page), 04 (yellow badge) |
| `track-parcel-update.xyz` | caution | `risky_tld`, `suspicious_keyword` | 04 (yellow badge) |

The Wikipedia hosts are on the extension's built-in list of official sites and are answered without any check.

### Server requests the stub answered (both languages)

- `GET /api/v1/public/check/help.parcel-service.example → 200 safe`
- `GET /api/v1/public/check/parcel-redelivery-payment-verify.xyz → 200 dangerous`
- `GET /api/v1/public/check/recipes.example → 200 safe`
- `GET /api/v1/public/check/redelivery-payment-confirm.top → 200 caution`
- `GET /api/v1/public/check/search.example → 200 safe`
- `GET /api/v1/public/check/track-parcel-update.xyz → 200 caution`
- `GET /health → 200`
- `GET /health?from=screenshot-script → 200`
- `POST /api/v1/explain → 404`

`?from=screenshot-script` is the script's own request from the restarted service worker, to prove it reaches the stub; every other line is a request the extension made.

### Requests refused (would have gone to the internet)

- `https://parcel-redelivery-payment-verify.xyz/favicon.ico`
- `https://recipes.example/favicon.ico`
- `https://redelivery-payment-confirm.top/favicon.ico`
- `https://search.example/favicon.ico`

## How to recapture

From the repository root, with Playwright installed in a throwaway folder (as the e2e workflow does; no repository
dependency is added):

```sh
T="${TMPDIR:-/tmp}/cw-shots"
npm install --prefix "$T" --no-audit --no-fund playwright@1.62.1
"$T/node_modules/.bin/playwright" install chromium     # skipped if this Chromium is already cached
NODE_PATH="$T/node_modules" node scripts/store-screenshots/extension.mjs     # en + ru, about 2 minutes
rm -rf "$T"
```

- `--ext <dir>` loads another unpacked build, for example the store ZIP unzipped into a folder.
- `en` or `ru` alone retakes one language (this README is only rewritten after a run in both).
- The run fails rather than capture a wrong state: a demo host whose verdict changed (in the source tree or in the store ZIP), a missing or wrong badge, a tooltip covering another badge, a popup in the wrong state, with its offline banner or taller than 600 px, a block page that did not appear, a worker the stub cannot reach.
- On macOS, Chromium ignores `--lang`, so the script starts it through a two-line wrapper that adds `-AppleLanguages (<lang>)`. On Linux `--lang` and `LANGUAGE` are enough.
- Fonts come from the OS: the committed set was rendered on macOS; on Linux the text looks different.
