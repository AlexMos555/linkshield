# Cleanway browser extension: store screenshots

These are screenshots for the Chrome Web Store, Microsoft Edge Add-ons and Firefox AMO. Each one is a 1280x800 PNG with 8-bit RGB and no alpha channel. There is one set in English (`en/`) and one in Russian (`ru/`). Every image is a capture of the real extension, with no captions, frames or marketing text added.

## Files

The file names are the same in `en/` and `ru/`.

| File | What it shows |
|------|---------------|
| `01-link-badges.png` | An ordinary page of shared links with Cleanway's badges next to each link. Wikipedia and GitHub get green ticks. `parcel-fee-redelivery.top` and `prize-claim-now.xyz` get yellow warning marks. `account-verify-login-secure.netlify.app` gets a red cross, and its tooltip (opened by hovering) lists the three reasons for the verdict. |
| `02-popup-verdict.png` | The toolbar popup on the blocked scam tab: "This is a scam site" with the "Close this page" button. It sits at the top right, over the block page of that same tab. **This one is a composite, see below.** |
| `03-block-page.png` | The full-page block that the extension puts over `account-verify-login-secure.netlify.app` by itself: STOP, the domain, and the "Why we blocked this site" evidence cards. It was captured after the 5-second countdown on the "continue anyway" button had finished. |
| `04-credential-warning.png` | The credential guard on a sign-in page at `secure-login-update.xyz`. The form's password would be posted to a different site (`collector-endpoint.example`) and the address is on a `.xyz` domain, so the full red "Stop — this looks like a scam page" banner appears. Nothing was typed into the form and it was never submitted. |
| `05-settings.png` | The top of the Settings page: Account (not signed in), the "Who uses this browser" persona picker, and the start of "Email scanning" with the switch off, which is the default. |

No shots were dropped. All five planned screens were captured in both languages.

## How they were captured

- **Date:** 2026-10-13
- **Build:** the unpacked `extension/` folder at version 0.2.0 (MV3), loaded with `--load-extension` exactly as a user would load it.
- **Browser:** Chromium 151.0.7922.34 (Chrome for Testing from Playwright 1.62.1), new headless mode, on macOS. The viewport was 1280x800 at device scale factor 1.
- **Locale:** for each set, Chromium's UI language was set (`-AppleLanguages`, `--lang` and `LANGUAGE`). The extension reported `chrome.i18n` UI locale `en_US` (which uses `_locales/en`) and `ru` respectively. The script refuses to capture if the locale does not match. The extension has no language setting of its own: it follows the browser's language.
- **API:** the extension's built-in default, the production `https://api.cleanway.ai`. It made only read-only `GET /api/v1/public/check/<host>` calls. There was no sign-in, webmail scanning stayed off, and no form was submitted.
- **Demo pages:** the link page (`https://news.example/`), the sign-in page (`https://secure-login-update.xyz/`) and a near-empty "Loading…" page at the scam host are served locally through Playwright `context.route`. Every badge, verdict, warning, block page and popup state comes from the extension and the live API. None of them is injected. The page texts are generic and imitate no real brand.

### Verdicts from the production API at capture time

| Host | Verdict | Where it appears |
|------|---------|------------------|
| `en.wikipedia.org` | safe (the extension's built-in known-site list, no API call) | 01 |
| `github.com` | safe, score 0 | 01 |
| `parcel-fee-redelivery.top` | caution, score 25 (the address does not resolve) | 01 |
| `prize-claim-now.xyz` | caution, score 25 (the address does not resolve) | 01 |
| `account-verify-login-secure.netlify.app` | **dangerous**, score 65 (missing security headers, hyphen-heavy name, ML phishing model) | 01, 02, 03 |
| `secure-login-update.xyz` | caution, score 25 | 04 (the banner itself comes from the on-page credential check) |
| `news.example` | caution, score 25 | host of the demo page in 01; no badge is drawn for the page's own host |

### The popup shot (02) is a composite

A toolbar popup cannot be screenshotted in headless Chromium, and a script cannot click the toolbar icon. The capture works around both limits as follows:

1. The real `src/popup/popup.html` is opened as a background tab in the same window, next to the blocked scam tab. Its "current tab" query then returns the scam page, just as it would from the toolbar.
2. Normally a toolbar click lets the popup read the current tab's address through `activeTab`. For this shot only, the extension is loaded from a temporary copy whose `manifest.json` also lists the `tabs` permission, to stand in for that grant. Nothing else in the copy is different.
3. The popup element (380 px wide) is captured and placed at the top right of a screenshot of the same tab, with a drop shadow.

The popup's texts and states are the extension's own, and the first-run welcome tip is what a new user sees. Shots 01, 03, 04 and 05 use the unmodified `extension/` folder.

## How to recapture

From the repository root, with Playwright and its Chromium installed (`npx playwright install chromium`):

```sh
NODE_PATH=$PWD/node_modules node store-assets/browser-extension/screenshots/capture.mjs en ru
# only the popup:  ... capture.mjs en ru --popup-only
```

The script is [`capture.mjs`](capture.mjs). It writes `en/` and `ru/` next to itself and prints each verdict it receives from the API.

- **macOS `sips`:** used to flatten the output to PNGs without alpha (a lossless-quality JPEG round-trip). On Linux, swap it for any JPEG-to-PNG conversion. Linux Chromium also honours `--lang` and `LANGUAGE` without the `-AppleLanguages` wrapper.
- **API limits:** the public check endpoint allows about 60 requests per hour per IP. A full two-language run uses about 21.
- **Warm-up requests:** the extension waits only 3 seconds for the API and otherwise uses its offline scorer. The script therefore asks the API about each host once before it opens the browser. The server caches the verdict, and the extension then gets the same answer in time.
- **Verdicts can change:** they are live. If a host stops coming back as dangerous or caution, pick another one with `curl -s https://api.cleanway.ai/api/v1/public/check/<host>` and update the constants at the top of the script. Never use a look-alike of a real brand.
- **Slow first start:** on a heavily loaded Mac, the first Chromium start can take several minutes. The launch has no timeout.
