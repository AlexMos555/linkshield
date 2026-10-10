# App Store screenshots — iPhone 6.9" (1320 × 2868)

Unedited frames from the Release build on the iOS 26.2 simulator (iPhone 17 Pro Max), status bar 9:41, captured 2026-10-10 from the code of #149 and #150. Upload in this order; `en/` for English (U.S.), `ru/` for Russian.

| # | File | Shows |
|---|---|---|
| 1 | `01-home.png` | Home: "Check a message" and "Check anything" |
| 2 | `02-result-dangerous.png` | A link check: "Dangerous", with the reasons |
| 3 | `03-message-scam.png` | A message check: "Looks like a scam", reasons, the link's server answer |
| 4 | `04-sms-filter.png` | Setting up the scam-text filter, with its limits |
| 5 | `05-safari-setup.png` | Turning on the Safari extension |

Rules kept (docs/IOS.md §3.7, docs/APP_STORE_LISTING.md):
- no "VPN" anywhere — the DNS protection sheet names Apple's "VPN & Device Management" page, so it is left out;
- no real brand in an example: the scam site is `account-verify-login-secure.netlify.app`, the scam text a generic parcel fee;
- the SMS filter frame states its limits (unknown senders only, never iMessage).

Recapture when one of these screens changes: build the app for the simulator (`docs/IOS.md` §1.1), `xcrun simctl status_bar <udid> override --time 9:41 --batteryState discharging --batteryLevel 100`, then `xcrun simctl io <udid> screenshot`. Put Russian text on the simulator clipboard with `LANG=en_US.UTF-8 xcrun simctl pbcopy` — without it the text arrives garbled.
