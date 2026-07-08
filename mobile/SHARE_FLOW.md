# Mobile Share Flow — build & verify (branch `mobile-share-flow`)

Wires the **"Share → Cleanway"** flow so a link from ANY app (Safari, Messages,
WhatsApp, Telegram, Mail…) can be shared into Cleanway and instantly checked. This
was ~80% built already — `app/shared.tsx` runs the full domain check and shows the
verdict + haptics — but the shared link never reached it. This branch adds the
missing bridge (`expo-share-intent`: iOS Share Extension + Android `ACTION_SEND`).

> ✅ **Typecheck-verified · ⚠️ not yet prebuilt/device-tested.** `npx tsc --noEmit`
> passes with **0 new type errors** — the `expo-share-intent@3.2.3` API usage in
> `_layout.tsx` (`useShareIntentContext()` → `{ hasShareIntent, shareIntent,
> resetShareIntent }`, `shareIntent.webUrl`/`.text`) is correct for SDK 52. (The 4
> pre-existing `tsc` errors are all in `app/(tabs)/_layout.tsx`, unrelated, present on
> `main` too.)
>
> **Correction to an earlier note:** the mobile toolchain blocker was NOT the Node
> version — it was a stale `mobile/node_modules` missing `@expo/cli`. A plain
> `npm install` (Node 20) repaired it and installed `expo-share-intent`.
>
> **`npx expo prebuild` is still blocked** by a pre-existing monorepo node_modules
> hoisting issue: `@expo/cli` resolves from the **repo-root** `node_modules`, whose
> `expo-router` plugin then fails to resolve `schema-utils`. Fix on your build machine
> with a clean isolated install before prebuild (below). This is unrelated to the
> share-flow code. It is on a branch, not `main`, until you prebuild + device-test.

## What changed
- `package.json` — added `expo-share-intent` (pinned `^3.2.1`; **reconcile the exact
  SDK-52 version with `npx expo install expo-share-intent`** — do this first).
- `app.json` — added the `expo-share-intent` config plugin (creates the iOS Share
  Extension target + wires Android intent handling; `iosShareExtensionName`,
  web-URL + text activation rules, `androidIntentFilters: ["text/*"]`).
- `app/_layout.tsx` — wrapped the root in `<ShareIntentProvider>` and added a
  `ShareIntentRouter` that pushes an inbound shared URL/text to `/shared?url=…`.
- `app/shared.tsx` — unchanged (already complete).

## Build & test (needs a Mac with Xcode for iOS; Node 18 or 20)

```bash
cd mobile
nvm use 20                      # or fnm/volta
# clean, isolated install fixes the monorepo hoist (schema-utils) that blocks prebuild:
rm -rf node_modules && npm install
npx expo install expo-share-intent   # confirms the SDK-52 version (3.2.3)
npx expo prebuild --clean            # regenerates ios/ + android/ WITH the extension
# iOS (device required — Share Extension can't run in Simulator reliably):
npx expo run:ios --device
# Android:
npx expo run:android
```

## On-device verification checklist
- [ ] `npx expo prebuild` completes without plugin errors.
- [ ] TypeScript: `npx tsc --noEmit` is clean (verifies the `useShareIntentContext`
      API shape I used — `{ hasShareIntent, shareIntent, resetShareIntent }` and
      `shareIntent.webUrl` / `shareIntent.text`; fix names if the installed version
      differs).
- [ ] iOS: "Cleanway — Check Link" appears in the Share Sheet from Safari and from
      WhatsApp (long-press a link → Share).
- [ ] Android: Cleanway appears in the share sheet for a text/link share.
- [ ] Sharing a **known-bad** link opens `/shared` and shows a DANGEROUS verdict.
- [ ] Sharing a safe link shows a safe verdict. Empty/invalid share → graceful
      "No valid URL shared".

## Known risks to check (couldn't verify here)
1. **Version/API drift** — if `expo-share-intent` resolves to a version whose hook
   returns different field names, `tsc` will flag it; adjust `ShareIntentRouter`.
2. **Android duplicate share target** — `app.json` still has a manual
   `android.intentFilters` `ACTION_SEND text/plain` entry from before. If the plugin
   also registers `SEND` and you see Cleanway twice in the share sheet, remove that
   manual entry (keep the `VIEW`/`BROWSABLE` `cleanway` scheme filter — that's for
   deep links, unrelated).
3. **iOS App Group** — the plugin sets up the extension↔app App Group; confirm the
   provisioning profile includes it (EAS handles this if the extension is declared).
4. **Cold-start navigation** — if sharing on a fully-cold app throws a "navigate
   before ready" error, gate the `router.push` behind a short `rootNavigationState`
   readiness check (expo-router `useRootNavigationState`).

## Why this first (vs the DNS-VPN)
Share flow has **zero store-policy gates**, ships on **both** platforms, and is the
only iOS path that reaches links opened inside messenger in-app browsers. The
system-wide **DNS-VPN** (also ~written, in `mobile/native/`) is the fuller "automatic
at open-time" protection but is gated on an **Organization** Apple Developer account
(App Review 5.4) + a config-plugin/native-module wiring effort. See
`memory/project_mobile_protection_state.md` for the full sequence.
