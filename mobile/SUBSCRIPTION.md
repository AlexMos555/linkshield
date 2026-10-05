# The subscription in the app (billing plan A.10, §2.5)

**Status: built, switched off.** `EXPO_PUBLIC_BILLING_RU_ENABLED` is unset by
default; with it unset there is no subscription screen, no home card, no call
to the billing server, and the native shield holds no pass (`billing.boot()`
clears one left by an earlier build). Nothing changes for today's users until
the founder sets the switch in a build (`.env.example`).

The server side is `api/billing` (`docs/BILLING.md`, PR #65). The app is
written against its `/billing/v1` contract: device auth by bearer secret, the
Ed25519 device pass, the status snapshot, plans, checkout, cancel, seats and
claim codes.

## Where things live

| Piece | File | Pinned by |
|---|---|---|
| The switch, host, public keys | `src/config/billing.ts` | `scripts/test-billing-view.mjs` |
| The device pass: verify, read back, the offline rule | `src/lib/entitlement.ts` | `scripts/test-entitlement.mjs` (the server's cases) |
| `/billing/v1` client | `src/lib/billing-api.ts` | `scripts/test-billing-api.mjs` |
| What the phone keeps (SecureStore), the "installed before paid launch" marker | `src/services/billing-store.ts` | — |
| The store the screens read, the actions behind the buttons | `src/services/billing.ts`, `src/hooks/useBilling.ts` | — |
| State → screen | `src/utils/billing-view.ts` | `scripts/test-billing-view.mjs` |
| Reminders (when, which, never a link) | `src/utils/billing-reminders.ts`, `src/services/billing-notify.ts` | `scripts/test-billing-reminders.mjs` |
| The claim code as a QR | `src/utils/qr.ts`, `src/components/billing/QrCode.tsx` | `scripts/test-qr.mjs` (independent read-back) |
| Screens | `app/subscription/*` | — |
| Native modes full / basic / off, weekly list in basic, the yellow-shield notification | `modules/cleanway-vpn/android/.../ProtectionPolicy.kt`, `CleanwayVpnService.kt`, `BlocklistSync.kt` | `ProtectionPolicyTest.kt` |

## The pass is the truth

`GET /entitlement` answers with a signed pass and a status snapshot. The app
verifies the pass (`verifyPass`: signature, kid, version, `exp`), stores it,
and hands its claims to the native shield (`setProtectionPass`). From then on
the shield applies the pass's own clock rule by itself
(`ProtectionPolicy.effectiveMode`, a 1:1 port of the server's `offline_mode`):
full until `until`, still full through `grace_until`, then `lapse_policy`
(`basic` or `off`). A trial that ends at 03:00 ends at 03:00 with the app
closed; a clock turned back extends nothing.

`basic`: blocking continues from the list, the list is refreshed once a week
(`BlocklistSync.refreshMs`), a week-old list is not "stale", the ongoing
notification says so ("yellow shield"), and the home hero says "Basic
protection". `off`: the tunnel stays up (the phone's DNS keeps working) but
nothing is blocked, and both say so. The founder has not chosen; the server
setting `BILLING_LAPSE_POLICY` decides, and the app builds both.

## Screens (`app/subscription/`)

`index` hub (trial with "осталось N дней", active with next charge and seats,
grace with its window and what follows, cancelled with the end date, lapsed
with what is left, legacy) · `plans` (from `/plans`, nothing hard-coded) ·
`checkout` (the ru/v1 consent text with the price and the masked number, then
"Получить SMS-код") · `sms` (polls the checkout; every failure says nothing was
charged) · `add-phone` (6-digit code, QR, "Отправить маме") · `join` ("У меня
есть код от родственника", also on the last onboarding slide) · `devices`
(the payer's list with "Убрать телефон из подписки").

Cancel is one tap on the hub plus one confirmation that says plainly until when
protection runs and what it becomes.

## Reminders

Local notifications (`expo-notifications`), scheduled by date so they fire
with the app closed: 3 days and 1 day before a trial ends; days 1, 3, 5, 7 of
grace (the server's retry days), never two closer than two days; one notice
on a lapse. No reminder carries a link — the test reads every locale. Known
limit: a reminder whose moment comes while the app is in the foreground is
not shown (no foreground handler is installed); the home card says the same
thing.

## Grandfathering

`billing-store.installMarkerAfterLaunch` writes, once, whether this phone was
installed before the paid launch (the switch was off, or the onboarding was
completed by a build without billing). `POST /devices` sends it as
`legacy_claim`; the server marks it unverified. The decision is the founder's;
the fact is kept either way.

## Not done here

- No emulator or device run in this pass: unit tests, `tsc` and the Kotlin JVM
  tests only. The screens, the notification scheduling and `setProtectionPass`
  over the bridge have not been exercised on a phone.
- Reminders in the foreground (above); a native alarm would be the robust path.
- The Fake provider's SMS is a stub: the server's test numbers decide the
  outcome; the screen only polls and names it.
- The seller's details on the consent screen come from the terms page; the
  server's `/plans` does not yet carry `legal_name` / INN / the STOP number.
