# Calls: the stop screen, the after-call notice, and notification hygiene

Status: shipped in the Android app (branch `feat/in-call-stop-kran`, 2026-10).
Final-stage plan §2 №5 (calls, honestly) and №7 (notification hygiene).
Texts and thresholds below are the ones the founder is asked to approve.

## 1. What Cleanway can and cannot know about a call

A third-party Android app cannot say "this call is from a scammer": the
call-screening role is exclusive (it would evict Yandex/Kaspersky caller ID),
`CallScreeningService` sees the number and direction only, there is no audio,
and the operator already labels calls for free. So this build **asks for no
call permission at all** — no `READ_PHONE_STATE`, no `READ_CALL_LOG`, no
`ANSWER_PHONE_CALLS`, no `ROLE_CALL_SCREENING` — and the guard that keeps it
that way runs in CI (`mobile/scripts/check-android-permissions.mjs`) and in the
Kotlin suite (`PolicyGuardTest`). `app.json` additionally strips the phone
permissions at manifest merge, so a library cannot bring one in.

What it CAN see, with no permission: the phone's **audio mode**
(`AudioManager.getMode()`): `MODE_IN_CALL` is a SIM call, `MODE_IN_COMMUNICATION`
a call inside WhatsApp / Telegram / MAX, `MODE_RINGTONE` a ringing phone.
`CallState.kt` turns that into "in a call since T" and "last call ended at T",
on Android 12+ through `addOnModeChangedListener` (free), before that by polling
every 3 s only while something holds the watcher (the VPN service while the
tunnel is up, the app while it is open). Ringing that is never answered is not a
call. Nothing here names a caller, a number or a verdict about the call, and
nothing user-facing calls it "ИИ".

## 2. The stop screen (стоп-кран)

Every phone scam ends with the same request: switch the protection off, open
this site, allow it, install this app. So while a call is going on **and for 30
minutes after it ends** ("hang up, I'll call you back" is the standard move),
these actions open a full-screen stop first:

- «Приостановить защиту» (home) — before the pause sheet;
- «Это не мошенники — разрешить» (History detail) — before the confirm;
- «Всё равно открыть» (the link guard's block screen, non-safe verdicts);
- the VPN-exclusion picker, once #60 lands: `useCallGuard().guard("exclude_app", openPicker)`.

Russian texts (10 locales in `packages/i18n-strings/src/<locale>.json`, `mobile.call_guard.*`):

| | |
|---|---|
| In a call, title | Вы сейчас разговариваете по телефону |
| In a call, body | Если вас просят отключить защиту, открыть сайт или установить приложение — это мошенники. Положите трубку. |
| After a call, title | Вы только что говорили по телефону |
| After a call, body | Если звонивший просил отключить защиту, открыть сайт или установить приложение — это мошенники. Не делайте этого и не перезванивайте по номеру, который он назвал. |
| Primary button | Положить трубку и оставить защиту (in a call) / Оставить защиту (after) |
| Slow path | Я понимаю, это мой звонок ({{seconds}}) → enabled after a 5-second countdown, then the original action |
| Hint under it | Подождите несколько секунд. Если сомневаетесь — положите трубку. |
| Honesty line | Cleanway не определяет номера, не блокирует звонки и не слушает разговоры. Кто звонит — показывает ваш оператор. |

«Положить трубку» cannot end the call for the person (that needs a permission
this app does not ask for); it brings the phone app's own screen to the front.
A build that cannot see calls (iOS, an older native module) never shows the
screen: `callState()` is null there and the action simply runs.

Opening the screen for a guarded action is itself recorded as the event
`protection_off_asked` for the notice below — the attempt is the signal,
whichever button follows.

## 3. «Мне звонят» — the same screen on demand

A big, calm card on the home screen opens the screen with no action behind it:
«Звонят из банка, полиции или госуслуг?» / «Положите трубку. Настоящий банк не
просит назвать код из SMS, перевести деньги на «безопасный счёт», отключить
защиту или установить приложение. Перезвоните в банк сами — по номеру на
обратной стороне карты.» Button «Понятно»; «Позвонить близкому» appears only
when a number is saved (§5).

## 4. The after-call notice — only with a concrete reason

No notice after an ordinary call. One goes out only when Cleanway **saw
something during the call or within 30 minutes after it** (`CallGuard.kt`):

| event | weight | reason line (RU) |
|---|---|---|
| the shield or the link guard stopped a site | 1 | Во время звонка или сразу после него Cleanway остановил опасный сайт. |
| the link guard warned about a site that had opened | 2 | …открылся сайт, похожий на мошеннический. |
| a message check came back dangerous (on-device, or raised by the server) | 3 | …вы проверили опасное сообщение. |
| the stop screen was reached (pause / allow / open anyway) | 4 | …вы пытались отключить защиту. |
| a new app install | reserved | …на телефон установили новое приложение. |

Title: «Вам только что звонили». Text: the heaviest reason line, then «Если
звонивший просил назвать код, перевести деньги, открыть сайт или установить
приложение — это мошенники. Ничего не переводите и никому не называйте коды.»
Events during the call are reported one minute after it ends (the hang-up
screen is still up at the moment it ends); an event inside the 30-minute
window is reported at once. **At most one notice per call.** The notice never
carries a link or a phone number; its one action, «Позвонить близкому», shows
only when a number is saved and opens the dialer (`ACTION_DIAL`, the person
presses call herself). A tap opens the on-demand screen.

## 5. The "close one" number — the hook for #55

`CloseContact.kt` keeps one number in the app's no-backup directory; nothing in
this branch writes it. The checkup screen (#55) mirrors its secure-store
contact through `setCloseContactPhone()` from its save/clear paths. Until then
every «Позвонить близкому» button and notification action stays hidden.

## 6. Notification hygiene (plan №7)

`AlertBudget.kt`, JVM-tested in `AlertBudgetTest`:

- **«Опасно» pops up** (high-importance channel): a site stopped by the shield,
  a late warning whose server verdict was *dangerous*, the after-call notice.
  Caps: **3 pop-ups an hour, 10 a day**. Past the cap, one collapsed, silent
  «Ещё подозрительных сайтов: N» stands in for the rest (updated in place; tap
  opens History). Every event stays in History regardless.
- **«Осторожно» is silent**: a late warning whose verdict was *caution* (even
  with the model sure) posts on a low-importance channel — no heads-up, no sound.
- **One pop-up per site in 6 hours.** A repeat inside that window still
  refreshes the same notification silently, so a second try at a site never
  looks like the shield did nothing (the 1.0.3 complaint).
- **The 45-second burst window stays**: lookups of one site closer together
  than that (A, AAAA, HTTPS, the browser's retries) are one attempt.
- **No links, no phone numbers** in any of our notifications — pinned by
  `scripts/check-mobile-i18n.py` (CI) and `PolicyGuardTest`. The site name
  stays plain text.
- Per-*sender* throttling applies to the RuStore SMS build only; the browser
  APK never reads messages on its own.

## 7. What was not verified

Kotlin JVM tests, the JS table/hook tests and `tsc` ran. No emulator or device
run in this track: the audio-mode listener, the dialer hand-off and the
notification channels were not exercised on a phone. The RuStore track owns the
emulator; a real-device pass with a SIM call and a messenger call is still due.
