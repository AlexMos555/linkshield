# Shield Checklist — Visual Design Spec (mobile, dark theme)

**Status:** Ready to implement · **Date:** 2026-07-30
**Scope:** New home screen (Shield Checklist) replacing `mobile/app/(tabs)/index.tsx`, plus a light modernization pass on `mobile/app/check.tsx` and `mobile/app/result.tsx`.
**Authority:** Layout + honesty states are FIXED requirements from `docs/MOBILE_AUTO_PROTECTION.md` §2 (as amended by its own adversarial critique: hero absolutes 3.3, "every app" 3.2, "before you type" 3.5, network-blocked remedy 2.2, honor-system counting 2.5). This document only decides the *visuals* and the exact EN strings.
**Language:** English copy only in this spec. Keys must be added to `packages/i18n-strings/src/` and rebuilt via `scripts/build-i18n.py` — never hand-edit `mobile/i18n` (generated).
**Direction:** 2026-modern fintech-trust. Deep ink-navy, one green (verified-ON only), blue for setup CTAs, amber for attention. Soft elevated cards, no heavy shadows, generous whitespace. No emoji as UI icons anywhere.

---

## 1. Design tokens

Extend/replace `mobile/src/utils/theme.ts`. Old keys stay exported (other screens reference them) but their values update to the new palette so the whole app shifts together. New keys are additive.

### 1.1 Color — core

| Token | Hex | Usage |
|---|---|---|
| `bg` | `#0B1220` | Screen background (was `#0f172a` — global update, intentional) |
| `surface` | `#FFFFFF0A` (4% white) | Card fill. Solid fallback if overdraw issues: `#141A28` |
| `surfaceRaised` | `#FFFFFF12` (7% white) | Card pressed state / input focus fill. Solid: `#1A2233` |
| `stroke` | `#FFFFFF14` (8% white) | 1px card border. Solid: `#1E2536` |
| `hairline` | `#FFFFFF0F` (6% white) | Row separators inside cards |
| `textPrimary` | `#F1F5F9` | Headings, primary copy |
| `textSecondary` | `#94A3B8` | Body copy, card descriptions, **honesty ⓘ lines** (7.2:1 on bg — passes AA at 13pt) |
| `textMuted` | `#6B7A93` | Section headers, captions, placeholder (4.3:1 — only ≥13pt semibold or decorative) |
| `textDisabled` | `#475569` | Rolling-out section only |

### 1.2 Color — semantic (the only three hues in the app)

| Token | Hex | Usage — strict |
|---|---|---|
| `green` | `#34D399` | Verified-ON shields, hero when ≥1 verified, "safe" verdict. **Never** appears on anything unverified. |
| `greenWash` | `#34D3991F` (12%) | ON-pill fill, safe-verdict card tint |
| `greenStroke` | `#34D39940` (25%) | ON-pill border, hero ring when active, safe card border |
| `blue` | `#4C8DFF` | Setup CTAs, links, primary buttons |
| `bluePressed` | `#3A75E8` | Pressed state of blue buttons |
| `blueWash` | `#4C8DFF1F` | Selected chips, recent-chip fill |
| `amber` | `#FBBF24` | CONFLICT / NETWORK BLOCKED / UNVERIFIABLE states, "caution" verdict |
| `amberWash` | `#FBBF241F` | Attention pill fill, caution card tint |
| `danger` | `#F87171` | "dangerous" verdict text/ring (result screen only — never on the checklist) |
| `dangerWash` | `#F871711F` | Dangerous verdict card tint |

Button text on `blue`: `#FFFFFF` at weight 700 (contrast 3.2:1 — acceptable for 15pt/700 button labels; primary CTA uses 17pt to clear AA-large).

### 1.3 Spacing (4/8pt grid)

`space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 20, xxl: 24, xxxl: 32, huge: 48 }`

Screen gutter: **20** horizontal. Vertical rhythm between cards: **12**. Between sections: **28** (24 + 4 optical). Top of scroll content: **8** below the safe area. Bottom padding: **120** (tab bar clearance).

### 1.4 Radii

| Token | Value | Usage |
|---|---|---|
| `radius.card` | 20 | All cards |
| `radius.control` | 14 | Primary CTA, text input |
| `radius.pill` | 10 | Small Set-up button, status pills |
| `radius.chip` | 10 | Action chips, domain chips |
| `radius.icon` | 12 | 40×40 leading icon containers |
| `radius.full` | 999 | Hero ring, score ring |

**No shadows.** Elevation is expressed only by `surface` fill + `stroke` border. (RN `elevation`/`shadow*` props: do not use.)

### 1.5 Type scale (system font — SF on iOS, Roboto on Android)

| Style | Size/Line | Weight | Usage |
|---|---|---|---|
| `display` | 34/40 | 700 | Score number in result ring |
| `title1` | 28/34 | 600 | Screen titles ("Check a link") |
| `title2` | 20/25 | 600 | Hero status line, card group verdict label |
| `headline` | 17/22 | 600 | Card titles |
| `body` | 15/20 | 400 | Descriptions, body copy |
| `caption` | 13/18 | 400 | Honesty ⓘ lines, footnotes, pills (600 for pill labels) |

Section headers: 13/18, weight 600, uppercase, letterSpacing 0.6, color `textMuted`.

### 1.6 Iconography — no emoji

Use `@expo/vector-icons` **Ionicons** (ships with Expo; no new dependency). All icons stroke-style (`-outline` variants) at 22pt inside 40×40 containers, except where noted.

| Concept | Ionicon name |
|---|---|
| Hero shield (neutral) | `shield-outline` |
| Hero shield (≥1 verified) | `shield-checkmark` |
| Every app (network) | `globe-outline` |
| Your browser | `compass-outline` |
| Text messages | `chatbubble-outline` |
| Check anything | `search-outline` |
| Paste | `clipboard-outline` |
| Scan QR | `qr-code-outline` |
| Share | `share-outline` |
| Honesty line marker | `information-circle-outline` (13pt, inline, `textSecondary`) |
| Chevron | `chevron-forward` (18pt, `textMuted`) |
| Attention | `alert-circle` (amber) |
| Paused | `pause-circle-outline` |
| Verified check (in ON pill) | `checkmark-circle` (16pt, green) |
| Privacy footnote lock | `lock-closed-outline` (13pt) |

The modernization pass **removes every emoji** currently used as an icon in `index.tsx`, `check.tsx`, `result.tsx` (🛡 📋 🔗 ✅ ⚠️ ❌ 🔒 etc.).

---

## 2. Home screen — Shield Checklist

Replaces `mobile/app/(tabs)/index.tsx` entirely. **Kills** the placebo `isProtected` toggle and the clipboard auto-monitor banner (kill-list items — clipboard monitoring is KILLED, not restyled).

### 2.1 Section order (top → bottom)

1. **Hero shield** (centered)
2. **Primary CTA** — only rendered when ≥1 shield is in NEEDS SETUP on this platform
3. **Shield cards** — shields that are *built and verifiable on this platform* (Android v1: Every app. iOS v1: none — section renders empty)
4. **Check anything card** — always present, always fully interactive. On iOS v1 it therefore sits directly under the hero: it is the working product there.
5. **Rolling out** — muted, non-interactive section for unbuilt shields on this platform
6. **Activity strip** (optional, keep if stats exist): 3 columns Checked / Blocked / Warned, numbers 20/600 `textPrimary`, labels caption `textMuted`, in one `surface` card, radius 20, no border emphasis
7. **Privacy footnote** (caption, centered, `textMuted`, lock icon): honest per current posture — see copy `home.privacy`

### 2.2 Hero shield

- Container: centered, marginTop 16, marginBottom 8.
- **Ring:** 160pt diameter, 2.5pt stroke, `radius.full`. Quiet gradient: if `react-native-svg` is already in `mobile/package.json`, draw an SVG circle with a linear gradient stroke; otherwise two-layer View fallback (outer View with solid ring color, inner disc) — do **not** add a native dependency just for this ring.
  - Neutral state gradient: `#2A3A55` → `#16202F` (top-left → bottom-right). Fallback solid: `#22314A`.
  - Active state (≥1 verified): `#34D399` → `#34D39933`. Fallback solid: `greenStroke`.
- **Inner disc:** 148pt, fill `surface`.
- **Glyph:** Ionicons shield at 56pt, centered. Neutral: `shield-outline` in `#94A3B8`. Active: `shield-checkmark` in `green`.
- **Status line** (directly under, centered): `title2` 20/25/600.
- **Count/sub line:** `body` 15, `textSecondary`, marginTop 4.
- Hero is **not tappable**. It is a status display, not a control.

#### Hero states (honesty rules — acceptance criteria)

| Condition | Ring/Glyph | Status line | Sub line |
|---|---|---|---|
| 0 shields verified-on (iOS v1 always) | Neutral | `home.hero.title.none` "Let's set up your protection" | `home.hero.sub.none` "0 shields active" |
| ≥1 verified but not all | Active (green) | `home.hero.title.partial` "{count} of {total} shields on" | `home.hero.sub.partial` "Tap a card below to finish setup" |
| ALL platform shields verified-on | Active (green) | `home.hero.title.all` "You're protected" | `home.hero.sub.all` "All shields on and verified" |
| Any shield in CONFLICT / NETWORK BLOCKED | Ring per rules above, plus amber sub line | (unchanged) | `home.hero.attention` "One shield needs attention" in `amber` |

Hard rules (test these):
- The hero is **never** green with 0 verified shields. `manager/isRunning` alone is not verification — verified = platform signal **plus canary** where specced.
- The absolute "You're protected" appears **only** when all countable shields are verified-on.
- Honor-system shields (future iOS SMS filter) **never** increment the count and never make the hero green.
- `{total}` counts only shields shipped-and-verifiable on the running platform (Android v1: 1, iOS v1: 0). With total ≤ 1, never render "1 of 1" — all-on shows the absolute state, all-off shows the neutral state.

### 2.3 Primary CTA

Rendered only when ≥1 shield is NEEDS SETUP. Full-width, height 50, `radius.control` 14, fill `blue`, pressed `bluePressed`, label `home.cta.turnOn` "Turn on protection" — 17/600 white, centered. Tapping starts the platform's network-shield flow. marginTop 20, marginBottom 4. On iOS v1: **not rendered** (nothing can be turned on — a CTA that leads nowhere fails the honesty bar).

### 2.4 Shield card anatomy

Card: fill `surface`, border 1px `stroke`, `radius.card` 20, padding 16. Vertical gap between cards 12.

```
┌──────────────────────────────────────────────┐
│ [icon 40×40]  Title (17/600)      [status]   │
│               Description (15/400,           │
│               textSecondary, ≤2 lines)       │
│  ⓘ Honesty line (13/400, textSecondary)      │
└──────────────────────────────────────────────┘
```

- Leading icon: 40×40 container, `radius.icon` 12, fill `#FFFFFF0A`, Ionicon 22pt. Icon color follows state: green when ON, `textSecondary` otherwise, amber when attention.
- Title row: title left, status control right-aligned, vertically centered to the title line.
- Description: marginTop 2, max 2 lines.
- Honesty line: marginTop 10, full card width, starts with inline `information-circle-outline` 13pt + 6pt gap. **Every shield card has one. Non-negotiable.**
- Pressed state (when card is tappable): fill `surfaceRaised`, `activeOpacity` 0.85. No scale transforms.

#### Status controls (right side)

| State | Control | Visual |
|---|---|---|
| NEEDS SETUP | Button | Height 36, `radius.pill`, paddingH 14, fill `blue`, label `shield.status.setupBtn` "Set up" 15/700 white |
| ON (verified) | Pill (non-interactive) | Fill `greenWash`, border 1px `greenStroke`, `checkmark-circle` 16pt green + `shield.status.onPill` "On" 13/600 `green` |
| PAUSED | Pill (tappable) | Fill `surface`, border `stroke`, `pause-circle-outline` 16pt + `shield.status.pausedPill` "Paused" 13/600 `textSecondary` |
| CONFLICT / NETWORK BLOCKED | Pill (tappable → detail sheet) | Fill `amberWash`, border `#FBBF2440`, `alert-circle` 16pt + `shield.status.attentionPill` "Attention" 13/600 `amber` |
| UNVERIFIABLE (honor-system, Phase 3) | Pill | Fill `surface`, border `stroke`, label `shield.status.unverifiedPill` "Set up (unverified)" 13/600 `textSecondary` |

#### Per-state card copy (status line replaces the description while non-default)

The state copy renders as the description line (15/400), colored `textSecondary` except amber states which use `amber` at 15/400.

| State | Copy key | EN string |
|---|---|---|
| ON | `shield.network.state.on` | "On. Working right now." |
| NEEDS SETUP | `shield.network.state.setup` | "One-time setup, about a minute." |
| PAUSED | `shield.network.state.paused` | "Paused. Tap to turn back on." |
| CONFLICT | `shield.network.state.conflict` | "Your VPN is in charge right now. Cleanway steps aside so nothing breaks." |
| NETWORK BLOCKED | `shield.network.state.blocked` | "This Wi-Fi needs a sign-in page. Cleanway paused itself and will come back on automatically." |

(NETWORK BLOCKED wording follows critique 2.2: auto-pause is the remedy; never instruct the user to switch protection off.)

### 2.5 The shield cards (default copy)

**Every app — network layer (Android v1 active; iOS: rolling out)**
- Icon `globe-outline`
- Title `shield.network.title` — "Every app"
- Description `shield.network.desc` — "Blocks known scam sites in almost every app — even inside WhatsApp"
- Honesty `shield.network.honesty` — "Can't catch brand-new scam sites, or apps that bring their own private DNS"

**Your browser — browser layer (Phase 2; rolling out on both platforms v1)**
- Icon `compass-outline`
- Title `shield.browser.title` — "Your browser"
- Description `shield.browser.desc` — "Checks every page you open and warns you right on the page"
- Honesty `shield.browser.honesty` — "Can't see inside other apps — the Every-app shield covers those"

**Text messages — messaging layer (Phase 3; rolling out)**
- Icon `chatbubble-outline`
- Title `shield.messages.title` — "Text messages"
- Description `shield.messages.desc` — "Moves scam texts (SMS) to Junk before you tap them"
- Honesty `shield.messages.honesty` — "Can't see iMessage — Apple's rule, not ours. It also can't count what it catches, by design."

### 2.6 Check anything card — first-class, always working

Placement per §2.1. Same card anatomy but taller, and always fully interactive (paste / share-sheet / QR are shipped).

```
┌──────────────────────────────────────────────┐
│ [search icon]  Check anything            ›   │
│                Paste a link, scan a QR code, │
│                or share anything suspicious  │
│                straight to Cleanway          │
│ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│ │ ⧉ Paste  │ │ ▦ Scan QR│ │ ↗ How to     │   │
│ │   link   │ │          │ │   share      │   │
│ └──────────┘ └──────────┘ └──────────────┘   │
└──────────────────────────────────────────────┘
```

- Card body tap → `/check`. Trailing `chevron-forward`.
- Title `home.check.title` — "Check anything" (17/600)
- Description `home.check.desc` — "Paste a link, scan a QR code, or share anything suspicious straight to Cleanway" (15/400 `textSecondary`)
- Chip row: marginTop 14, 3 chips, gap 8, height 40, `radius.chip`, fill `#FFFFFF0A`, border 1px `stroke`, Ionicon 16pt + label 13/600 `textPrimary`:
  - `home.check.paste` "Paste link" (`clipboard-outline`) → `/check` and immediately read clipboard into the input (explicit user action — this is allowed; only *passive* clipboard monitoring is killed)
  - `home.check.qr` "Scan QR" (`qr-code-outline`) → `/scanner`
  - `home.check.share` "How to share" (`share-outline`) → bottom sheet with 2-step share-sheet how-to, body `home.check.shareSheet` — "From any app, tap Share, then choose Cleanway. We'll check the link and tell you if it's safe." Sheet: `surface` fill on `#0B1220E6` scrim, radius 20 top corners, title 17/600, body 15/400.
- No honesty line on this card (it makes no protection claim), but keep the footnote row: `home.check.note` 13/400 `textSecondary` — "Works with anything you can copy or share — including iMessage."

### 2.7 Rolling out section — muted, non-interactive

- Section header: `home.rollout.header` — "Rolling out" (13/600 uppercase, letterSpacing 0.6, `textMuted`, marginBottom 8).
- Rows, not cards: one `surface` container (radius 20, border `stroke`) with internal rows separated by `hairline`. Row padding 14 vertical, 16 horizontal.
- Row anatomy: leading Ionicon 20pt `textDisabled` (no 40×40 container) · text block · trailing pill.
- Title 15/600 `textDisabled`. Line 13/400 `textMuted`, ≤2 lines.
- Trailing pill (non-interactive): fill `#FFFFFF0A`, border `stroke`, label `shield.status.rolloutPill` "Rolling out" 13/600 `textMuted`.
- **No Set-up buttons, no chevrons, no onPress, `accessibilityState={{disabled: true}}`.** Rows are visibly quieter than active cards — that is the point.

Honest per-shield lines:

| Platform v1 | Row | Copy key | EN string |
|---|---|---|---|
| iOS | Every app | `rollout.network.ios` | "Blocks scam sites in almost every app. In final testing — not on iPhone yet." |
| iOS | Your browser | `rollout.browser.ios` | "Warns you right on the page in Safari. Coming next." |
| iOS | Text messages | `rollout.messages.ios` | "Filters scam texts (SMS). Planned — it will never be able to see iMessage." |
| Android | Your browser | `rollout.browser.android` | "Checks links you tap in any app, before they open. Coming next." |
| Android | Text messages | `rollout.messages.android` | "Not possible for us on Android yet — sharing a text to Cleanway is the way to check one." |

### 2.8 Platform matrix (v1)

| | iOS v1 | Android v1 |
|---|---|---|
| Hero | Neutral, "Let's set up your protection" / "0 shields active" — always, nothing is verifiable | Neutral until VPN verified (isRunning + canary), then green |
| Primary CTA | Hidden | Shown while Network shield = NEEDS SETUP |
| Active shield cards | None | Every app |
| Check anything | Directly under hero (position 2) | After the shield card |
| Rolling out | Every app · Your browser · Text messages | Your browser · Text messages |

---

## 3. check.tsx — modernization pass

Keep the flow (input → check → `/result`, quick chips, recent). Changes only:

1. Tokens: bg `bg`, all cards → `surface` + `stroke` + radius 20; input → fill `surfaceRaised`, border 1px `stroke` (focus: border `blue`), radius 14, height 56, text 17/400 `textPrimary`, placeholder `textMuted`.
2. Title → `title1` 28/600, left-aligned (drop center), marginTop 8. Subtitle `body` 15 `textSecondary`.
3. Copy: title `check.title` "Check a link" · subtitle `check.subtitle` "Paste any link or type a website name" · placeholder `check.placeholder` "example.com or paste a full link".
4. Buttons: primary "Check it" (`check.submit`) — blue, height 50, radius 14, 17/600 white. Secondary "Paste from clipboard" (`check.pasteBtn`) — `surface` fill, `stroke` border, radius 14, height 50, 15/600 `textSecondary`, leading `clipboard-outline` 18pt. **Remove the 📋 emoji.**
5. Invalid-input alert copy: title `check.invalid.title` "That doesn't look like a link", body `check.invalid.body` "Type a website name like example.com, or paste the whole link."
6. Chips ("Try these" / "Recent"): height 36, radius 10, paddingH 12, 13/600. Try-these: `surface`/`stroke`/`textSecondary`. Recent: `blueWash` fill, border `#4C8DFF40`, text `blue`. Section headers per §1.5. Keys: `check.try` "Try these", `check.recent` "Recent".

---

## 4. result.tsx — modernization pass

Keep: loading state, error state, signals list, details rows, share, privacy footnote. Restructure the header into a **verdict card with a score ring**.

### 4.1 Verdict card

- Card: `surface` fill, radius 20, padding 24, centered content. Border 1px tinted by verdict: safe `greenStroke` / caution `#FBBF2440` / dangerous `#F8717140`.
- **Score ring** (replaces the emoji + "Score: X/100" line): 120pt diameter, 8pt stroke, `radius.full`. Track `#FFFFFF0F`; progress arc = `score`% of circumference, rounded caps, color by verdict (`green` / `amber` / `danger`), starting at 12 o'clock clockwise. Center: score number `display` 34/700 in verdict color, with "/100" 13/400 `textMuted` directly below. Implementation: `react-native-svg` circle + strokeDasharray if available; fallback = 120pt circle View with 8pt solid border in the verdict color at 40% (`…66`) and the same centered numbers — do not add a native dep without checking `mobile/package.json`.
- Under the ring: verdict label `title2` 20/600 in verdict color — `result.verdict.safe` "Looks safe" / `result.verdict.caution` "Be careful" / `result.verdict.dangerous` "Dangerous". Then domain 15/400 `textSecondary`, marginTop 4.
- Low confidence note (kept): `result.lowConfidence` "Limited analysis — some checks couldn't run" — 13/400 `amber`, marginTop 12. Drop the italic.

### 4.2 Signals ("Detection Signals" → plainer)

- Card: `surface`, radius 20, padding 16. Title `result.signals` "Why we say this" 17/600.
- Row: 8pt vertical padding, `hairline` separators. Leading 6pt dot (View, `radius.full`) in verdict color. Text 15/400 `textSecondary`, flex. Trailing weight chip: fill verdict wash (`greenWash`/`amberWash`/`dangerWash`), radius 8, paddingH 8, height 24, label "+{weight}" 13/600 in verdict color.

### 4.3 Details, share, footnote

- Details card: same card style; rows keep label (15 `textMuted`) / value (15/600 `textPrimary`) with `hairline` separators. Keys: `result.details` "Details", `result.age` "Domain age", `result.https` "HTTPS", `result.cert` "Certificate", `result.confidence` "Confidence".
- Share button: secondary style (`surface` fill, `stroke` border, radius 14, height 50), label `result.share` "Share result" 15/600 `blue`, leading `share-outline` 18pt.
- Privacy footnote **kept**, emoji removed: `lock-closed-outline` 13pt inline + `result.privacy` — "Checked on our servers. Only the website name was sent — nothing else." 13/400 `textMuted`, centered.
- Loading: spinner `blue`; `result.loading` "Checking {domain}…" 17/600; `result.loadingSub` "Running 18 safety checks" 13 `textMuted` (18 is the real fan-out — replaces the stale "9 threat sources + ML model" line).
- Error: `alert-circle` 44pt `amber` (no ⚠ emoji), `result.error.title` "Couldn't finish the check" 17/600, `result.error.body` "The server didn't answer. Check your connection and try again." 15 `textSecondary`, retry button (blue, `result.error.retry` "Try again").

---

## 5. Motion & haptics (quiet)

- Hero state change: cross-fade + scale 0.96→1.0, 250ms ease-out. On first verified-ON: ring sweep (stroke-dashoffset animate 600ms) + `Haptics.notificationAsync(Success)`. No confetti, no pulses, no loops.
- Card press: `activeOpacity` 0.85 only.
- Score ring on result: animate progress 0→score over 600ms ease-out once.
- All animations respect `AccessibilityInfo.isReduceMotionEnabled` — render final state instantly.

## 6. Accessibility

- Touch targets ≥ 44×44 (the 36pt Set-up button gets `hitSlop` to 44).
- Honesty lines use `textSecondary` (7.2:1), never `textMuted`.
- Status is never color-only: every state pairs color + icon + text label.
- `accessibilityRole`/`Label` on hero ("Protection status: {status line}"), pills, and rollout rows (disabled).

## 7. Implementation notes

- New components under `mobile/src/components/shield/`: `HeroShield.tsx`, `ShieldCard.tsx`, `StatusPill.tsx`, `CheckAnythingCard.tsx`, `RolloutList.tsx`, `ScoreRing.tsx` (shared with result). Keep files small.
- `theme.ts`: update `bg`, add `surface/surfaceRaised/stroke/hairline`, semantic `green/blue/amber` families, `radius`, new `type` scale. Keep old exports as aliases (`bgCard → surface` solid fallback, `primary → blue`, `safe → green`, `caution → amber`, `dangerous → danger`) so untouched screens don't break.
- Kill list executed in this change: `isProtected` toggle, clipboard auto-monitor + banner, "VPN mode" how-it-works row, the "Your browsing data never leaves this device" line (false — see `home.privacy` replacement), all emoji icons.
- Strings: add keys below to `packages/i18n-strings/src/` (EN only for now), run `python3 scripts/build-i18n.py`, commit source + generated together (CI drift guard).

## 8. EN copy strings (complete)

| Key | EN |
|---|---|
| `home.hero.title.none` | Let's set up your protection |
| `home.hero.sub.none` | 0 shields active |
| `home.hero.title.partial` | {count} of {total} shields on |
| `home.hero.sub.partial` | Tap a card below to finish setup |
| `home.hero.title.all` | You're protected |
| `home.hero.sub.all` | All shields on and verified |
| `home.hero.attention` | One shield needs attention |
| `home.cta.turnOn` | Turn on protection |
| `shield.network.title` | Every app |
| `shield.network.desc` | Blocks known scam sites in almost every app — even inside WhatsApp |
| `shield.network.honesty` | Can't catch brand-new scam sites, or apps that bring their own private DNS |
| `shield.network.state.on` | On. Working right now. |
| `shield.network.state.setup` | One-time setup, about a minute. |
| `shield.network.state.paused` | Paused. Tap to turn back on. |
| `shield.network.state.conflict` | Your VPN is in charge right now. Cleanway steps aside so nothing breaks. |
| `shield.network.state.blocked` | This Wi-Fi needs a sign-in page. Cleanway paused itself and will come back on automatically. |
| `shield.browser.title` | Your browser |
| `shield.browser.desc` | Checks every page you open and warns you right on the page |
| `shield.browser.honesty` | Can't see inside other apps — the Every-app shield covers those |
| `shield.messages.title` | Text messages |
| `shield.messages.desc` | Moves scam texts (SMS) to Junk before you tap them |
| `shield.messages.honesty` | Can't see iMessage — Apple's rule, not ours. It also can't count what it catches, by design. |
| `shield.status.setupBtn` | Set up |
| `shield.status.onPill` | On |
| `shield.status.pausedPill` | Paused |
| `shield.status.attentionPill` | Attention |
| `shield.status.unverifiedPill` | Set up (unverified) |
| `shield.status.rolloutPill` | Rolling out |
| `home.check.title` | Check anything |
| `home.check.desc` | Paste a link, scan a QR code, or share anything suspicious straight to Cleanway |
| `home.check.paste` | Paste link |
| `home.check.qr` | Scan QR |
| `home.check.share` | How to share |
| `home.check.shareSheet` | From any app, tap Share, then choose Cleanway. We'll check the link and tell you if it's safe. |
| `home.check.note` | Works with anything you can copy or share — including iMessage. |
| `home.rollout.header` | Rolling out |
| `rollout.network.ios` | Blocks scam sites in almost every app. In final testing — not on iPhone yet. |
| `rollout.browser.ios` | Warns you right on the page in Safari. Coming next. |
| `rollout.messages.ios` | Filters scam texts (SMS). Planned — it will never be able to see iMessage. |
| `rollout.browser.android` | Checks links you tap in any app, before they open. Coming next. |
| `rollout.messages.android` | Not possible for us on Android yet — sharing a text to Cleanway is the way to check one. |
| `home.activity.checked` | Checked |
| `home.activity.blocked` | Blocked |
| `home.activity.warned` | Warned |
| `home.privacy` | We check website names on our servers — never your passwords, messages, or browsing history. |
| `check.title` | Check a link |
| `check.subtitle` | Paste any link or type a website name |
| `check.placeholder` | example.com or paste a full link |
| `check.pasteBtn` | Paste from clipboard |
| `check.submit` | Check it |
| `check.try` | Try these |
| `check.recent` | Recent |
| `check.invalid.title` | That doesn't look like a link |
| `check.invalid.body` | Type a website name like example.com, or paste the whole link. |
| `result.loading` | Checking {domain}… |
| `result.loadingSub` | Running 18 safety checks |
| `result.verdict.safe` | Looks safe |
| `result.verdict.caution` | Be careful |
| `result.verdict.dangerous` | Dangerous |
| `result.lowConfidence` | Limited analysis — some checks couldn't run |
| `result.signals` | Why we say this |
| `result.details` | Details |
| `result.age` | Domain age |
| `result.https` | HTTPS |
| `result.cert` | Certificate |
| `result.confidence` | Confidence |
| `result.share` | Share result |
| `result.privacy` | Checked on our servers. Only the website name was sent — nothing else. |
| `result.error.title` | Couldn't finish the check |
| `result.error.body` | The server didn't answer. Check your connection and try again. |
| `result.error.retry` | Try again |
