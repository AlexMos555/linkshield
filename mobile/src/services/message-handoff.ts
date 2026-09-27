/**
 * Hands a shared message from the share-intent router to the message-check
 * screen — in memory, once.
 *
 * Not a route param on purpose. Params become part of the navigation state
 * and of the deep-link URL expo-router builds for the screen, which is exactly
 * the kind of string that ends up in a log line or a crash breadcrumb. The
 * text of someone's SMS must never be written anywhere, so it travels in this
 * variable instead, and the screen takes it (which clears it).
 *
 * Every handoff gets an id, and the id — never the text — is the route param.
 * The screen may already be open when the next message is shared: Expo
 * Router then does not mount a new one, it hands the open screen new params.
 * Before the id, those params never changed (`from=share` both times), the
 * screen never looked again, and a second scam SMS got the first one's
 * "no signs of fraud" (report #5, 2026-09-25). A new id is how the open
 * screen knows there is a new message to take.
 *
 * A handoff nobody takes quickly is dropped: if navigation failed, the text
 * must not surface later in a check the person started by hand.
 *
 * Pure (no React Native): scripts/test-message-handoff.mjs runs it under node.
 */

const HANDOFF_TTL_MS = 30_000;

let seq = 0;
let pending: { id: string; text: string; at: number } | null = null;

/** Leave [text] for the message screen; returns the id to put in its route. */
export function handOffMessage(text: string, now: number = Date.now()): string {
  seq += 1;
  const id = `${now.toString(36)}-${seq}`;
  pending = { id, text, at: now };
  return id;
}

/**
 * The text handed off under [id], at most once; null when there is none, it
 * expired, or the waiting message belongs to another id (a newer share —
 * it stays for the screen that asks with its own id).
 */
export function takeHandedOffMessage(id: string, now: number = Date.now()): string | null {
  const taken = pending;
  if (!taken || taken.id !== id) return null;
  pending = null;
  return now - taken.at > HANDOFF_TTL_MS ? null : taken.text;
}

/**
 * The message screen's side of a share: from its route params and the last
 * handoff it handled ([handled], a React ref), the text to check now — or
 * null. The id is marked handled before taking, so a re-render with the same
 * params never checks twice, and a new id always gets its turn.
 */
export function takeForScreen(
  params: { from?: string; handoff?: string },
  handled: { current: string | null },
  now: number = Date.now(),
): string | null {
  if (params.from !== "share" || !params.handoff || handled.current === params.handoff) return null;
  handled.current = params.handoff;
  return takeHandedOffMessage(params.handoff, now);
}
